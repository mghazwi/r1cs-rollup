use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    fields::{Field, PrimeField},
    One, ToConstraintField, UniformRand, Zero,
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::boolean::AllocatedBool;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use crate::commitment::{blake2s::Commitment, CommitmentScheme};

use derivative::Derivative;
//#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct Schnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup"), Debug)]
pub struct Parameters<C: CurveGroup> {
    // _hash: PhantomData<H>,
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

pub trait DigestToScalarField<C: CurveGroup> {
    fn digest_to_scalar_field(&self) -> Result<C::ScalarField, Error>;
}

impl<C: CurveGroup> DigestToScalarField<C> for Vec<u8> {
    fn digest_to_scalar_field(&self) -> Result<C::ScalarField, Error> {
        Ok(C::ScalarField::deserialize_uncompressed(self.as_slice())?)
    }
}

#[derive(Clone, Default, Debug)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: C::ScalarField,
    pub prover_com: C::Affine,
}

impl<C: CurveGroup + Hash> Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Parameters<C>, Error> {
        let generator = C::rand(rng).into();

        Ok(Parameters {
            generator,
        })
    }

    pub fn keygen<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
    ) -> Result<(PublicKey<C>, SecretKey<C>), Error> {
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((public_key, SecretKey(secret_key)))
    }

    pub fn sign<R: Rng>(
        parameters: &Parameters<C>,
        sk: &SecretKey<C>,
        pk: &PublicKey<C>,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<C>, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge, prover_com) = loop {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            let mut hash_input = Vec::new();
            pk.serialize_uncompressed(&mut hash_input)?;
            prover_commitment.serialize_uncompressed(&mut hash_input)?;
            hash_input.extend_from_slice(message);

            let verifier_challenge_hash = Commitment::commit(&(),&hash_input)?;

            if let Ok(clean_verifier_challenge) = <Vec<u8> as DigestToScalarField<C>>::digest_to_scalar_field(&verifier_challenge_hash.to_vec()) {
                break (random_scalar, clean_verifier_challenge, prover_commitment);
            };
        };
        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * sk.0);
        let signature = Signature {
            prover_response,
            verifier_challenge,
            prover_com,
        };
        Ok(signature)
    }

    pub fn verify(
        parameters: &Parameters<C>,
        pk: &PublicKey<C>,
        message: &[u8],
        signature: &Signature<C>,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
            prover_com,
        } = signature;
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(*verifier_challenge);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        let mut hash_input = Vec::new();
        pk.serialize_uncompressed(&mut hash_input)?;
        claimed_prover_commitment.serialize_uncompressed(&mut hash_input)?;
        hash_input.extend_from_slice(message);

        let obtained_verifier_challenge = if let Some(obtained_verifier_challenge) =
            C::ScalarField::from_random_bytes(&Commitment::commit(&(),&hash_input)?)
        {
            obtained_verifier_challenge
        } else {
            return Ok(false);
        };
        Ok(verifier_challenge == &obtained_verifier_challenge)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> (8 - i - 1)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

impl<ConstraintF: Field, C: CurveGroup + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_group().to_field_elements()
    }
}
