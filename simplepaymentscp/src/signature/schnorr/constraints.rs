use ark_crypto_primitives::prf::blake2s::constraints::OutputVar;
use ark_std::vec::Vec;
use ark_ec::CurveGroup;
use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, Namespace, SynthesisError};

use crate::signature::{schnorr};
use crate::signature::schnorr::Signature;
use crate::serde_utils::*;
use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{cfg_iter, fmt::Debug, io::Write, test_rng};

use core::{borrow::Borrow, marker::PhantomData};
use std::ops::Mul;

use ark_relations::r1cs::ConstraintSystemRef;
use crate::signature::schnorr::{Parameters, PublicKey, Schnorr};
use derivative::Derivative;
use digest::Digest;

use crate::commitment::{
    blake2s::{
        constraints::{CommGadget, ParametersVar as B2SParamsVar},
        Commitment,
    },
    CommitmentGadget,
};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
{
    pub generator: GC,
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: CurveGroup + CanonicalSerialize, GC: CurveVar<C, ConstraintF<C>>>
{
    pub pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
{
    pub prover_response: Vec<UInt8<ConstraintF<C>>>,
    pub verifier_challenge: Vec<UInt8<ConstraintF<C>>>,
    #[doc(hidden)]
    _group: PhantomData<GC>,
}

pub struct SchnorrSignatureVerifyGadget<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SchnorrSignatureVerifyGadget<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    pub fn verify(
        parameters: &ParametersVar<C,GC>,
        public_key: &PublicKeyVar<C,GC>,
        message: &[UInt8<ConstraintF<C>>],
        signature: &SignatureVar<C,GC>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(message);

        type TestCOMM = Commitment;
        type TestCOMMGadget = CommGadget;

        let b2s_params = <TestCOMMGadget as CommitmentGadget<TestCOMM, Fr>>::ParametersVar::new_constant(
            ConstraintSystemRef::<Fr>::None,
            (),
        )?;

        let obtained_verifier_challenge = <TestCOMMGadget as CommitmentGadget<TestCOMM, ConstraintF<C>>>::commit(
            &b2s_params,
            &hash_input,
        ).unwrap();

        obtained_verifier_challenge.0.is_eq(&verifier_challenge)
    }
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GC::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let mut response_bytes = Vec::new();
            val.borrow().prover_response.serialize_uncompressed(&mut response_bytes);

            let mut challenge_bytes = Vec::new();
            val.borrow().verifier_challenge.serialize_uncompressed(&mut challenge_bytes);
            let mut prover_response = Vec::<UInt8<ConstraintF<C>>>::new();
            let mut verifier_challenge = Vec::<UInt8<ConstraintF<C>>>::new();
            for byte in &response_bytes {
                prover_response.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            for byte in &challenge_bytes {
                verifier_challenge.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
            })
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
