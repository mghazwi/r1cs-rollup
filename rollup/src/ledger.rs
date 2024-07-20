use crate::ConstraintF;
use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, PedersenTwoToOneCRHCompressorGadget, TECompressorGadget,
};
use ark_crypto_primitives::crh::{pedersen, TwoToOneCRHScheme, CRHScheme, CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::crh::injective_map::{PedersenCRHCompressor, PedersenTwoToOneCRHCompressor, TECompressor};
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective, Fq};
use ark_r1cs_std::bits::uint64::UInt64;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_simple_payments_scp::ledger::*;
use ark_simple_payments_scp::ledger::JubJubMerkleTreeParamsVar as JubJubMTP;
use ark_simple_payments_scp::signature::schnorr::constraints::ParametersVar as SchnorrParamsVar;
use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget as MTConfigGad;
use std::borrow::Borrow;

/// Represents transaction amounts and account balances.
#[derive(Clone, Debug)]
pub struct AmountVar(pub UInt64<ConstraintF>);

impl AmountVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        self.0.to_bytes().unwrap()
    }

    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn checked_add(&self, other: &Self) -> Result<Self, SynthesisError> {
        // To do a checked add, we add two uint64's directly.
        // We also check for overflow, by casting them to field elements,
        // adding the field element representation
        // converting the field elements to bits
        // and then checking if the 65th bit is 0.
        let self_bits = self.0.to_bits_le();
        let self_fe = Boolean::le_bits_to_fp_var(&self_bits)?;
        let other_bits = other.0.to_bits_le();
        let other_fe = Boolean::le_bits_to_fp_var(&other_bits)?;
        let res_fe = self_fe + other_fe;
        let res_bz = res_fe.to_bytes()?;
        // Ensure 65th bit is 0
        // implies 8th word (0-indexed) is 0
        res_bz[8].enforce_equal(&UInt8::<ConstraintF>::constant(0))?;
        // Add sum
        let result = UInt64::addmany(&[self.0.clone(), other.0.clone()])?;
        Ok(AmountVar(result))
    }

    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn checked_sub(&self, other: &Self) -> Result<Self, SynthesisError> {
        // To do a checked sub, we convert the uints to a field element.
        // We do the sub on the field element.
        // We then cast the field element to bits, and ensure the top bits are 0.
        // We then convert these bits to a field element
        let self_bits = self.0.to_bits_le();
        let self_fe = Boolean::le_bits_to_fp_var(&self_bits)?;
        let other_bits = other.0.to_bits_le();
        let other_fe = Boolean::le_bits_to_fp_var(&other_bits)?;
        let res_fe = self_fe - other_fe;
        let res_bz = res_fe.to_bytes()?;
        // Ensure top bit is 0
        res_bz[res_bz.len() - 1].enforce_equal(&UInt8::<ConstraintF>::constant(0))?;
        // Convert to UInt64
        let res = UInt64::from_bits_le(&res_fe.to_bits_le()?[..64]);
        Ok(AmountVar(res))
    }
}

impl AllocVar<Amount, ConstraintF> for AmountVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Amount>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt64::new_variable(cs.into(), || f().map(|u| u.borrow().0), mode).map(Self)
    }
}

pub type TwoToOneHashGadget = PedersenTwoToOneCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    Window4x256,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    Window4x256,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, Window4x256>;
pub type TwoToOneHash = PedersenTwoToOneCRHCompressor<EdwardsProjective, TECompressor, Window4x256>;

pub type AccRootVar = <JubJubMTP as MTConfigGad<JubJubMerkleTreeParams,ConstraintF>>::InnerDigest;
pub type AccPathVar = PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar>;
pub type LeafHashParamsVar = <LeafHashGadget as CRHSchemeGadget<LeafHash, ConstraintF>>::ParametersVar;
pub type TwoToOneHashParamsVar = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

/// The parameters that are used in transaction creation and validation.
pub struct ParametersVar {
    pub sig_params: SchnorrParamsVar<EdwardsProjective, EdwardsVar>,
    pub leaf_crh_params: LeafHashParamsVar,
    pub two_to_one_crh_params: TwoToOneHashParamsVar,
}

impl AllocVar<Parameters, ConstraintF> for ParametersVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, _mode))]
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|params| {
            let params: &Parameters = params.borrow();
            let sig_params = SchnorrParamsVar::new_constant(cs.clone(), &params.sig_params)?;
            let leaf_crh_params =
                LeafHashParamsVar::new_constant(cs.clone(), &params.leaf_crh_params)?;
            let two_to_one_crh_params =
                TwoToOneHashParamsVar::new_constant(cs.clone(), &params.two_to_one_crh_params)?;
            Ok(Self {
                sig_params,
                leaf_crh_params,
                two_to_one_crh_params,
            })
        })
    }
}