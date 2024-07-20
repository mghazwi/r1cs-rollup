use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

#[cfg(test)]
mod test {
    use crate::signature::{schnorr, schnorr::constraints::*, *};
    use crate::signature::schnorr::Schnorr;
    use crate::commitment::blake2s::Commitment;
    use crate::commitment::blake2s::constraints::CommGadget;
    use crate::commitment::CommitmentGadget;
    use ark_bls12_381::Fr;
    use ark_ec::{CurveGroup};
    use ark_ed_on_bls12_381::{constraints::EdwardsVar as JubJubVar, EdwardsProjective as JubJub, Fq};
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;


    type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

    type VG = SchnorrSignatureVerifyGadget<JubJub, JubJubVar>;

    fn sign_and_verify<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>(
        message: &[u8],
    ) {
        let rng = &mut test_rng();
        let parameters = Schnorr::<C>::setup::<_>(rng).unwrap();
        let (pk, sk) = Schnorr::<C>::keygen(&parameters, rng).unwrap();
        let sig = Schnorr::<C>::sign(&parameters, &sk, &pk, &message, rng).unwrap();
        assert!(Schnorr::<C>::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<ConstraintF<C>>::new_ref();

        // create a schnorr struct with these 3 variables, and a generate constraints
        // blake2 circuit based on commitment_gadget_test -> create circuit
        let parameters_var = ParametersVar::<C,GC>::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SignatureVar::<C,GC>::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = PublicKeyVar::<C,GC>::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let mut msg_var = Vec::new();
        for i in 0..message.len() {
            msg_var.push(UInt8::new_witness(cs.clone(), || Ok(&message[i])).unwrap())
        }

        type TestCOMM = Commitment;
        type TestCOMMGadget = CommGadget;

        let b2s_parameters_var = <TestCOMMGadget as CommitmentGadget<TestCOMM, Fr>>::ParametersVar::new_witness(
            ark_relations::ns!(cs, "gadget_parameters"), 
            || Ok(&()), 
        ).unwrap();

        let valid_sig_var = SchnorrSignatureVerifyGadget::<C,GC>::verify(&parameters_var, &pk_var, &msg_var, &signature_var, &b2s_parameters_var).unwrap();
        valid_sig_var.enforce_equal(&Boolean::<ConstraintF<C>>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            JubJub, JubJubVar
        >(message.as_bytes());
    }
}