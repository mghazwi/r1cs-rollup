use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

//#[cfg(feature = "r1cs")]
pub mod constraints;
//#[cfg(feature = "r1cs")]
pub use constraints::*;

pub mod schnorr;

#[cfg(test)]
mod test {
    use crate::signature::{schnorr, *};
    use crate::signature::schnorr::Schnorr;
    //use ark_ec::AdditiveGroup;
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::{test_rng, vec::Vec, UniformRand};

    fn sign_and_verify<C: CurveGroup>(message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = Schnorr::<C>::setup::<_>(rng).unwrap();
        let (pk, sk) = Schnorr::<C>::keygen(&parameters, rng).unwrap();
        let sig = Schnorr::<C>::sign(&parameters, &sk, &pk, &message, rng).unwrap();
        assert!(Schnorr::<C>::verify(&parameters, &pk, &message, &sig).unwrap());
    }

    fn failed_verification<C: CurveGroup>(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = Schnorr::<C>::setup::<_>(rng).unwrap();
        let (pk, sk) = Schnorr::<C>::keygen(&parameters, rng).unwrap();
        let sig = Schnorr::<C>::sign(&parameters, &sk, &pk, message, rng).unwrap();
        assert!(!Schnorr::<C>::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    // #[test]
    // fn schnorr_signature_test() {
    //     let message = "Hi, I am a Schnorr signature!";
    //     let rng = &mut test_rng();
    //     sign_and_verify::<schnorr::Schnorr<JubJub, Blake2s>>(message.as_bytes());
    //     failed_verification::<schnorr::Schnorr<JubJub, Blake2s>>(
    //         message.as_bytes(),
    //         "Bad message".as_bytes(),
    //     );
    //     let mut random_scalar_bytes = Vec::new();
    //     let random_scalar = <JubJub as AdditiveGroup>::Scalar::rand(rng);
    //     random_scalar
    //         .serialize_compressed(&mut random_scalar_bytes)
    //         .unwrap();
    //     randomize_and_verify::<schnorr::Schnorr<JubJub, Blake2s>>(
    //         message.as_bytes(),
    //         &random_scalar_bytes.as_slice(),
    //     );
    // }
    #[test]
    fn schnorr_signature_test() {
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<JubJub>(message.as_bytes());
        failed_verification::<JubJub>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
