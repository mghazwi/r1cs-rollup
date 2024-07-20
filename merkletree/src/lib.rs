use ark_crypto_primitives::merkle_tree::{MerkleTree, ByteDigestConverter, DigestConverter, Path, Config, constraints::{BytesVarDigestConverter, ConfigGadget, PathVar}};
use ark_crypto_primitives::crh::{pedersen, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget, CRHScheme, CRHSchemeGadget};
use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, ConstraintSystem}};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_std::rand::{prelude::StdRng, SeedableRng, RngCore};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::*;
use ark_bls12_381::Bls12_381;
use derivative::Derivative;
use ark_ec::AffineRepr;

#[allow(unused_imports)]

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub type LeafH = pedersen::CRH<JubJub, Window4x256>;
pub type LeafHG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

pub type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;
pub type CompressHG = pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window4x256>;

pub type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

#[derive(Clone)]
pub struct JubJubMerkleTreeParams;

impl Config for JubJubMerkleTreeParams {
    type Leaf = [u8];
    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;

    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

type ConstraintF = Fq;
pub struct JubJubMerkleTreeParamsVar;
impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest =
    <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

pub type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

/// Generate a merkle tree, its constraints, and test its constraints
#[test]
fn good_merkle_tree_test() {
    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let input = vec![i; 30];
        leaves.push(input);
    }
    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone()).unwrap();
    let root = tree.root();
    for (i, leaf) in leaves.iter().enumerate() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let proof = tree.generate_proof(i).unwrap();
        assert!(proof
            .verify(
                &leaf_crh_params,
                &two_to_one_crh_params,
                &root,
                leaf.as_slice()
            )
            .unwrap());

        // Allocate Merkle Tree Root
        let root = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_witness(
            ark_relations::ns!(cs, "new_digest"),
            || {Ok(root)},
        )
        .unwrap();

        let constraints_from_digest = cs.num_constraints();
        println!("constraints from digest: {}", constraints_from_digest);

        // Allocate Parameters for CRH
        let leaf_crh_params_var =
            <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &leaf_crh_params,
            )
                .unwrap();
        let two_to_one_crh_params_var =
            <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                &two_to_one_crh_params,
            )
                .unwrap();

        let constraints_from_params = cs.num_constraints() - constraints_from_digest;
        println!("constraints from parameters: {}", constraints_from_params);

        // Allocate Leaf
        let leaf_g = UInt8::new_input_vec(cs.clone(), leaf).unwrap();

        let constraints_from_leaf =
            cs.num_constraints() - constraints_from_params - constraints_from_digest;
        println!("constraints from leaf: {}", constraints_from_leaf);

        // Allocate Merkle Tree Path
        let cw: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&proof)).unwrap();

        let constraints_from_path = cs.num_constraints()
            - constraints_from_params
            - constraints_from_digest
            - constraints_from_leaf;
        println!("constraints from path: {}", constraints_from_path);

        assert!(cs.is_satisfied().unwrap());
        assert!(cw
            .verify_membership(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &root,
                &leaf_g,
            )
            .unwrap()
            .value()
            .unwrap());
        let setup_constraints = constraints_from_leaf
            + constraints_from_digest
            + constraints_from_params
            + constraints_from_path;
        println!(
            "number of constraints: {}",
            cs.num_constraints() - setup_constraints
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "verification constraints not satisfied"
        );
    }
}

#[derive(Clone)]
pub struct MerkleTreeCircuit {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <CompressH as TwoToOneCRHScheme>::Parameters,

    // This is the public input to the circuit.
    pub root: <CompressH as TwoToOneCRHScheme>::Output,
    
    // These are the private witnesses to the circuit.
    pub leaf: u8,
    pub authentication_path: Path<JubJubMerkleTreeParams>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(ark_relations::ns!(cs, "new_digest"), || Ok(self.root))?;

        let leaf = UInt8::new_witness(ark_relations::ns!(cs, "leaf_var"), || Ok(self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(ark_relations::ns!(cs, "leaf_crh_parameter"), &self.leaf_crh_params)?;
        let two_to_one_crh_params = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(ark_relations::ns!(cs, "two_to_one_crh_parameter"), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> = PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(self.authentication_path))?;

        let leaf_bytes = vec![leaf; 30];

        let is_member = 
            path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_bytes,
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[test]
fn merkle_tree_constraints_correctness() {
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    let mut leaves = Vec::new();
    leaves.push(vec![1u8; 30]);
    leaves.push(vec![2u8; 30]);
    leaves.push(vec![3u8; 30]);
    leaves.push(vec![10u8; 30]);
    leaves.push(vec![9u8; 30]);
    leaves.push(vec![17u8; 30]);
    leaves.push(vec![70u8; 30]);
    leaves.push(vec![45u8; 30]);
    let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves).unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!

    // First, let's get the root we want to verify against:
    let root = tree.root();

    let circuit = MerkleTreeCircuit {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public input
        root,

        // witnesses
        leaf: 9u8,
        authentication_path: proof,
    };

    // Next, let's make the circuit!
    let cs = ConstraintSystem::<Fq>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    println!("Ya we got here");
    assert!(is_satisfied);
}

#[test]
fn merkle_tree_groth_correctness() {
    let mut rng = StdRng::seed_from_u64(0u64);

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    let mut leaves = Vec::new();
    leaves.push(vec![1u8; 30]);
    leaves.push(vec![2u8; 30]);
    leaves.push(vec![3u8; 30]);
    leaves.push(vec![10u8; 30]);
    leaves.push(vec![9u8; 30]);
    leaves.push(vec![17u8; 30]);
    leaves.push(vec![70u8; 30]);
    leaves.push(vec![45u8; 30]);
    let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves).unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = tree.generate_proof(4).unwrap(); 

    // First, let's get the root we want to verify against:
    let root = tree.root();

    let circuit = MerkleTreeCircuit {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public input
        root,

        // witnesses
        leaf: 9u8,
        authentication_path: proof,
    };

    let (pk, vk) = {
        ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap()
    };

    let pvk = ark_groth16::prepare_verifying_key(&vk);

    let public_input = tree.root().into_group().to_field_elements().unwrap();

    let groth_proof = ark_groth16::Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit,&pk,&mut rng).unwrap();
    
    let a = ark_groth16::Groth16::<Bls12_381>::verify_proof(&pvk,&groth_proof,&public_input).unwrap();
    println!("verification result: {}",a);
    assert!(a);
}