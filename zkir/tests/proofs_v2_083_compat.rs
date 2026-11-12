//! Fixture-free ZKIR v2 proof gate for the local proofs 0.8.3 migration.

use std::{borrow::Cow, io, sync::Arc};

use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use midnight_zkir::IrSource;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, ProofPreimage, Zkir,
};

struct GeneratedParams(ParamsProver);

impl ParamsProverProvider for GeneratedParams {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

fn generated_params(ir: &IrSource) -> (GeneratedParams, ParamsVerifier) {
    let params = GeneratedParams(ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([9; 32]),
    ))));
    let mut bytes = Vec::new();
    params
        .0
        .0
        .write_custom(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize generated parameters");
    let verifier = ParamsVerifier::read(&bytes[..]).expect("verifier parameters");
    (params, verifier)
}

#[actix_rt::test]
async fn v2_proof_verifies_and_wrong_statement_fails() {
    let ir = IrSource::load(
        &br#"{
            "version": { "major": 2, "minor": 2 },
            "num_inputs": 1,
            "do_communications_commitment": false,
            "instructions": [{ "op": "assert", "cond": 0 }]
        }"#[..],
    )
    .expect("load v2 IR");
    let (params, verifier_params) = generated_params(&ir);
    let (pk, vk) = ir.v2_keygen(&params).await.expect("keygen");
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };
    let (proof, pis, _) = ir
        .prove(ChaCha20Rng::from_seed([42; 32]), &params, pk, &preimage)
        .await
        .expect("prove v2");
    vk.verify(&verifier_params, &proof, pis.into_iter())
        .expect("verify v2");
    assert!(
        vk.verify(&verifier_params, &proof, [43.into()].into_iter())
            .is_err(),
        "wrong public statement must not verify"
    );
}

#[actix_rt::test]
async fn v2_ecc_proof_verifies() {
    use transient_crypto::curve::EmbeddedGroupAffine;

    let ir = IrSource::load(
        &br#"{
            "version": { "major": 2, "minor": 2 },
            "num_inputs": 4,
            "do_communications_commitment": false,
            "instructions": [
                { "op": "ec_mul", "a_x": 0, "a_y": 1, "scalar": 2 },
                { "op": "ec_mul_generator", "scalar": 3 },
                { "op": "ec_add", "a_x": 4, "a_y": 5, "b_x": 6, "b_y": 7 }
            ]
        }"#[..],
    )
    .expect("load ECC v2 IR");
    let (params, verifier_params) = generated_params(&ir);
    let (pk, vk) = ir.v2_keygen(&params).await.expect("ECC keygen");
    let point = EmbeddedGroupAffine::generator();
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![point.x().unwrap(), point.y().unwrap(), 42.into(), 63.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };
    let (proof, pis, _) = ir
        .prove(ChaCha20Rng::from_seed([42; 32]), &params, pk, &preimage)
        .await
        .expect("prove ECC v2");
    vk.verify(&verifier_params, &proof, pis.into_iter())
        .expect("verify ECC v2");
}

#[actix_rt::test]
async fn v2_hash_to_curve_proof_verifies() {
    let ir = IrSource::load(
        &br#"{
            "version": { "major": 2, "minor": 2 },
            "num_inputs": 3,
            "do_communications_commitment": false,
            "instructions": [{ "op": "hash_to_curve", "inputs": [0, 1, 2] }]
        }"#[..],
    )
    .expect("load hash-to-curve v2 IR");
    let (params, verifier_params) = generated_params(&ir);
    let (pk, vk) = ir.v2_keygen(&params).await.expect("hash-to-curve keygen");
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into(), 2.into(), 3.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };
    let (proof, pis, _) = ir
        .prove(ChaCha20Rng::from_seed([42; 32]), &params, pk, &preimage)
        .await
        .expect("prove hash-to-curve v2");
    vk.verify(&verifier_params, &proof, pis.into_iter())
        .expect("verify hash-to-curve v2");
}
