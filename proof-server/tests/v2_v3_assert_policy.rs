//! Ledger9-only comparison of logically identical ZKIR v2/v3 assertion circuits.

use std::{borrow::Cow, io, path::PathBuf, sync::Arc, time::Instant};

use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, ProofPreimage, Zkir,
};

use serde_json::json;

fn assert_ir_pair(count: usize) -> (zkir::IrSource, zkir_v3::IrSource) {
    let v2 = json!({
        "version": { "major": 2, "minor": 2 },
        "num_inputs": 1,
        "do_communications_commitment": false,
        "instructions": vec![json!({ "op": "assert", "cond": 0 }); count],
    });
    let v3 = json!({
        "version": { "major": 3, "minor": 0 },
        "inputs": [{ "name": "%v_0", "type": "Scalar<BLS12-381>" }],
        "outputs": [],
        "do_communications_commitment": false,
        "instructions": vec![json!({ "op": "assert", "cond": "%v_0" }); count],
    });
    (
        zkir::IrSource::load(serde_json::to_vec(&v2).unwrap().as_slice()).unwrap(),
        zkir_v3::IrSource::load(serde_json::to_vec(&v3).unwrap().as_slice()).unwrap(),
    )
}

const ASSERT_COUNT: usize = 16_384;
const EXPECTED_K: u8 = 15;
const EXPECTED_ROWS: usize = 16_386;

#[test]
fn assert_models_match_across_v2_and_v3() {
    let count = ASSERT_COUNT;
    let (v2, v3) = assert_ir_pair(count);
    let (v2, v3) = (v2.model(), v3.model());
    assert_eq!((v2.k(), v2.rows()), (EXPECTED_K, EXPECTED_ROWS));
    assert_eq!((v3.k(), v3.rows()), (EXPECTED_K, EXPECTED_ROWS));
}

struct HeapParams(ParamsProver);

impl ParamsProverProvider for HeapParams {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

fn mark_phase(path: &Option<PathBuf>, phase: &str) {
    if let Some(path) = path {
        std::fs::write(path, phase).expect("mark benchmark phase");
    }
}

fn preimage() -> ProofPreimage {
    ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("assert-pair")),
    }
}

#[actix_web::test]
#[ignore = "focused one-arm Ledger9 v2/v3 memory comparison"]
async fn compare_assert_policy() {
    let phase_file = std::env::var_os("MIDNIGHT_BENCH_PHASE_FILE").map(PathBuf::from);
    let version = std::env::var("MIDNIGHT_BENCH_IR_VERSION").expect("v2 or v3 version");
    let (v2, v3) = assert_ir_pair(ASSERT_COUNT);
    assert_eq!(
        (v2.model().k(), v2.model().rows()),
        (EXPECTED_K, EXPECTED_ROWS)
    );
    assert_eq!(
        (v3.model().k(), v3.model().rows()),
        (EXPECTED_K, EXPECTED_ROWS)
    );

    mark_phase(&phase_file, "setup");
    let params =
        ParamsKZG::<Bls12>::unsafe_setup(EXPECTED_K as u32, ChaCha20Rng::from_seed([9; 32]));
    let mut bytes = Vec::new();
    params
        .write_custom(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize synthetic SRS");
    let verifier_params = ParamsVerifier::read(&bytes[..]).expect("verifier params");
    let provider = HeapParams(ParamsProver(Arc::new(params)));

    mark_phase(&phase_file, "keygen");
    let keygen_start = Instant::now();
    match version.as_str() {
        "v2" => {
            let (pk, vk) = v2.v2_keygen(&provider).await.expect("v2 keygen");
            let keygen_seconds = keygen_start.elapsed().as_secs_f64();
            mark_phase(&phase_file, "prove");
            let prove_start = Instant::now();
            let (proof, pis, _) = v2
                .prove(ChaCha20Rng::from_seed([42; 32]), &provider, pk, &preimage())
                .await
                .expect("v2 proof");
            let prove_seconds = prove_start.elapsed().as_secs_f64();
            vk.verify(&verifier_params, &proof, pis.into_iter())
                .expect("verify v2 proof");
            mark_phase(&phase_file, "done");
            eprintln!(
                "version=v2 k={EXPECTED_K} rows={EXPECTED_ROWS} keygen_seconds={keygen_seconds:.3} prove_seconds={prove_seconds:.3} proof_bytes={}",
                proof.0.len()
            );
        }
        "v3" => {
            let (pk, vk) = v3.keygen(&provider).await.expect("v3 keygen");
            let keygen_seconds = keygen_start.elapsed().as_secs_f64();
            mark_phase(&phase_file, "prove");
            let prove_start = Instant::now();
            let (proof, pis, _) = v3
                .prove(ChaCha20Rng::from_seed([42; 32]), &provider, pk, &preimage())
                .await
                .expect("v3 proof");
            let prove_seconds = prove_start.elapsed().as_secs_f64();
            vk.verify(&verifier_params, &proof, pis.into_iter())
                .expect("verify v3 proof");
            mark_phase(&phase_file, "done");
            eprintln!(
                "version=v3 k={EXPECTED_K} rows={EXPECTED_ROWS} keygen_seconds={keygen_seconds:.3} prove_seconds={prove_seconds:.3} proof_bytes={}",
                proof.0.len()
            );
        }
        other => panic!("unknown IR version: {other}"),
    }
}
