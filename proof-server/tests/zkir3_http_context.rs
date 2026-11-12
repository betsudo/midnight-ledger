#![cfg(not(target_family = "wasm"))]

//! Exercise both released and opt-in context ZKIR v3 routes through the real
//! HTTP server with a generated key and an immutable mapped parameter companion.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use base_crypto::data_provider::MidnightDataProvider;
use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_curves::Bls12;
use midnight_proof_server::{server, worker_pool::WorkerPool};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    CompanionCache, KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, ProofPreimage,
    ProvingKeyMaterial, TrustedParamsDir, Zkir,
};
use zkir_v3::IrSource;
use zswap::prove::ZswapResolver;

struct HeapParams(ParamsProver);

impl ParamsProverProvider for HeapParams {
    async fn get_params(&self, _k: u8) -> std::io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

#[actix_web::test]
async fn prove_endpoint_accepts_v3_with_mapped_params() {
    let ir = IrSource::load(
        &br#"{
            "version": { "major": 3, "minor": 0 },
            "inputs": [{ "name": "%v_0", "type": "Scalar<BLS12-381>" }],
            "outputs": [],
            "do_communications_commitment": false,
            "instructions": [{ "op": "assert", "cond": "%v_0" }]
        }"#[..],
    )
    .expect("load v3 IR");
    let k = ir.k();
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        k as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params
        .0
        .write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize params");
    let verifier_params = ParamsVerifier::read(&params_bytes[..]).expect("read verifier params");
    let (pk, vk) = ir
        .keygen(&HeapParams(params.clone()))
        .await
        .expect("v3 keygen");

    let dir = tempfile::tempdir().expect("private companion dir");
    // The test owns this directory and leaves its companion immutable until
    // the server has stopped and every mapped view has been dropped.
    let trusted = unsafe { TrustedParamsDir::new(dir.path()) };
    let cache = CompanionCache::from_trusted_dir(trusted.clone());
    cache
        .open_or_build(&MidnightDataProvider::name_k(k), || Ok(params))
        .expect("publish companion");
    ZswapResolver::configure_mapped_params_dir(trusted).expect("configure mapped params");

    let mut prover_key = Vec::new();
    let mut verifier_key = Vec::new();
    let mut ir_source = Vec::new();
    tagged_serialize(&pk, &mut prover_key).expect("serialize prover key");
    tagged_serialize(&vk, &mut verifier_key).expect("serialize verifier key");
    tagged_serialize(&ir, &mut ir_source).expect("serialize IR");
    let data = ProvingKeyMaterial {
        prover_key,
        verifier_key,
        ir_source,
    };
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("test")),
    };
    let mut body = Vec::new();
    tagged_serialize(
        &(
            ProofPreimageVersioned::V2(Arc::new(preimage)),
            Some(data),
            None::<Fr>,
        ),
        &mut body,
    )
    .expect("serialize prove request");

    let (server, port) = server(0, false, WorkerPool::new(1, 2, 120.0)).expect("start server");
    let handle = server.handle();
    let server_task = actix_web::rt::spawn(server);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client")
        .post(format!("http://127.0.0.1:{port}/prove"))
        .body(body)
        .send()
        .await
        .expect("prove request");
    let status = response.status();
    let bytes = response.bytes().await.expect("read prove response");
    handle.stop(false).await;
    server_task
        .await
        .expect("server task panicked")
        .expect("server error");
    assert_eq!(
        status,
        200,
        "unexpected prove response: {}",
        String::from_utf8_lossy(&bytes)
    );
    let proof = tagged_deserialize::<ProofVersioned>(bytes.as_ref()).expect("deserialize proof");
    let ProofVersioned::V2(proof) = proof else {
        panic!("unexpected proof version");
    };
    vk.verify(&verifier_params, &proof, [42.into()].into_iter())
        .expect("verify HTTP proof");
}
