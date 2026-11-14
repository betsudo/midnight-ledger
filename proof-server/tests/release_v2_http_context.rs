#![cfg(not(target_family = "wasm"))]

//! Exercise released Ledger 9.1.0.1 V2 key material through `/prove`.
//! Its verifier key uses the v7 tag, which requires a V3 proof envelope.

use std::{borrow::Cow, sync::Arc, time::Duration};

use base_crypto::data_provider::MidnightDataProvider;
use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_curves::Bls12;
use midnight_proof_server::{ServerConfig, server_with_config, worker_pool::WorkerPool};
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::proofs::{
    CompanionCache, KeyLocation, ParamsProver, ParamsVerifier, ProofPreimage, ProvingKeyMaterial,
    TrustedParamsDir, VerifierKey, Zkir,
};
use zkir::IrSource;
use zswap::prove::ZswapResolver;

const IR: &[u8] = include_bytes!("release-v2-9.1.0.1/ir.bin");
const PARAMS: &[u8] = include_bytes!("release-v2-9.1.0.1/params.bin");
const PK: &[u8] = include_bytes!("release-v2-9.1.0.1/prover-key.bin");
const VK: &[u8] = include_bytes!("release-v2-9.1.0.1/verifier-key.bin");

#[actix_web::test]
async fn released_v2_key_gets_v3_http_envelope() {
    let ir: IrSource = tagged_deserialize(&mut &IR[..]).expect("released V2 IR");
    let prover_params =
        ParamsKZG::<Bls12>::read_custom(&mut &PARAMS[..], SerdeFormat::RawBytesUnchecked)
            .expect("released prover params");
    let dir = tempfile::tempdir().expect("private companion directory");
    // This test owns the directory and leaves its companion immutable while mapped.
    let trusted = unsafe { TrustedParamsDir::new(dir.path()) };
    CompanionCache::from_trusted_dir(trusted.clone())
        .open_or_build(&MidnightDataProvider::name_k(ir.k()), || {
            Ok(ParamsProver(Arc::new(prover_params)))
        })
        .expect("publish released parameters");
    ZswapResolver::configure_mapped_params_dir(trusted).expect("configure mapped params");

    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("release-v2")),
    };
    let data = ProvingKeyMaterial {
        prover_key: PK.to_vec(),
        verifier_key: VK.to_vec(),
        ir_source: IR.to_vec(),
    };
    let mut request = Vec::new();
    tagged_serialize(
        &(
            ProofPreimageVersioned::V2(Arc::new(preimage)),
            Some(data),
            None::<transient_crypto::curve::Fr>,
        ),
        &mut request,
    )
    .expect("serialize released V2 prove request");

    let (server, port) = server_with_config(
        0,
        false,
        WorkerPool::new(1, 2, 120.0),
        ServerConfig::default(),
    )
    .expect("start proof server");
    let handle = server.handle();
    let server_task = actix_web::rt::spawn(server);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client")
        .post(format!("http://127.0.0.1:{port}/prove"))
        .body(request)
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
    let envelope: ProofVersioned =
        tagged_deserialize(bytes.as_ref()).expect("deserialize versioned proof");
    let ProofVersioned::V3(proof) = envelope else {
        panic!("released v7 verifier key must select the V3 envelope");
    };
    let vk: VerifierKey = tagged_deserialize(&mut &VK[..]).expect("released verifier key");
    let params = ParamsVerifier::read(PARAMS).expect("released verifier params");
    vk.verify(&params, &proof, [42.into()].into_iter())
        .expect("released verifier key accepts HTTP proof");
}
