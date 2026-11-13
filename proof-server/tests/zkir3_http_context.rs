#![cfg(not(target_family = "wasm"))]

//! Exercise release-compatible context ZKIR v3 through the real
//! HTTP server with a generated key and an immutable mapped parameter companion.
//! `MIDNIGHT_LEDGER_TEST_CEREMONY_SRS` selects a tracked Ledger9 SRS file;
//! the default remains self-contained.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use base_crypto::data_provider::MidnightDataProvider;
use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_curves::Bls12;
use midnight_proof_server::{ServerConfig, server_with_config, worker_pool::WorkerPool};
use midnight_proofs::config::ProverConfig;
use midnight_proofs::poly::commitment::Params;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::{tagged_deserialize, tagged_serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_commit;
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
    // Compact 0.36.1 (7fa3a117c) generated this ZKIR 3.1 circuit. It uses
    // the communications commitment and impact transcript required by Ledger9.
    let ir = IrSource::load(include_str!("compact-v3-counter/increment.zkir").as_bytes())
        .expect("load Compact-generated v3 IR");
    let k = ir.k();
    let full_ceremony_k = std::env::var_os("MIDNIGHT_LEDGER_TEST_CEREMONY_FULL_K").is_some();
    assert!(
        !full_ceremony_k || std::env::var_os("MIDNIGHT_LEDGER_TEST_CEREMONY_SRS").is_some(),
        "full-k gate requires the tracked Ledger9 SRS file"
    );
    if std::env::var("MIDNIGHT_SPILL_COSETS").as_deref() == Ok("1") {
        assert!(
            ProverConfig::process().spills_cosets_at(k as u32),
            "forced-spill run must select this circuit's k"
        );
    }
    let params = if let Some(path) = std::env::var_os("MIDNIGHT_LEDGER_TEST_CEREMONY_SRS") {
        let file = std::fs::File::open(path).expect("open ceremony SRS");
        let loaded = ParamsProver::read(file).expect("read ceremony SRS through Ledger9");
        let mut params = Arc::try_unwrap(loaded.0).expect("freshly loaded SRS must have one owner");
        assert!(params.max_k() >= k as u32);
        if full_ceremony_k {
            assert_eq!(params.max_k(), 14, "full-k gate expects Ledger9's k=14 SRS");
        } else {
            params.downsize(k as u32);
        }
        ParamsProver(Arc::new(params))
    } else {
        ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
            k as u32,
            ChaCha20Rng::from_seed([7; 32]),
        )))
    };
    let params_k = u8::try_from(params.0.max_k()).expect("SRS k fits the provider key");
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
        .open_or_build(&MidnightDataProvider::name_k(params_k), || Ok(params))
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
    let opening: Fr = 7.into();
    let commitment = transient_commit(&[] as &[Fr], opening);
    let public_transcript_inputs: Vec<Fr> = [0x70, 0x01, 0x01, 0x00, 0x0e, 0x01, 0xa1]
        .into_iter()
        .map(Fr::from)
        .collect();
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: Some((commitment, opening)),
        inputs: vec![],
        private_transcript: vec![],
        public_transcript_inputs: public_transcript_inputs.clone(),
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

    let pool = WorkerPool::new(1, 2, 120.0);
    let requests = pool.requests.clone();
    let release_blocker = {
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = release.clone();
        pool.submit(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !worker_release.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Vec::new())
        })
        .await
        .expect("occupy proof worker");
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.processing_count().await != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker did not start blocker");
        release
    };
    let (server, port) = server_with_config(
        0,
        false,
        pool,
        ServerConfig {
            allow_half_closed_clients: false,
            ..ServerConfig::default()
        },
    )
    .expect("start server");
    let handle = server.handle();
    let server_task = actix_web::rt::spawn(server);
    {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect queued proof client");
        let headers = format!(
            "POST /prove HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client
            .write_all(headers.as_bytes())
            .await
            .expect("send queued proof headers");
        client
            .write_all(&body)
            .await
            .expect("send queued proof body");
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.pending_count().await != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("proof was not queued");
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.pending_count().await != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closed client did not cancel queued proof");
        assert_eq!(requests.processing_count().await, 1);
        release_blocker.store(true, Ordering::SeqCst);
    }
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
    let mut public_inputs = vec![42.into(), commitment];
    public_inputs.extend(public_transcript_inputs);
    vk.verify(&verifier_params, &proof, public_inputs.into_iter())
        .expect("verify HTTP proof");
}
