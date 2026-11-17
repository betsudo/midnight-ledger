// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

#![cfg(not(target_family = "wasm"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_proof_server::worker_pool::{JobStatus, WorkerPool};
use midnight_proof_server::{ServerConfig, server, server_with_config};
use serialize::{tagged_deserialize, tagged_serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{ProofPreimage, ProvingKeyMaterial};

#[cfg(feature = "native-memory")]
use base_crypto::data_provider::MidnightDataProvider;
#[cfg(feature = "native-memory")]
use transient_crypto::proofs::{
    CompanionCache, ParamsProver, ParamsVerifier, TrustedParamsDir, VerifierKey,
};
#[cfg(feature = "native-memory")]
use zswap::prove::ZswapResolver;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal"
);

fn proof_body() -> Vec<u8> {
    let preimage: ProofPreimage = tagged_deserialize(
        std::fs::read(format!("{FIXTURE}/preimage.bin"))
            .expect("read release preimage")
            .as_slice(),
    )
    .expect("decode release preimage");
    let material = ProvingKeyMaterial {
        prover_key: std::fs::read(format!("{FIXTURE}/keys/minimal.prover"))
            .expect("read release prover key"),
        verifier_key: std::fs::read(format!("{FIXTURE}/keys/minimal.verifier"))
            .expect("read release verifier key"),
        ir_source: {
            let ir = zkir_v3::IrSource::load(
                std::fs::read(format!("{FIXTURE}/zkir/minimal.zkir"))
                    .expect("read release IR")
                    .as_slice(),
            )
            .expect("decode release IR");
            let mut bytes = Vec::new();
            tagged_serialize(&ir, &mut bytes).expect("encode release IR");
            bytes
        },
    };
    let mut body = Vec::new();
    tagged_serialize(
        &(
            ProofPreimageVersioned::V2(Arc::new(preimage)),
            Some(material),
            None::<Fr>,
        ),
        &mut body,
    )
    .expect("encode proof request");
    body
}

async fn occupied_pool(timeout_secs: f64) -> (WorkerPool, Arc<AtomicBool>) {
    let pool = WorkerPool::new(1, 1, timeout_secs);
    let release = Arc::new(AtomicBool::new(false));
    let worker_release = release.clone();
    let (_, updates) = pool
        .submit_and_subscribe(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !worker_release.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(Vec::new())
        })
        .await
        .expect("occupy worker");
    assert!(matches!(updates.recv().await, Ok(JobStatus::Processing)));
    (pool, release)
}

#[actix_web::test]
async fn disconnected_v3_request_releases_queued_body_without_affecting_server() {
    let (pool, release) = occupied_pool(5.0).await;
    let requests = pool.requests.clone();
    let (server, port) = server_with_config(
        0,
        false,
        pool,
        ServerConfig {
            allow_half_closed_clients: false,
            ..ServerConfig::default()
        },
    )
    .expect("start proof server");
    let handle = server.handle();
    let task = actix_web::rt::spawn(server);

    let body = proof_body();
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect proof client");
    let headers = format!(
        "POST /prove HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    client
        .write_all(headers.as_bytes())
        .await
        .expect("send headers");
    client.write_all(&body).await.expect("send body");
    tokio::time::timeout(Duration::from_secs(3), async {
        while requests.pending_count().await != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("V3 proof did not enter queue");
    drop(client);
    tokio::time::timeout(Duration::from_secs(3), async {
        while requests.pending_count().await != 0 || requests.is_full().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("disconnect did not release queued request");
    assert_eq!(requests.processing_count().await, 1);
    release.store(true, Ordering::SeqCst);

    let response = reqwest::get(format!("http://127.0.0.1:{port}/version"))
        .await
        .expect("live server responds");
    assert_eq!(response.status(), 200);
    handle.stop(false).await;
    task.await.expect("server task").expect("server result");
}

#[actix_web::test]
async fn queued_v3_deadline_returns_timeout_and_releases_admission() {
    let (pool, release) = occupied_pool(0.1).await;
    let requests = pool.requests.clone();
    let (server, port) =
        server_with_config(0, false, pool, ServerConfig::default()).expect("start proof server");
    let handle = server.handle();
    let task = actix_web::rt::spawn(server);
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/prove"))
        .body(proof_body())
        .send()
        .await
        .expect("proof timeout response");
    assert_eq!(response.status(), 408);
    assert_eq!(requests.pending_count().await, 0);
    assert!(!requests.is_full().await);
    release.store(true, Ordering::SeqCst);
    handle.stop(false).await;
    task.await.expect("server task").expect("server result");
}

#[actix_web::test]
async fn default_server_accepts_half_closed_http1_clients() {
    let (server, port) =
        server(0, false, WorkerPool::new(1, 1, 5.0)).expect("start default proof server");
    let handle = server.handle();
    let task = actix_web::rt::spawn(server);
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect proof server");
    client
        .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("send request");
    client.shutdown().await.expect("half-close request side");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .expect("response deadline")
        .expect("read response");
    handle.stop(false).await;
    task.await.expect("server task").expect("server result");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(env!("CARGO_PKG_VERSION").as_bytes()));
}

#[cfg(feature = "native-memory")]
#[actix_web::test]
async fn release_v3_fixture_proves_over_http_with_request_context() {
    let params_bytes =
        std::fs::read(format!("{FIXTURE}/params.bin")).expect("read official k4 parameters");
    let params =
        ParamsProver::read(params_bytes.as_slice()).expect("decode official k4 parameters");
    let companion_dir = tempfile::tempdir().expect("private parameter companion");
    // This test owns the directory and does not change the companion while
    // the proof server holds a mapped view.
    let trusted = unsafe { TrustedParamsDir::new(companion_dir.path()) };
    CompanionCache::from_trusted_dir(trusted.clone())
        .open_or_build(&MidnightDataProvider::name_k(4), || Ok(params))
        .expect("publish official k4 parameter companion");
    ZswapResolver::configure_mapped_params_dir(trusted)
        .expect("configure local parameter provider");

    let (server, port) = server(0, false, WorkerPool::new(1, 1, 30.0)).expect("start proof server");
    let handle = server.handle();
    let task = actix_web::rt::spawn(server);
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/prove"))
        .body(proof_body())
        .send()
        .await
        .expect("HTTP proof request");
    let status = response.status();
    let bytes = response.bytes().await.expect("read HTTP proof");
    handle.stop(false).await;
    task.await.expect("server task").expect("server result");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
    let ProofVersioned::V2(proof) =
        tagged_deserialize::<ProofVersioned>(bytes.as_ref()).expect("decode HTTP proof")
    else {
        panic!("unexpected proof version");
    };
    let preimage: ProofPreimage = tagged_deserialize(
        std::fs::read(format!("{FIXTURE}/preimage.bin"))
            .expect("read preimage")
            .as_slice(),
    )
    .expect("decode preimage");
    let vk: VerifierKey = tagged_deserialize(
        std::fs::read(format!("{FIXTURE}/keys/minimal.verifier"))
            .expect("read verifier key")
            .as_slice(),
    )
    .expect("decode verifier key");
    vk.init().expect("initialize verifier key");
    let verifier_params =
        ParamsVerifier::read(params_bytes.as_slice()).expect("read verifier parameters");
    let mut public_inputs = vec![preimage.binding_input];
    if let Some((commitment, _)) = preimage.communications_commitment {
        public_inputs.push(commitment);
    }
    public_inputs.extend(preimage.public_transcript_inputs.iter().copied());
    public_inputs.extend(preimage.public_transcript_outputs.iter().copied());
    vk.verify(&verifier_params, &proof, public_inputs.into_iter())
        .expect("verify HTTP proof with official k4 parameters");
}
