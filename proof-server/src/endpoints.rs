// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(unreachable_pub)]
#![deny(warnings)]
use actix_web::error::{
    ErrorBadRequest, ErrorPayloadTooLarge, ErrorRequestTimeout, ErrorTooManyRequests,
};
use actix_web::http::{StatusCode, header};
use actix_web::web::{self, Bytes, BytesMut, Data, Payload};
use actix_web::{Error, HttpRequest, HttpResponse, HttpResponseBuilder, Responder, get, post};
use base_crypto::data_provider::{self, MidnightDataProvider};
use base_crypto::data_provider::{FetchMode, OutputMode};
use futures_util::stream::StreamExt;
use hex::ToHex;
use introspection::Introspection;
use lazy_static::lazy_static;
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use ledger::structure::{
    INITIAL_TRANSACTION_COST_MODEL, ProofPreimageMarker, ProofPreimageVersioned, ProofVersioned,
    Signature, Transaction,
};
use midnight_proofs::config::{CancelToken, ProverConfig, ProverContext};
use rand::rngs::OsRng;
use serialize::{tagged_deserialize, tagged_serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use storage::db::InMemoryDB;
use tracing::{debug, info};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{KeyLocation, ProvingKeyMaterial, Resolver as ResolverT, WrappedIr};

use zkir as zkir_v2;
use zswap::prove::ZswapResolver;

use crate::IngressState;
use crate::versioned_ir;
use crate::worker_pool::{JobStatus, WorkError, WorkerPool};

lazy_static! {
    pub static ref PUBLIC_PARAMS: ZswapResolver = ZswapResolver(
        MidnightDataProvider::new(
            data_provider::FetchMode::OnDemand,
            data_provider::OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .expect("data provider initialization failed")
    );
}

/// Tie a proof job to its HTTP handler. A dropped handler signals the running
/// prover and cancels queued work before a worker can claim it.
struct CancelOnDrop {
    token: CancelToken,
    queued_job: Option<(Arc<WorkerPool>, uuid::Uuid)>,
}

impl CancelOnDrop {
    fn new(token: CancelToken) -> Self {
        Self {
            token,
            queued_job: None,
        }
    }

    fn track_job(&mut self, pool: Arc<WorkerPool>, id: uuid::Uuid) {
        self.queued_job = Some((pool, id));
    }

    fn disarm_job(&mut self) {
        self.queued_job = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.token.cancel();
        if let Some((pool, id)) = self.queued_job.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                let _ = pool.cancel(id).await;
            });
        }
    }
}

async fn wait_for_proof_job(
    pool: &WorkerPool,
    id: uuid::Uuid,
    updates: &async_channel::Receiver<JobStatus>,
    cancel: &CancelToken,
) -> Result<Vec<u8>, Error> {
    match tokio::time::timeout(pool.job_timeout(), JobStatus::wait_for_success(updates)).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => {
            cancel.cancel();
            let _ = pool.cancel(id).await;
            Err(ErrorRequestTimeout("proof job timed out"))
        }
    }
}

async fn payload_to_bytes(
    request: &HttpRequest,
    mut payload: Payload,
    ingress: &IngressState,
) -> Result<Bytes, Error> {
    let max = ingress.config.max_body_bytes;
    if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| ErrorBadRequest("invalid Content-Length"))?;
        if length > max {
            return Err(ErrorPayloadTooLarge(
                "request body exceeds configured limit",
            ));
        }
    }
    let mut body = BytesMut::new();
    tokio::time::timeout(ingress.config.read_timeout, async {
        while let Some(chunk) = payload.next().await {
            let chunk = chunk?;
            if chunk.len() > max.saturating_sub(body.len()) {
                return Err(ErrorPayloadTooLarge(
                    "request body exceeds configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok::<_, Error>(())
    })
    .await
    .map_err(|_| ErrorRequestTimeout("request body read timed out"))??;
    Ok(body.freeze())
}

async fn ingress_permit(
    pool: &WorkerPool,
    ingress: &IngressState,
) -> Result<tokio::sync::OwnedSemaphorePermit, Error> {
    if pool.requests.is_full().await {
        return Err(ErrorTooManyRequests("job queue full"));
    }
    ingress
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorTooManyRequests("too many concurrent request bodies"))
}

fn log_request(request: &Bytes) {
    if tracing::enabled!(tracing::Level::DEBUG) {
        if request.len() <= 4096 {
            debug!(
                "Received request: {}",
                (&request[..]).encode_hex::<String>()
            );
        } else {
            debug!("Received request: {} bytes (hex omitted)", request.len());
        }
    }
}

type TransactionProvePayload<S> = (
    Transaction<S, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    HashMap<String, ProvingKeyMaterial>,
);

#[get("/version")]
pub(crate) async fn version() -> impl Responder {
    env!("CARGO_PKG_VERSION")
}

#[get("/fetch-params/{k}")]
pub(crate) async fn fetch_k(path: web::Path<u8>) -> impl Responder {
    let k = path.into_inner();
    if !(0..=25).contains(&k) {
        return Err(ErrorBadRequest(format!("k={k} out of range")));
    }
    PUBLIC_PARAMS.0.fetch_k(k).await?;
    Ok("success")
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthResponse {
    status: &'static str,
    timestamp: time::OffsetDateTime,
}

pub(crate) async fn health() -> Result<web::Json<HealthResponse>, Error> {
    let status = HealthResponse {
        status: "ok",
        timestamp: time::OffsetDateTime::now_utc(),
    };
    Ok(web::Json(status))
}

#[derive(Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Status {
    Ok,
    Busy,
}

impl From<Status> for StatusCode {
    fn from(val: Status) -> Self {
        match val {
            Status::Ok => StatusCode::OK,
            Status::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: Status,
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    timestamp: time::OffsetDateTime,
}

#[get("/ready")]
pub(crate) async fn ready(pool: web::Data<Arc<WorkerPool>>) -> Result<HttpResponse, Error> {
    let jobs_processing = pool.requests.processing_count().await;
    let jobs_pending = pool.requests.pending_count().await;
    let job_capacity = pool.requests.capacity;
    let status = ReadyResponse {
        status: if pool.requests.is_full().await {
            Status::Busy
        } else {
            Status::Ok
        },
        jobs_processing,
        jobs_pending,
        job_capacity,
        timestamp: time::OffsetDateTime::now_utc(),
    };

    let builder = HttpResponseBuilder::new(status.status.into()).json(status);
    Ok(builder)
}

#[get("/proof-versions")]
pub(crate) async fn proof_versions() -> impl Responder {
    let mut fields = ProofVersioned::introspection().fields;
    fields.retain(|x| x != "Dummy");
    format!("{:?}", fields)
}

#[post("/k")]
pub(crate) async fn get_k(
    request: HttpRequest,
    ingress: Data<Arc<IngressState>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /k...");
    let _permit = ingress
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorTooManyRequests("too many concurrent request bodies"))?;
    let request = payload_to_bytes(&request, payload, &ingress).await?;
    log_request(&request);

    let k = versioned_ir::k(&request).map_err(ErrorBadRequest)?;

    Ok(HttpResponse::Ok().body(format!("{k}")))
}

#[post("/check")]
pub(crate) async fn check(
    request: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    ingress: Data<Arc<IngressState>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /check...");
    let permit = ingress_permit(&pool, &ingress).await?;
    let request = payload_to_bytes(&request, payload, &ingress).await?;
    log_request(&request);
    let (ppi, ir): (ProofPreimageVersioned, Option<WrappedIr>) =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let ir = match ir {
                    Some(ir) => ir.0,
                    None => {
                        let resolver = Resolver::new(
                            PUBLIC_PARAMS.clone(),
                            DustResolver(
                                MidnightDataProvider::new(
                                    FetchMode::OnDemand,
                                    OutputMode::Log,
                                    ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                                )
                                .expect("data provider initialization failed"),
                            ),
                            Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(None)))),
                        );
                        let proof_data = resolver
                            .resolve_key(ppi.key_location().clone())
                            .await
                            .map_err(|e| WorkError::BadInput(e.to_string()))?;

                        proof_data
                            .ok_or_else(|| {
                                WorkError::BadInput(format!(
                                    "couldn't find built-in key {}",
                                    ppi.key_location().0
                                ))
                            })?
                            .ir_source
                    }
                };
                let result = match ppi {
                    ProofPreimageVersioned::V2(ppi) => {
                        versioned_ir::check(ppi, &ir).map_err(WorkError::BadInput)?
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let result = result
                    .into_iter()
                    .map(|i| i.map(|i| i as u64))
                    .collect::<Vec<_>>();
                let mut response = Vec::new();
                tagged_serialize(&result, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    drop(permit);
    let response = JobStatus::wait_for_success(&updates).await?;

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove")]
pub(crate) async fn prove(
    request: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    ingress: Data<Arc<IngressState>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove...");
    let permit = ingress_permit(&pool, &ingress).await?;
    let request = payload_to_bytes(&request, payload, &ingress).await?;
    log_request(&request);
    let (ppi, data, binding_input): (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    ) = tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;

    let data = data.map(Arc::new);
    let data_resolver = data.clone();
    let mut cancel_on_drop = CancelOnDrop::new(CancelToken::new());
    let proof_cancel = cancel_on_drop.token.clone();
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |_: KeyLocation| {
                        Box::pin(std::future::ready(Ok(data_resolver
                            .as_ref()
                            .map(|material| material.as_ref().clone()))))
                    }),
                );
                let proof = match ppi {
                    ProofPreimageVersioned::V2(mut ppi) => {
                        if let Some(binding_input) = binding_input {
                            let mut inner = (*ppi).clone();
                            inner.binding_input = binding_input;
                            ppi = Arc::new(inner);
                        }
                        let proving_data = match data.as_ref() {
                            Some(pkm) => Cow::Borrowed(pkm.as_ref()),
                            None => Cow::Owned(
                                resolver
                                    .resolve_key(ppi.key_location.clone())
                                    .await
                                    .map_err(|e| WorkError::BadInput(e.to_string()))?
                                    .ok_or_else(|| {
                                        WorkError::BadInput(format!(
                                            "couldn't find key {}",
                                            ppi.key_location.0
                                        ))
                                    })?,
                            ),
                        };

                        let context = ProverContext::new(ProverConfig::process().clone())
                            .with_cancel(proof_cancel);
                        let proof =
                            versioned_ir::prove(ppi, &proving_data.ir_source, &resolver, &context)
                                .await?
                                .0;

                        ProofVersioned::V2(proof)
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let mut response = Vec::new();
                tagged_serialize(&proof, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    cancel_on_drop.track_job(pool.get_ref().clone(), _id);
    drop(permit);
    let response = wait_for_proof_job(&pool, _id, &updates, &cancel_on_drop.token).await?;
    cancel_on_drop.disarm_job();
    drop(cancel_on_drop);

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove-tx")]
pub(crate) async fn prove_transaction(
    request: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    ingress: Data<Arc<IngressState>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove-tx...");
    let permit = ingress_permit(&pool, &ingress).await?;
    let request = payload_to_bytes(&request, payload, &ingress).await?;
    log_request(&request);
    let (tx, keys): TransactionProvePayload<Signature> =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut response = Vec::new();
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |loc| {
                        Box::pin(std::future::ready(Ok(keys.get(loc.0.as_ref()).cloned())))
                    }),
                );
                let provider = zkir_v2::LocalProvingProvider {
                    rng: OsRng,
                    params: &resolver,
                    resolver: &resolver,
                };
                // NOTE: The initial cost model here is part of why this is deprecated!
                // Use /prove instead!
                tagged_serialize(
                    &tx.prove(provider, &INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model)
                        .await
                        .map_err(|e| WorkError::BadInput(e.to_string()))?,
                    &mut response,
                )
                .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    drop(permit);
    let response = JobStatus::wait_for_success(&updates).await?;
    Ok(HttpResponse::Ok().body(response))
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct DisconnectState {
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        cancel: CancelToken,
    }

    struct RunningDisconnectState {
        pool: Arc<WorkerPool>,
        started: Mutex<Option<tokio::sync::oneshot::Sender<uuid::Uuid>>>,
        cancel: CancelToken,
    }

    async fn pending_http_proof(state: Data<DisconnectState>) -> HttpResponse {
        let _guard = CancelOnDrop::new(state.cancel.clone());
        state
            .started
            .lock()
            .expect("start signal lock")
            .take()
            .expect("one request")
            .send(())
            .expect("signal handler start");
        std::future::pending::<()>().await;
        HttpResponse::Ok().finish()
    }

    async fn running_http_proof(
        state: Data<RunningDisconnectState>,
    ) -> Result<HttpResponse, Error> {
        let mut guard = CancelOnDrop::new(state.cancel.clone());
        let worker_cancel = guard.token.clone();
        let (id, updates) = state
            .pool
            .submit_and_subscribe(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                while !worker_cancel.is_cancelled() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                if worker_cancel.is_cancelled() {
                    Err(WorkError::CancelledUnexpectedly)
                } else {
                    Err(WorkError::InternalError("probe deadline expired".into()))
                }
            })
            .await?;
        guard.track_job(state.pool.clone(), id);
        state
            .started
            .lock()
            .expect("start signal lock")
            .take()
            .expect("one request")
            .send(id)
            .expect("signal job submission");
        let result = wait_for_proof_job(&state.pool, id, &updates, &guard.token).await?;
        guard.disarm_job();
        Ok(HttpResponse::Ok().body(result))
    }

    #[actix_web::test]
    async fn client_close_cancels_pending_handler_when_half_closes_disallowed() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let state = Data::new(DisconnectState {
            started: Mutex::new(Some(started_tx)),
            cancel: CancelToken::new(),
        });
        let observed = state.cancel.clone();
        let server = actix_web::HttpServer::new(move || {
            actix_web::App::new()
                .app_data(state.clone())
                .route("/pending-proof", web::get().to(pending_http_proof))
        })
        .h1_allow_half_closed(false)
        .bind(("127.0.0.1", 0))
        .expect("bind local probe");
        let port = server.addrs()[0].port();
        let server = server.run();
        let handle = server.handle();
        let task = actix_web::rt::spawn(server);
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect local probe");
        client
            .write_all(b"GET /pending-proof HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("send request");
        tokio::time::timeout(std::time::Duration::from_secs(2), started_rx)
            .await
            .expect("handler start timeout")
            .expect("handler start signal");
        drop(client);
        let cancelled = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !observed.is_cancelled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        handle.stop(false).await;
        task.await.expect("server task").expect("server result");
        assert!(
            cancelled.is_ok(),
            "disconnect did not cancel the handler token"
        );
    }

    #[actix_web::test]
    async fn client_close_signals_running_worker_without_cancelling_next_job() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let pool = Arc::new(WorkerPool::new(1, 2, 5.0));
        let state = Data::new(RunningDisconnectState {
            pool: pool.clone(),
            started: Mutex::new(Some(started_tx)),
            cancel: CancelToken::new(),
        });
        let observed = state.cancel.clone();
        let server = actix_web::HttpServer::new(move || {
            actix_web::App::new()
                .app_data(state.clone())
                .route("/running-proof", web::get().to(running_http_proof))
        })
        .h1_allow_half_closed(false)
        .bind(("127.0.0.1", 0))
        .expect("bind local probe");
        let port = server.addrs()[0].port();
        let server = server.run();
        let handle = server.handle();
        let task = actix_web::rt::spawn(server);
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect local probe");
        client
            .write_all(b"GET /running-proof HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("send request");
        let id = tokio::time::timeout(std::time::Duration::from_secs(2), started_rx)
            .await
            .expect("handler start timeout")
            .expect("handler start signal");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while pool.requests.processing_count().await != 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker did not start");
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !observed.is_cancelled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("disconnect did not signal request token");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !matches!(
                pool.poll(id).await,
                Some(JobStatus::Error(WorkError::CancelledUnexpectedly))
            ) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("running worker did not stop at cancellation checkpoint");
        let (_, updates) = pool
            .submit_and_subscribe(|| Ok(vec![42]))
            .await
            .expect("submit independent job");
        assert_eq!(
            JobStatus::wait_for_success(&updates)
                .await
                .expect("independent job completed"),
            vec![42]
        );
        handle.stop(false).await;
        task.await.expect("server task").expect("server result");
    }

    #[actix_web::test]
    async fn default_server_allows_client_half_close_after_request() {
        let (server, port) = crate::server_with_config(
            0,
            false,
            WorkerPool::new(1, 1, 5.0),
            crate::ServerConfig::default(),
        )
        .expect("start default proof server");
        let handle = server.handle();
        let task = actix_web::rt::spawn(server);
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect proof server");
        client
            .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("send version request");
        client.shutdown().await.expect("half-close request side");
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .expect("response timeout")
        .expect("read response");
        handle.stop(false).await;
        task.await.expect("server task").expect("server result");
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(env!("CARGO_PKG_VERSION").as_bytes()));
    }

    #[actix_web::test]
    async fn proof_job_deadline_cancels_only_the_expired_request() {
        let pool = WorkerPool::new(1, 2, 0.1);
        let expired = CancelToken::new();
        let worker_token = expired.clone();
        let (id, updates) = pool
            .submit_and_subscribe(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while !worker_token.is_cancelled() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(WorkError::CancelledUnexpectedly)
            })
            .await
            .expect("submit expiring proof");
        let error = wait_for_proof_job(&pool, id, &updates, &expired)
            .await
            .expect_err("proof must reach its deadline");
        assert_eq!(
            error.as_response_error().status_code(),
            StatusCode::REQUEST_TIMEOUT
        );
        assert!(expired.is_cancelled());

        let live = CancelToken::new();
        let (id, updates) = pool
            .submit_and_subscribe(|| Ok(vec![42]))
            .await
            .expect("submit independent proof");
        assert_eq!(
            wait_for_proof_job(&pool, id, &updates, &live)
                .await
                .expect("independent proof completes"),
            vec![42]
        );
        assert!(!live.is_cancelled());
        pool.shutdown().await;
    }

    #[actix_web::test]
    async fn proof_job_deadline_skips_queued_work() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pool = WorkerPool::new(1, 2, 0.05);
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = release.clone();
        pool.submit(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !worker_release.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(Vec::new())
        })
        .await
        .expect("occupy worker");
        let token = CancelToken::new();
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = ran.clone();
        let (id, updates) = pool
            .submit_and_subscribe(move || {
                worker_ran.store(true, Ordering::SeqCst);
                Ok(Vec::new())
            })
            .await
            .expect("submit queued proof");
        let result = wait_for_proof_job(&pool, id, &updates, &token).await;
        release.store(true, Ordering::SeqCst);
        let error = result.expect_err("queued proof must reach its deadline");
        assert_eq!(
            error.as_response_error().status_code(),
            StatusCode::REQUEST_TIMEOUT
        );
        assert!(token.is_cancelled());
        assert!(matches!(updates.recv().await, Ok(JobStatus::Cancelled)));
        pool.shutdown().await;
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dropped_request_cancels_only_its_proof_token() {
        let abandoned = CancelOnDrop::new(CancelToken::new());
        let abandoned_proof = abandoned.token.clone();
        let live = CancelOnDrop::new(CancelToken::new());
        let live_proof = live.token.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handler = tokio::spawn(async move {
            let _guard = abandoned;
            started_tx.send(()).expect("signal handler start");
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("handler started");
        handler.abort();
        assert!(
            handler
                .await
                .expect_err("handler was aborted")
                .is_cancelled()
        );

        assert!(abandoned_proof.is_cancelled());
        assert!(!live_proof.is_cancelled());
        drop(live);
    }
}
