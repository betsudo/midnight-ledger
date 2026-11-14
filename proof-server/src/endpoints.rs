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

                        let wrap = versioned_ir::proof_envelope_for_vk(&proving_data.verifier_key)?;
                        let proof = versioned_ir::prove(ppi, &proving_data.ir_source, &resolver)
                            .await?
                            .0;

                        wrap(proof)
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
    drop(permit);
    let response = JobStatus::wait_for_success(&updates).await?;

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
                        .map_err(versioned_ir::classify_transaction_proving_error)?,
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
