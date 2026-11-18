// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

struct RunningState {
    pool: Arc<WorkerPool>,
    started: Mutex<Option<tokio::sync::oneshot::Sender<(uuid::Uuid, CancelToken)>>>,
}

async fn running_handler(state: Data<RunningState>) -> Result<HttpResponse, Error> {
    let mut guard = CancelOnDrop::new();
    let worker_cancel = guard.token.clone();
    let (id, updates) = state
        .pool
        .submit_and_subscribe(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !worker_cancel.is_cancelled() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if worker_cancel.is_cancelled() {
                Err(WorkError::CancelledUnexpectedly)
            } else {
                Err(WorkError::InternalError("worker deadline expired".into()))
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
        .send((id, guard.token.clone()))
        .expect("signal worker submission");
    let result = wait_for_proof_job(&state.pool, id, &updates, &guard.token).await?;
    guard.disarm_job();
    Ok(HttpResponse::Ok().body(result))
}

#[actix_web::test]
async fn disconnect_signals_running_worker_without_cancelling_next_job() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let pool = Arc::new(WorkerPool::new(1, 2, 5.0));
    let state = Data::new(RunningState {
        pool: pool.clone(),
        started: Mutex::new(Some(started_tx)),
    });
    let server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(state.clone())
            .route("/running-proof", web::get().to(running_handler))
    })
    .h1_allow_half_closed(false)
    .bind(("127.0.0.1", 0))
    .expect("bind probe");
    let port = server.addrs()[0].port();
    let server = server.run();
    let handle = server.handle();
    let task = actix_web::rt::spawn(server);
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect probe");
    client
        .write_all(b"GET /running-proof HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("send request");
    let (id, token) = tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("handler start timeout")
        .expect("handler start signal");
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.requests.processing_count().await != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not start");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !token.is_cancelled() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while !matches!(
            pool.poll(id).await,
            Some(JobStatus::Error(WorkError::CancelledUnexpectedly))
        ) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("running worker ignored disconnect");
    let (_, updates) = pool
        .submit_and_subscribe(|| Ok(vec![42]))
        .await
        .expect("submit independent job");
    assert_eq!(
        JobStatus::wait_for_success(&updates)
            .await
            .expect("independent job completes"),
        vec![42]
    );
    handle.stop(false).await;
    task.await.expect("server task").expect("server result");
}
