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

use actix_web::error::{
    ErrorBadRequest, ErrorInternalServerError, ErrorPreconditionRequired, ErrorTooManyRequests,
};
use async_channel::{Receiver, RecvError, Sender, bounded, unbounded};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::{sync::Mutex, task};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum WorkerPoolError {
    #[error("Job Queue full")]
    JobQueueFull,
    #[error("Work channel closed")]
    ChannelClosed,
    #[error("Job Missing")]
    JobMissing(Uuid),
    #[error("Tried to cancel job, but job wasn't pending")]
    JobNotPending(Uuid),
}

#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum WorkError {
    #[error("bad input: `{0}`")]
    BadInput(String),
    #[error("internal error")]
    InternalError(String),
    /// An operator-owned parameter cache or temporary proving volume failed.
    /// The response names the failing operation for server diagnostics.
    #[error("server environment: {0}")]
    ServerEnvironment(String),
    #[error("work cancelled unexpectedly")]
    CancelledUnexpectedly,
    #[error("task join error")]
    JoinError,
}

impl From<WorkError> for actix_web::Error {
    fn from(val: WorkError) -> Self {
        match val {
            e @ WorkError::BadInput(_) => ErrorBadRequest(e),
            e @ WorkError::InternalError(_) => ErrorInternalServerError(e),
            e @ WorkError::ServerEnvironment(_) => ErrorInternalServerError(e),
            e @ WorkError::CancelledUnexpectedly => ErrorInternalServerError(e),
            e @ WorkError::JoinError => ErrorInternalServerError(e),
        }
    }
}

impl From<WorkerPoolError> for actix_web::Error {
    fn from(val: WorkerPoolError) -> Self {
        match val {
            e @ WorkerPoolError::JobQueueFull => ErrorTooManyRequests(e),
            e @ WorkerPoolError::ChannelClosed => ErrorInternalServerError(e),
            e @ WorkerPoolError::JobMissing(_uuid) => ErrorPreconditionRequired(e),
            e @ WorkerPoolError::JobNotPending(_uuid) => ErrorBadRequest(e),
        }
    }
}

#[derive(Clone)]
pub enum JobStatus {
    Pending,
    Processing,
    Cancelled,
    Error(WorkError),
    Success(Vec<u8>),
}

impl JobStatus {
    pub async fn wait_for_success(updates: &Receiver<JobStatus>) -> Result<Vec<u8>, WorkError> {
        while let Ok(status) = updates.recv().await {
            match status {
                JobStatus::Success(res) => return Ok(res),
                JobStatus::Error(e) => return Err(e),
                JobStatus::Cancelled => return Err(WorkError::CancelledUnexpectedly),
                _ => continue,
            }
        }
        Err(WorkError::InternalError(
            "failed to complete job".to_string(),
        ))
    }
}

type Work = Box<dyn FnOnce() -> Result<Vec<u8>, WorkError> + Send + 'static>;

pub struct WorkItem {
    id: Uuid,
}

#[derive(Clone)]
pub struct Job {
    status: JobStatus,
    // The channel holds only an ID. Cancelling a pending request can drop its
    // captured body immediately, even while another worker is occupied.
    work: Arc<StdMutex<Option<Work>>>,
    update_sender: Sender<JobStatus>,
    update_receiver: Arc<Receiver<JobStatus>>,
    timeout: SystemTime,
}

impl Job {
    fn new(ttl: Duration, work: Work) -> Self {
        let (update_sender, receiver) = unbounded();
        Self {
            update_sender,
            update_receiver: Arc::new(receiver),
            status: JobStatus::Pending,
            work: Arc::new(StdMutex::new(Some(work))),
            timeout: SystemTime::now() + ttl,
        }
    }

    fn updates(&self) -> Arc<Receiver<JobStatus>> {
        self.update_receiver.clone()
    }
}

#[derive(Clone)]
pub struct Requests {
    pub capacity: usize,
    job_ttl: Duration,
    reqs: Arc<Mutex<HashMap<Uuid, Job>>>,
    // Counts pending closures that still retain their captured request body.
    queued: Arc<AtomicUsize>,
}

impl Requests {
    fn new(capacity: usize, job_ttl: Duration) -> Self {
        Self {
            capacity,
            job_ttl,
            reqs: Default::default(),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn processing_count(&self) -> usize {
        self.reqs
            .lock()
            .await
            .values()
            .filter(|j| matches!(j.status, JobStatus::Processing))
            .count()
    }

    pub async fn pending_count(&self) -> usize {
        self.reqs
            .lock()
            .await
            .values()
            .filter(|j| matches!(j.status, JobStatus::Pending))
            .count()
    }

    pub async fn is_full(&self) -> bool {
        self.capacity != 0 && self.queued.load(Ordering::Acquire) >= self.capacity
    }

    async fn set_status(&self, id: &Uuid, status: JobStatus) {
        if let Some(req) = self.reqs.lock().await.get_mut(id) {
            req.status = status.clone();
            req.update_sender.send(status).await.unwrap();
        }
    }

    async fn new_req(
        &self,
        work: Work,
    ) -> Result<(Uuid, Arc<Receiver<JobStatus>>), WorkerPoolError> {
        // Capacity admission must be one atomic operation. With the previous
        // `is_full().await` followed by a second lock for `insert`, a burst of
        // HTTP requests could all observe spare capacity and overfill the
        // supposedly bounded queue before any one of them inserted its job.
        let mut reqs = self.reqs.lock().await;
        if self.capacity != 0 && self.queued.load(Ordering::Acquire) >= self.capacity {
            return Err(WorkerPoolError::JobQueueFull);
        }
        let req = Job::new(self.job_ttl, work);
        let updates = req.updates();
        let id = Uuid::new_v4();
        reqs.insert(id, req);
        self.queued.fetch_add(1, Ordering::Release);
        Ok((id, updates))
    }

    async fn get(&self, id: Uuid) -> Option<Job> {
        self.reqs.lock().await.get(&id).cloned()
    }

    async fn try_start(&self, id: Uuid) -> Option<Work> {
        let mut reqs = self.reqs.lock().await;
        let req = reqs.get_mut(&id)?;
        if !matches!(req.status, JobStatus::Pending) {
            return None;
        }
        let work = req
            .work
            .lock()
            .expect("job work lock")
            .take()
            .expect("pending job retains its work");
        req.status = JobStatus::Processing;
        self.queued.fetch_sub(1, Ordering::AcqRel);
        req.update_sender.try_send(JobStatus::Processing).unwrap();
        Some(work)
    }

    async fn cancel(&self, id: Uuid) -> Result<(), WorkerPoolError> {
        let mut reqs = self.reqs.lock().await;
        let req = reqs.get_mut(&id).ok_or(WorkerPoolError::JobMissing(id))?;
        if !matches!(req.status, JobStatus::Pending) {
            return Err(WorkerPoolError::JobNotPending(id));
        }
        let work = req.work.lock().expect("job work lock").take();
        req.status = JobStatus::Cancelled;
        self.queued.fetch_sub(1, Ordering::AcqRel);
        req.update_sender.try_send(JobStatus::Cancelled).unwrap();
        drop(reqs);
        drop(work);
        Ok(())
    }

    async fn remove(&self, id: Uuid) {
        let mut reqs = self.reqs.lock().await;
        let job = reqs.remove(&id);
        if job
            .as_ref()
            .is_some_and(|job| matches!(job.status, JobStatus::Pending))
        {
            self.queued.fetch_sub(1, Ordering::AcqRel);
        }
        drop(reqs);
        drop(job);
    }

    async fn gc(&self) {
        let mut reqs = self.reqs.lock().await;
        let mut keys_to_remove = vec![];
        let now = SystemTime::now();
        for (id, req) in reqs.iter() {
            if req.timeout < now {
                keys_to_remove.push(*id);
            }
        }
        let removed: Vec<_> = keys_to_remove
            .into_iter()
            .filter_map(|key| reqs.remove(&key))
            .collect();
        let pending = removed
            .iter()
            .filter(|job| matches!(job.status, JobStatus::Pending))
            .count();
        if pending != 0 {
            self.queued.fetch_sub(pending, Ordering::AcqRel);
        }
        drop(reqs);
        drop(removed);
    }
}

/// Worker pool that processes work items in parallel
pub struct WorkerPool {
    sender: Sender<WorkItem>,
    workers: Vec<task::JoinHandle<()>>,
    pub requests: Requests,
    job_gc_handle: task::JoinHandle<()>,
    gc_stop_sender: Sender<()>,
}

impl WorkerPool {
    pub fn job_timeout(&self) -> Duration {
        self.requests.job_ttl
    }

    /// Creates a new worker pool with the specified number of workers and channel capacity
    pub fn new(num_workers: usize, job_capacity: usize, job_timeout_secs: f64) -> Self {
        let (work_sender, work_receiver) = unbounded::<WorkItem>();
        let work_receiver = Arc::new(work_receiver);
        let requests = Requests::new(job_capacity, Duration::from_secs_f64(job_timeout_secs));
        let mut workers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let work_receiver = Arc::clone(&work_receiver);
            let requests = requests.clone();

            let handle = task::spawn(async move {
                while let Ok(work) = work_receiver.recv().await {
                    // Starting work and cancelling it must compete for the
                    // same pending state under one lock.
                    let Some(job_work) = requests.try_start(work.id).await else {
                        continue;
                    };
                    let result = task::spawn_blocking(job_work).await;
                    match result {
                        Ok(Ok(res)) => requests.set_status(&work.id, JobStatus::Success(res)).await,
                        Ok(Err(e)) => requests.set_status(&work.id, JobStatus::Error(e)).await,
                        Err(_e) => {
                            requests
                                .set_status(&work.id, JobStatus::Error(WorkError::JoinError))
                                .await
                        }
                    }
                }
            });

            workers.push(handle);
        }

        let (gc_stop_sender, gc_stop_receiver) = bounded::<()>(1);
        let job_gc_handle = {
            let requests = requests.clone();
            tokio::spawn(async move {
                loop {
                    match tokio::time::timeout(Duration::from_secs(10), gc_stop_receiver.recv())
                        .await
                    {
                        Ok(Ok(_)) => break,
                        Ok(Err(RecvError)) => break,
                        // Timeout case
                        Err(_) => requests.gc().await,
                    }
                }
            })
        };

        WorkerPool {
            sender: work_sender,
            workers,
            requests,
            job_gc_handle,
            gc_stop_sender,
        }
    }

    async fn enqueue(
        &self,
        work: Work,
    ) -> Result<(Uuid, Arc<Receiver<JobStatus>>), WorkerPoolError> {
        let (id, updates) = self.requests.new_req(work).await?;
        // No suspension follows admission on the successful path: a dropped
        // handler cannot leave an untracked queued job behind.
        if self.sender.try_send(WorkItem { id }).is_err() {
            self.requests.remove(id).await;
            return Err(WorkerPoolError::ChannelClosed);
        }
        Ok((id, updates))
    }

    /// Submits a work item to the pool
    pub async fn submit<F>(&self, work: F) -> Result<Uuid, WorkerPoolError>
    where
        F: FnOnce() -> Result<Vec<u8>, WorkError> + Send + 'static,
    {
        let (id, _) = self.enqueue(Box::new(work)).await?;
        Ok(id)
    }

    /// Submits a work item to the pool and returns both the job ID and a subscription to its status updates
    /// Returns None if the submission fails
    pub async fn submit_and_subscribe<F>(
        &self,
        work: F,
    ) -> Result<(Uuid, Arc<Receiver<JobStatus>>), WorkerPoolError>
    where
        F: FnOnce() -> Result<Vec<u8>, WorkError> + Send + 'static,
    {
        self.enqueue(Box::new(work)).await
    }

    /// Receives the result of a completed work item
    pub async fn poll(&self, id: Uuid) -> Option<JobStatus> {
        let job = self.requests.get(id).await;
        if let Some(ref job) = job {
            if job.timeout < SystemTime::now() {
                return None;
            }
            Some(job.status.clone())
        } else {
            None
        }
    }

    /// Cancels a job with the given ID
    /// Succeeds only while the job is still pending.
    pub async fn cancel(&self, id: Uuid) -> Result<(), WorkerPoolError> {
        self.requests.cancel(id).await
    }

    /// Subscribes to status updates for a specific job
    /// Returns a receiver that will receive all status updates for the job
    /// Returns None if the job doesn't exist or has already timed out
    pub async fn subscribe(&self, id: Uuid) -> Result<Arc<Receiver<JobStatus>>, WorkerPoolError> {
        let job = self
            .requests
            .get(id)
            .await
            .ok_or(WorkerPoolError::JobMissing(id))?;
        if job.timeout < SystemTime::now() {
            return Err(WorkerPoolError::JobMissing(id));
        }
        Ok(job.updates())
    }

    /// Shuts down the worker pool, waiting for all workers to complete
    pub async fn shutdown(self) {
        drop(self.sender);
        drop(self.gc_stop_sender);
        for worker in self.workers {
            worker.await.unwrap();
        }
        self.job_gc_handle.await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_worker_pool_basic() {
        let pool = WorkerPool::new(4, 10, 2.0);

        // Submit some work using closures
        let mut ids = vec![];
        for i in 0..5u32 {
            let id = pool
                .submit(move || Ok((i * 2).to_le_bytes().to_vec()))
                .await
                .unwrap();
            ids.push(id);
        }

        // Collect results
        let mut results = Vec::new();
        for id in ids {
            let updates = pool.subscribe(id).await.unwrap();
            while let Ok(status) = updates.recv().await {
                if let JobStatus::Success(res) = status {
                    let result_u32 = u32::from_le_bytes(res.try_into().unwrap());
                    results.push(result_u32);
                    break;
                }
            }
        }

        // Verify results
        results.sort();
        assert_eq!(results, vec![0, 2, 4, 6, 8]);

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_error_handling() {
        let pool = WorkerPool::new(2, 5, 2.0);

        let error_message = "Test error".to_string();
        let error_message_clone = error_message.clone(); // Clone for closure
        let (_id, receiver) = pool
            .submit_and_subscribe(move || Err(WorkError::InternalError(error_message_clone)))
            .await
            .unwrap();

        while let Ok(status) = receiver.recv().await {
            if let JobStatus::Error(e) = status {
                assert_eq!(e, WorkError::InternalError(error_message));
                break;
            }
        }

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_cancellation() {
        let pool = WorkerPool::new(1, 5, 2.0);
        let (release_first, first_released) = std::sync::mpsc::channel();
        let (_, first_updates) = pool
            .submit_and_subscribe(move || {
                first_released.recv().unwrap();
                Ok(vec![])
            })
            .await
            .unwrap();
        while !matches!(first_updates.recv().await.unwrap(), JobStatus::Processing) {}

        // The only worker is occupied, so this job remains pending.
        let ran = Arc::new(AtomicBool::new(false));
        let ran_in_work = ran.clone();
        let (id, receiver) = pool
            .submit_and_subscribe(move || {
                ran_in_work.store(true, Ordering::SeqCst);
                Ok(vec![1, 2, 3])
            })
            .await
            .unwrap();

        let cancelled_job = pool.cancel(id).await;
        assert!(cancelled_job.is_ok());

        // Verify the job was cancelled using subscription
        while let Ok(status) = receiver.recv().await {
            if matches!(status, JobStatus::Cancelled) {
                break;
            }
        }

        release_first.send(()).unwrap();
        pool.shutdown().await;
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_and_start_cannot_both_succeed() {
        for start_first in [true, false] {
            let requests = Requests::new(1, Duration::from_secs(1));
            let (id, _) = requests.new_req(Box::new(|| Ok(vec![]))).await.unwrap();
            let (started, cancelled) = if start_first {
                tokio::join!(requests.try_start(id), requests.cancel(id))
            } else {
                let (cancelled, started) =
                    tokio::join!(requests.cancel(id), requests.try_start(id));
                (started, cancelled)
            };
            match (started.is_some(), cancelled) {
                (true, Err(WorkerPoolError::JobNotPending(error_id))) => {
                    assert_eq!(error_id, id);
                    assert!(matches!(
                        requests.get(id).await.unwrap().status,
                        JobStatus::Processing
                    ));
                }
                (false, Ok(())) => {
                    assert!(matches!(
                        requests.get(id).await.unwrap().status,
                        JobStatus::Cancelled
                    ));
                }
                _ => panic!("start and cancel did not make an exclusive transition"),
            }
        }
    }

    #[tokio::test]
    async fn test_worker_pool_timeout() {
        let pool = WorkerPool::new(2, 5, 1.0); // 1 second timeout

        // Submit a work item that takes longer than the timeout using closure
        let id = pool
            .submit(move || {
                std::thread::sleep(Duration::from_millis(2000));
                Ok(vec![4, 5, 6])
            })
            .await
            .unwrap();

        // Wait for the timeout
        tokio::time::sleep(Duration::from_secs(2)).await;

        // The job should have been garbage collected
        assert!(pool.poll(id).await.is_none());

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_concurrent_work() {
        let pool = WorkerPool::new(4, 10, 2.0);

        // Submit multiple slow work items using closures and get subscriptions
        let mut receivers = vec![];
        for _ in 0..4 {
            let (_, receiver) = pool
                .submit_and_subscribe(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    Ok(vec![7, 8, 9])
                })
                .await
                .unwrap();
            receivers.push(receiver);
        }

        // All jobs should complete within a reasonable time
        let start = std::time::Instant::now();
        for receiver in receivers {
            JobStatus::wait_for_success(&receiver).await.unwrap();
        }
        let duration = start.elapsed();

        // Should take less than 500ms total (4 jobs * 100ms each, but parallel)
        assert!(duration < Duration::from_millis(500));

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_too_many_jobs() {
        let pool = WorkerPool::new(2, 5, 5.0);

        for _ in 0..5 {
            let _id = pool
                .submit(move || {
                    std::thread::sleep(Duration::from_millis(5000));
                    Ok(vec![1])
                })
                .await
                .unwrap();
        }

        // Allow the 2 workers to pick up the jobs
        tokio::time::sleep(Duration::from_millis(200)).await;

        for _ in 0..2 {
            let _id = pool
                .submit(move || {
                    std::thread::sleep(Duration::from_millis(5000));
                    Ok(vec![2])
                })
                .await
                .unwrap();
        }

        // Should fail to submit the 8th job (capacity is 5 pending)
        let res = pool
            .submit(move || {
                std::thread::sleep(Duration::from_millis(5000));
                Ok(vec![3])
            })
            .await;
        assert!(res.is_err());
        assert!(matches!(res, Err(WorkerPoolError::JobQueueFull)));
    }

    #[tokio::test]
    async fn concurrent_submissions_never_exceed_pending_capacity() {
        const CAPACITY: usize = 5;
        const ATTEMPTS: usize = 32;

        let requests = Arc::new(Requests::new(CAPACITY, Duration::from_secs(5)));
        let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
        let attempts = (0..ATTEMPTS).map(|_| {
            let requests = Arc::clone(&requests);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                requests.new_req(Box::new(|| Ok(vec![]))).await
            })
        });
        let results = futures::future::join_all(attempts).await;
        let accepted = results
            .into_iter()
            .filter(|result| matches!(result, Ok(Ok(_))))
            .count();

        assert_eq!(accepted, CAPACITY);
        assert_eq!(requests.pending_count().await, CAPACITY);
    }

    #[tokio::test]
    async fn expired_queued_work_releases_capacity_and_captured_body() {
        let pool = WorkerPool::new(1, 1, 0.05);
        let (release_first, first_released) = std::sync::mpsc::channel();
        let (_, first_updates) = pool
            .submit_and_subscribe(move || {
                first_released.recv().unwrap();
                Ok(vec![])
            })
            .await
            .unwrap();
        assert!(matches!(
            first_updates.recv().await,
            Ok(JobStatus::Processing)
        ));

        let retained = Arc::new(AtomicBool::new(false));
        let captured = DropProbe(retained.clone());
        pool.submit(move || {
            drop(captured);
            Ok(vec![])
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        pool.requests.gc().await;
        assert_eq!(pool.requests.pending_count().await, 0);
        assert_eq!(pool.requests.queued.load(Ordering::Acquire), 0);
        assert!(retained.load(Ordering::SeqCst));
        pool.submit(|| Ok(vec![])).await.expect("freed queue slot");

        release_first.send(()).unwrap();
        pool.shutdown().await;
        assert!(retained.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelling_queued_work_releases_body_and_capacity_immediately() {
        let pool = WorkerPool::new(1, 1, 5.0);
        let (release_first, first_released) = std::sync::mpsc::channel();
        let (_, first_updates) = pool
            .submit_and_subscribe(move || {
                first_released.recv().unwrap();
                Ok(vec![])
            })
            .await
            .unwrap();
        assert!(matches!(
            first_updates.recv().await,
            Ok(JobStatus::Processing)
        ));

        let released = Arc::new(AtomicBool::new(false));
        let captured = DropProbe(released.clone());
        let (id, updates) = pool
            .submit_and_subscribe(move || {
                drop(captured);
                Ok(vec![])
            })
            .await
            .unwrap();
        pool.cancel(id).await.unwrap();
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(pool.requests.queued.load(Ordering::Acquire), 0);
        assert!(matches!(updates.recv().await, Ok(JobStatus::Cancelled)));
        pool.submit(|| Ok(vec![])).await.expect("freed queue slot");

        release_first.send(()).unwrap();
        pool.shutdown().await;
    }
}
