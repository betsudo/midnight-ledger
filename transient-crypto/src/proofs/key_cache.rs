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

//! Lazy prover-key initialization and bounded caches for legacy and request policies.

use super::{InnerProverKey, ProverKey, ProvingError, Zkir};
use base_crypto::hash::{HashOutput, persistent_hash};
use lazy_static::lazy_static;
use lru::LruCache;
use midnight_proofs::config::{ProverConfig, ProverContext};
use std::any::{Any, TypeId};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

const PK_CACHE_SIZE: usize = 5;
// Explicit-policy keys are kept separately from the legacy bytes-only cache.
// One entry bounds the mapped files held open after a request completes.
const PK_POLICY_CACHE_SIZE: usize = 1;

struct PolicyKeyCacheEntry {
    hash: HashOutput,
    type_id: TypeId,
    policy: ProverConfig,
    key: Arc<dyn Any + Send + Sync>,
}

lazy_static! {
    // forall<T> Arc<MidnightPK<T>>
    static ref PK_CACHE: Mutex<LruCache<HashOutput, Arc<dyn Any + Send + Sync>>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(PK_CACHE_SIZE).unwrap()));
    static ref PK_POLICY_CACHE: Mutex<VecDeque<PolicyKeyCacheEntry>> =
        Mutex::new(VecDeque::with_capacity(PK_POLICY_CACHE_SIZE));
    // Admit one explicit-policy key build at a time. Cache hits do not wait.
    static ref PK_POLICY_BUILD_LOCK: Mutex<()> = Mutex::new(());
}

fn cached_policy_key<T: Zkir>(
    cache: &mut VecDeque<PolicyKeyCacheEntry>,
    hash: &HashOutput,
    policy: &ProverConfig,
) -> Option<Arc<T::ProverKey>> {
    let index = cache.iter().position(|entry| {
        &entry.hash == hash && entry.type_id == TypeId::of::<T>() && entry.policy == *policy
    })?;
    let entry = cache.remove(index).expect("cache index exists");
    let key = entry.key.clone().downcast::<T::ProverKey>().ok();
    cache.push_front(entry);
    key
}

fn check_key_cancelled(
    context: Option<&ProverContext>,
    phase: &'static str,
) -> Result<(), ProvingError> {
    if context.is_some_and(ProverContext::is_cancelled) {
        Err(midnight_proofs::plonk::ProveWithPolicyError::Cancelled { phase }.into())
    } else {
        Ok(())
    }
}

fn lock_with_context<'a, T>(
    gate: &'a Mutex<T>,
    context: Option<&ProverContext>,
    phase: &'static str,
) -> Result<MutexGuard<'a, T>, ProvingError> {
    if context.is_none() {
        // Preserve the blocking lock for policy-only callers. The global
        // gate has no data, and callers inspect the per-key enum after lock.
        return Ok(gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }
    loop {
        check_key_cancelled(context, phase)?;
        match gate.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poison)) => return Ok(poison.into_inner()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

impl<T: Zkir> InnerProverKey<T> {
    fn try_cache(&mut self) {
        let hash = match self {
            InnerProverKey::Uninitialized(data) => persistent_hash(&data[..]),
            _ => return,
        };
        if let Some(pk) = PK_CACHE
            .lock()
            .ok()
            .and_then(|mut c| c.get(&hash).cloned())
            .and_then(|ptr| ptr.downcast().ok())
        {
            *self = InnerProverKey::Initialized(pk);
        }
    }
}

impl<T: Zkir> ProverKey<T> {
    /// Constructs a `ProverKey` from an already-initialized raw inner key.
    pub fn from_raw(raw: T::ProverKey) -> Self {
        ProverKey(Arc::new(Mutex::new(InnerProverKey::Initialized(Arc::new(
            raw,
        )))))
    }

    /// Initializes the lazy prover key
    pub fn init(&self) -> Result<Arc<T::ProverKey>, ProvingError> {
        let mut mutex = self.0.lock().expect("mutex is not poisoned");
        mutex.try_cache();
        let data = match &*mutex {
            InnerProverKey::Initialized(key) => {
                return Ok(key.clone());
            }
            InnerProverKey::Invalid(_) => {
                return Err(anyhow::anyhow!("known invalid verifier key"));
            }
            InnerProverKey::Uninitialized(data) => data.clone(),
        };
        let mut inner_reader = &mut &data[..];
        let read_inner = |inner_reader| {
            let pk = T::read_raw_pk(inner_reader)?;
            Ok(pk)
        };
        let res: Result<_, ProvingError> = read_inner(&mut inner_reader);
        match res {
            Ok(pk) => {
                let key = Arc::new(pk);
                PK_CACHE
                    .lock()
                    .ok()
                    .and_then(|mut c| c.put(persistent_hash(&data), key.clone()));
                *mutex = InnerProverKey::Initialized(key.clone());
                Ok(key)
            }
            Err(e) => {
                *mutex = InnerProverKey::Invalid(data);
                Err(e)
            }
        }
    }

    /// Load a lazy key under the caller's policy without changing this key's
    /// state or using the bytes-only process cache. A subsequent request with
    /// another policy must not inherit this request's storage decisions.
    /// The separate policy cache retains at most one initialized key, including
    /// any mapped files it owns. A process-wide build gate prevents concurrent
    /// misses from constructing multiple keys at once.
    pub fn init_with_policy(
        &self,
        policy: &ProverConfig,
    ) -> Result<Arc<T::ProverKey>, ProvingError> {
        self.init_with_policy_inner(policy, None)
    }

    /// Load a lazy key under this request's memory policy and cancellation token.
    /// Cancellation is checked while waiting for key-build admission or the
    /// per-key lock, and before retaining the completed key. The low-level key
    /// reader cannot yet stop partway through a single read.
    pub fn init_with_context(
        &self,
        context: &ProverContext,
    ) -> Result<Arc<T::ProverKey>, ProvingError> {
        self.init_with_policy_inner(&context.config, Some(context))
    }

    fn init_with_policy_inner(
        &self,
        policy: &ProverConfig,
        context: Option<&ProverContext>,
    ) -> Result<Arc<T::ProverKey>, ProvingError> {
        check_key_cancelled(context, "prover_key.init")?;
        // Snapshot the serialized bytes without copying them. Holding the
        // per-key mutex across the global build-gate wait would make another
        // request for this key uninterruptible while the builder is busy.
        let data = {
            let mutex = lock_with_context(&self.0, context, "prover_key.lock")?;
            match &*mutex {
                InnerProverKey::Uninitialized(data) => data.clone(),
                InnerProverKey::Invalid(_) => {
                    return Err(anyhow::anyhow!("known invalid prover key"));
                }
                InnerProverKey::Initialized(key) => {
                    // No load occurs for an already initialized key. The heap
                    // policy can reuse it, but a mapped request must start
                    // from bytes so its storage choice is actually honored.
                    if *policy != ProverConfig::heap() {
                        return Err(anyhow::anyhow!(
                            "mapped memory policy requires a serialized prover key"
                        ));
                    }
                    check_key_cancelled(context, "prover_key.init")?;
                    return Ok(key.clone());
                }
            }
        };
        let hash = persistent_hash(&data[..]);
        if let Ok(mut cache) = PK_POLICY_CACHE.lock()
            && let Some(key) = cached_policy_key::<T>(&mut cache, &hash, policy)
        {
            check_key_cancelled(context, "prover_key.cache")?;
            return Ok(key);
        }
        let _build = lock_with_context(&PK_POLICY_BUILD_LOCK, context, "prover_key.wait")?;
        check_key_cancelled(context, "prover_key.wait")?;
        // A prior waiter may have populated the cache while this request was
        // waiting at the build gate.
        if let Ok(mut cache) = PK_POLICY_CACHE.lock()
            && let Some(key) = cached_policy_key::<T>(&mut cache, &hash, policy)
        {
            check_key_cancelled(context, "prover_key.cache")?;
            return Ok(key);
        }
        // A legacy initializer can change this key's state while we wait at
        // the global gate. Recheck under the key lock and hold it only for the
        // reader, preserving the old exclusion with legacy `init()`.
        let mutex = lock_with_context(&self.0, context, "prover_key.lock")?;
        match &*mutex {
            InnerProverKey::Uninitialized(_) => {}
            InnerProverKey::Invalid(_) => {
                return Err(anyhow::anyhow!("known invalid prover key"));
            }
            InnerProverKey::Initialized(key) => {
                if *policy != ProverConfig::heap() {
                    return Err(anyhow::anyhow!(
                        "mapped memory policy requires a serialized prover key"
                    ));
                }
                check_key_cancelled(context, "prover_key.init")?;
                return Ok(key.clone());
            }
        }
        let key = Arc::new(T::read_raw_pk_with_policy(&data[..], policy)?);
        drop(mutex);
        check_key_cancelled(context, "prover_key.read")?;
        if let Ok(mut cache) = PK_POLICY_CACHE.lock() {
            cache.retain(|entry| {
                entry.hash != hash || entry.type_id != TypeId::of::<T>() || entry.policy != *policy
            });
            cache.push_front(PolicyKeyCacheEntry {
                hash,
                type_id: TypeId::of::<T>(),
                policy: policy.clone(),
                key: key.clone(),
            });
            cache.truncate(PK_POLICY_CACHE_SIZE);
        }
        Ok(key)
    }

    /// Pre-populate the process-wide `PK_CACHE` so that a subsequent
    /// `tagged_deserialize::<ProverKey<T>>` of bytes produced by
    /// serialising **this** key can share the same `Arc<T::ProverKey>`
    /// when its legacy `init()` is called — no rebuild and no extended-domain
    /// FFT recomputation. Deserialization itself keeps the raw bytes so an
    /// explicit-policy request can select a different storage policy.
    ///
    /// Designed for `Resolver::resolve_key` impls that hold an
    /// initialized `ProverKey` in process memory and feed it into
    /// the bytes-based prover pipeline. The bytes API at the prover
    /// boundary is preserved; the consumer's `init()`/`try_cache` hits the
    /// freshly-inserted entry instead of paying the multi-GiB
    /// rebuild.
    ///
    /// # What is and is not measured
    ///
    /// The rebuild was observed at roughly 1.3 GiB for BLS12-381 at
    /// k=18 during early mobile work. That figure has not been
    /// reproduced on the current implementation and no k=20 figure was
    /// ever taken — the ~5 GiB that used to appear here was
    /// extrapolated from it, not measured.
    ///
    /// This doc previously called the rebuild *the main reason* a k=20
    /// proof dies on mobile. The laptop sweep does not support that:
    /// mapping the prover key is close to neutral on its own, and the
    /// memory that actually moves at k=20 is the coset working set
    /// (14.26 → 6.04 GiB physical footprint, and only with the coset
    /// spill enabled). Skipping the rebuild is worth doing and is not
    /// the dominant term.
    ///
    /// Numbers per `k`, host class and concurrency are being collected
    /// separately; until then, treat the figure above as an
    /// unreproduced observation rather than a benchmark.
    ///
    /// Returns `Ok(true)` if the key was `Initialized` and the
    /// cache was warmed; `Ok(false)` if the key was
    /// `Uninitialized`/`Invalid` (nothing to share).
    pub fn warm_pk_cache(&self) -> std::io::Result<bool> {
        let arc_pk = {
            let mutex = self.0.lock().expect("mutex not poisoned");
            match &*mutex {
                InnerProverKey::Initialized(key) => key.clone(),
                _ => return Ok(false),
            }
        };

        // Compute the exact bytes the consumer-side `try_cache` will
        // hash. Going through `T::write_raw_pk` is what makes that
        // exact rather than hopeful: `inner_serialize` writes an
        // `Initialized` key with the very same call, and the peer's
        // `init()` hashes the bytes retained by `deserialize`. Re-implementing the
        // encoding here — as the ledger-8 version did, gzipping in this
        // crate — would leave two copies that must agree by convention,
        // and a drift between them is silent: every lookup misses and
        // the multi-GiB rebuild happens anyway.
        let mut inner_buf = Vec::new();
        T::write_raw_pk(&mut inner_buf, &arc_pk)?;

        let hash = persistent_hash(&inner_buf);
        if let Ok(mut c) = PK_CACHE.lock() {
            c.put(hash, arc_pk as Arc<dyn Any + Send + Sync>);
        }
        Ok(true)
    }

    pub(super) fn inner_serialize<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        match &*self.0.lock().expect("mutex is not poisoned") {
            InnerProverKey::Uninitialized(data) | InnerProverKey::Invalid(data) => {
                writer.write_all(data)?;
                Ok(())
            }
            InnerProverKey::Initialized(key) => T::write_raw_pk(&mut writer, key),
        }
    }
}

#[cfg(test)]
mod key_build_gate_tests {
    use super::*;
    use midnight_proofs::config::CancelToken;
    use std::sync::mpsc;

    #[test]
    fn queued_request_can_cancel_while_another_builder_holds_admission() {
        let gate = Arc::new(Mutex::new(()));
        let active = gate.lock().expect("hold build admission");
        let token = CancelToken::new();
        let context = ProverContext::new(ProverConfig::heap()).with_cancel(token.clone());
        let (started_tx, started_rx) = mpsc::channel();
        let waiting_gate = gate.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).expect("announce waiter");
            lock_with_context(&waiting_gate, Some(&context), "prover_key.wait").map(|_| ())
        });
        started_rx.recv().expect("waiter started");
        std::thread::sleep(Duration::from_millis(25));
        token.cancel();
        let error = waiter
            .join()
            .expect("waiter thread")
            .expect_err("cancelled waiter must leave the queue");
        assert!(matches!(
            error.downcast_ref::<midnight_proofs::plonk::ProveWithPolicyError>(),
            Some(midnight_proofs::plonk::ProveWithPolicyError::Cancelled {
                phase: "prover_key.wait"
            })
        ));
        assert!(gate.try_lock().is_err(), "active builder still owns gate");
        drop(active);
        assert!(gate.try_lock().is_ok(), "admission remains reusable");
    }

    #[test]
    fn per_key_lock_wait_is_cancellable() {
        let key_mutex = Arc::new(Mutex::new(vec![1u8]));
        let active = key_mutex.lock().expect("hold key lock");
        let token = CancelToken::new();
        let context = ProverContext::new(ProverConfig::heap()).with_cancel(token.clone());
        let (started_tx, started_rx) = mpsc::channel();
        let waiting_mutex = key_mutex.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).expect("announce waiter");
            lock_with_context(&waiting_mutex, Some(&context), "prover_key.lock").map(|_| ())
        });
        started_rx.recv().expect("waiter started");
        std::thread::sleep(Duration::from_millis(25));
        token.cancel();
        let error = waiter
            .join()
            .expect("waiter thread")
            .expect_err("cancelled waiter must leave the key lock queue");
        assert!(matches!(
            error.downcast_ref::<midnight_proofs::plonk::ProveWithPolicyError>(),
            Some(midnight_proofs::plonk::ProveWithPolicyError::Cancelled {
                phase: "prover_key.lock"
            })
        ));
        drop(active);
        assert!(key_mutex.try_lock().is_ok(), "key lock remains reusable");
    }
}
