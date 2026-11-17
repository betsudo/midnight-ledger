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
use clap::{Parser, ValueEnum};

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use futures::future::join;
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use midnight_proof_server::endpoints::PUBLIC_PARAMS;
use midnight_proof_server::{
    IngressConfig, ServerConfig, server_with_config, worker_pool::WorkerPool,
};
use midnight_proofs::config::{DEFAULT_COSET_SPILL_FLOOR_K, ProverConfig};
use tracing::{Level, info};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};
#[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
use transient_crypto::proofs::TrustedParamsDir;
use transient_crypto::proofs::{KeyLocation, Resolver as ResolverT};
#[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
use zswap::prove::ZswapResolver;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum V3MemoryPolicy {
    Heap,
    MappedKey,
    MappedKeyAndCosets,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = 6300,
        env = "MIDNIGHT_PROOF_SERVER_PORT"
    )]
    port: u16,
    #[arg(short, long, env = "MIDNIGHT_PROOF_SERVER_VERBOSE")]
    verbose: bool,
    #[arg(long, default_value_t = 10, env = "MIDNIGHT_PROOF_SERVER_JOB_CAPACITY")]
    job_capacity: usize,
    #[arg(long, default_value_t = 2, env = "MIDNIGHT_PROOF_SERVER_NUM_WORKERS")]
    num_workers: usize,
    #[arg(
        long,
        default_value_t = 600.0,
        env = "MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT"
    )]
    job_timeout: f64,
    /// Maximum buffered bytes in one request body. Must accommodate the largest key bundle.
    #[arg(long, default_value_t = 512 * 1024 * 1024, env = "MIDNIGHT_PROOF_SERVER_MAX_BODY_BYTES")]
    max_body_bytes: usize,
    /// Maximum requests reading or decoding bodies concurrently.
    #[arg(long, default_value_t = 2, env = "MIDNIGHT_PROOF_SERVER_MAX_INGRESS")]
    max_ingress: usize,
    #[arg(
        long,
        default_value_t = 120,
        env = "MIDNIGHT_PROOF_SERVER_BODY_READ_TIMEOUT_SECS"
    )]
    body_read_timeout_secs: u64,
    /// Abort HTTP/1 handlers on a client write-side close. Clients that
    /// intentionally half-close after sending a request must leave this off.
    #[arg(
        long,
        default_value_t = false,
        env = "MIDNIGHT_PROOF_SERVER_ABORT_HALF_CLOSED_CLIENTS"
    )]
    abort_half_closed_clients: bool,
    #[arg(
        long,
        default_value_t = false,
        env = "MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS"
    )]
    no_fetch_params: bool,
    /// Private, immutable mmap companion directory. Published files must not
    /// be changed by another process while this server is running.
    #[arg(long, env = "MIDNIGHT_PROOF_SERVER_TRUSTED_MMAP_DIR")]
    trusted_mmap_dir: Option<std::path::PathBuf>,
    /// V3 proving-key and coset storage. V2 keeps its compatibility path.
    #[arg(
        long,
        value_enum,
        default_value = "heap",
        env = "MIDNIGHT_PROOF_SERVER_V3_MEMORY_POLICY"
    )]
    v3_memory_policy: V3MemoryPolicy,
    /// Temporary volume for V3 mapped-key and coset storage.
    #[arg(long, env = "MIDNIGHT_PROOF_SERVER_V3_SPILL_DIR")]
    v3_spill_dir: Option<std::path::PathBuf>,
    /// Minimum V3 circuit k at which the selected coset policy spills.
    #[arg(long, default_value_t = DEFAULT_COSET_SPILL_FLOOR_K, env = "MIDNIGHT_PROOF_SERVER_V3_COSET_SPILL_FLOOR_K")]
    v3_coset_spill_floor_k: u32,
}

impl Args {
    fn v3_policy(&self) -> std::io::Result<Option<ProverConfig>> {
        let mut policy = match self.v3_memory_policy {
            V3MemoryPolicy::Heap => {
                if self.v3_spill_dir.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "V3 spill directory requires a mapped V3 memory policy",
                    ));
                }
                return Ok(None);
            }
            V3MemoryPolicy::MappedKey => ProverConfig::mapped_key(),
            V3MemoryPolicy::MappedKeyAndCosets => ProverConfig::mapped_key_and_cosets(),
        };
        if !cfg!(all(feature = "native-memory", not(target_family = "wasm"))) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "mapped V3 proving requires native-memory on a native target",
            ));
        }
        policy.spill_dir = self.v3_spill_dir.clone();
        policy.coset_spill_floor_k = self.v3_coset_spill_floor_k;
        policy.ensure_supported()?;
        Ok(Some(policy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_keeps_the_compatibility_route() {
        let args = Args::try_parse_from(["proof-server"]).expect("default CLI");
        assert!(args.v3_policy().expect("default policy").is_none());
    }

    #[test]
    fn mapped_policy_requires_native_support() {
        let args = Args::try_parse_from([
            "proof-server",
            "--v3-memory-policy",
            "mapped-key-and-cosets",
            "--v3-coset-spill-floor-k",
            "20",
        ])
        .expect("mapped CLI");
        let result = args.v3_policy();
        if cfg!(all(feature = "native-memory", not(target_family = "wasm"))) {
            let policy = result
                .expect("supported native policy")
                .expect("explicit policy");
            assert!(policy.map_prover_key);
            assert!(policy.spill_cosets);
            assert_eq!(policy.coset_spill_floor_k, 20);
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
        }
    }

    #[test]
    fn spill_directory_needs_an_explicit_policy() {
        let args =
            Args::try_parse_from(["proof-server", "--v3-spill-dir", "/tmp"]).expect("spill CLI");
        assert_eq!(
            args.v3_policy().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    init_logging(args.verbose);
    let v3_policy = args.v3_policy()?;
    #[cfg(not(all(feature = "native-memory", not(target_family = "wasm"))))]
    if args.trusted_mmap_dir.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "trusted mmap parameters require native-memory on a native target",
        ));
    }
    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    if let Some(dir) = args.trusted_mmap_dir.as_deref() {
        let canonical = std::fs::canonicalize(dir)?;
        let metadata = std::fs::metadata(&canonical)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "trusted mmap path must be a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "trusted mmap directory must be private (mode 0700)",
                ));
            }
        }
        // SAFETY: this is an explicit operator-selected private directory.
        // The server publishes companions only through CompanionCache, which
        // never rewrites a published inode. The operator must keep other
        // processes from modifying files here while mappings are alive.
        let trusted = unsafe { TrustedParamsDir::new(canonical) };
        ZswapResolver::configure_mapped_params_dir(trusted).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "trusted mmap directory was already configured",
            )
        })?;
    }
    if !args.no_fetch_params {
        info!("Ensuring zswap key material is available...");
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
        let ks = futures::future::join_all((10..=15).map(|k| PUBLIC_PARAMS.0.fetch_k(k)));
        let keys = futures::future::join_all(
            [
                "midnight/zswap/spend",
                "midnight/zswap/output",
                "midnight/zswap/sign",
                "midnight/dust/spend",
            ]
            .into_iter()
            .map(|k| resolver.resolve_key(KeyLocation(k.into()))),
        );
        let (ks, keys) = join(ks, keys).await;
        ks.into_iter().collect::<Result<Vec<_>, _>>()?;
        keys.into_iter().collect::<Result<Vec<_>, _>>()?;
    }
    let pool = WorkerPool::new(args.num_workers, args.job_capacity, args.job_timeout);
    let ingress = IngressConfig {
        max_body_bytes: args.max_body_bytes,
        max_inflight: args.max_ingress,
        read_timeout: std::time::Duration::from_secs(args.body_read_timeout_secs),
    };
    server_with_config(
        args.port,
        !args.no_fetch_params,
        pool,
        ServerConfig {
            ingress,
            v3_policy,
            allow_half_closed_clients: !args.abort_half_closed_clients,
        },
    )?
    .0
    .await
}

fn init_logging(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    Registry::default()
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                Targets::new()
                    .with_default(level)
                    .with_target("zkir", tracing_subscriber::filter::LevelFilter::OFF),
            ),
        )
        .try_init()
        .ok();
}
