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

use std::sync::Arc;

use ledger::prove::Resolver;
use midnight_proofs::config::{ProverConfig, ProverContext};
use midnight_proofs::plonk::{MappedKeyStorageFailure, ProveWithPolicyError};
use rand::rngs::OsRng;
#[allow(unused_imports)]
use serialize::{peek_tag, tagged_deserialize};
use std::io::Cursor;
use transient_crypto::proofs::{
    ParamsProverProvider, Proof, ProofPreimage, ProvingError, Resolver as ResolverT, Zkir,
};
use zkir as zkir_v2;

use crate::endpoints::PUBLIC_PARAMS;
use crate::worker_pool::WorkError;
use zswap::prove::ParamsLoadFailure;

fn classify_proving_error(error: ProvingError) -> WorkError {
    let server_owned_storage = error.chain().any(|cause| {
        cause.is::<ParamsLoadFailure>()
            || cause.is::<MappedKeyStorageFailure>()
            || matches!(
                cause.downcast_ref::<ProveWithPolicyError>(),
                Some(ProveWithPolicyError::Storage(_))
            )
            || cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|inner| {
                    inner.is::<ParamsLoadFailure>() || inner.is::<MappedKeyStorageFailure>()
                })
    });
    if server_owned_storage {
        tracing::error!(error = ?error, "server-owned proving storage failed");
        WorkError::InternalError("server-owned proving storage failed".to_owned())
    } else {
        WorkError::BadInput(error.to_string())
    }
}

async fn prove_v3(
    ppi: &ProofPreimage,
    params: &impl ParamsProverProvider,
    resolver: &impl ResolverT,
    v3_policy: Option<&ProverConfig>,
) -> Result<(Proof, Vec<Option<usize>>), WorkError> {
    // Keep the compatibility route for the default server. An
    // operator-selected V3 policy belongs to this request's context.
    match v3_policy {
        Some(policy) => {
            let context = ProverContext::new(policy.clone());
            ppi.prove_with_context::<zkir_v3::IrSource>(OsRng, params, resolver, &context)
                .await
        }
        None => {
            ppi.prove::<zkir_v3::IrSource>(OsRng, params, resolver)
                .await
        }
    }
    .map_err(classify_proving_error)
}

pub(crate) fn k(request: &[u8]) -> Result<u8, String> {
    let tag = peek_tag(&mut std::io::Cursor::new(request)).map_err(|e| e.to_string())?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir_v2 = zkir_v2::IrSource::load_from_tagged(Cursor::new(request))
                .map_err(|e| e.to_string())?;
            Ok(ir_v2.k())
        }
        "ir-source[v3-generic]" => {
            let ir_v3 =
                tagged_deserialize::<zkir_v3::IrSource>(request).map_err(|e| e.to_string())?;
            Ok(ir_v3.k())
        }
        _ => Err(format!("Unsupported ZKIR tag: '{tag}'")),
    }
}

pub(crate) fn check(ppi: Arc<ProofPreimage>, ir: &[u8]) -> Result<Vec<Option<usize>>, String> {
    let tag = peek_tag(&mut std::io::Cursor::new(ir)).map_err(|e| e.to_string())?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir_v2 =
                zkir_v2::IrSource::load_from_tagged(Cursor::new(ir)).map_err(|e| e.to_string())?;
            ppi.check(&ir_v2).map_err(|e| e.to_string())
        }
        "ir-source[v3-generic]" => {
            let ir_v3 = tagged_deserialize::<zkir_v3::IrSource>(ir).map_err(|e| e.to_string())?;
            ppi.check(&ir_v3).map_err(|e| e.to_string())
        }
        _ => Err(format!("Unsupported ZKIR tag: '{tag}'")),
    }
}

pub(crate) async fn prove(
    ppi: Arc<ProofPreimage>,
    ir_source: &[u8],
    resolver: &Resolver,
    v3_policy: Option<&ProverConfig>,
) -> Result<(Proof, Vec<Option<usize>>), WorkError> {
    let tag = peek_tag(&mut std::io::Cursor::new(ir_source))
        .map_err(|e| WorkError::BadInput(e.to_string()))?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir = zkir_v2::IrSource::load_from_tagged(Cursor::new(ir_source))
                .map_err(|e| WorkError::BadInput(e.to_string()))?;
            // Use LocalProvingProvider for v2 IRs to handle V0/V1 backward compat routing.
            use base_crypto::rng::SplittableRng;
            use transient_crypto::proofs::ProvingProvider;

            let mut provider = zkir_v2::LocalProvingProvider {
                rng: OsRng.split(),
                resolver,
                params: &*PUBLIC_PARAMS,
            };
            let proof = provider
                .split()
                .prove(&ppi, None)
                .await
                .map_err(classify_proving_error)?;
            let skips = ppi
                .check(&ir)
                .map_err(|e| WorkError::BadInput(e.to_string()))?;
            Ok((proof, skips))
        }
        "ir-source[v3-generic]" => prove_v3(&ppi, &*PUBLIC_PARAMS, resolver, v3_policy).await,
        _ => Err(WorkError::BadInput(format!(
            "Unsupported ZKIR tag: '{tag}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    #[actix_web::test]
    async fn explicit_v3_policy_reaches_mapped_key_storage() {
        use serialize::tagged_serialize;
        use transient_crypto::proofs::{KeyLocation, ParamsProver, ProvingKeyMaterial};

        struct FixtureParams(ParamsProver);
        impl ParamsProverProvider for FixtureParams {
            async fn get_params(&self, _k: u8) -> std::io::Result<ParamsProver> {
                Ok(self.0.clone())
            }
        }

        struct FixtureResolver(ProvingKeyMaterial);
        impl ResolverT for FixtureResolver {
            async fn resolve_key(
                &self,
                _key: KeyLocation,
            ) -> std::io::Result<Option<ProvingKeyMaterial>> {
                Ok(Some(self.0.clone()))
            }
        }

        let preimage: ProofPreimage = tagged_deserialize(
            &mut &include_bytes!(concat!(
                "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
                "preimage.bin"
            ))[..],
        )
        .expect("decode release-source V3 preimage");
        let params = FixtureParams(
            ParamsProver::read(
                &include_bytes!(concat!(
                    "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
                    "params.bin"
                ))[..],
            )
            .expect("read release-source parameters"),
        );
        let ir = zkir_v3::IrSource::load(
            &include_bytes!(concat!(
                "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
                "zkir/minimal.zkir"
            ))[..],
        )
        .expect("load released V3 source");
        let mut ir_source = Vec::new();
        tagged_serialize(&ir, &mut ir_source).expect("encode V3 source for resolver");
        let resolver = FixtureResolver(ProvingKeyMaterial {
            prover_key: include_bytes!(concat!(
                "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
                "keys/minimal.prover"
            ))
            .to_vec(),
            verifier_key: include_bytes!(concat!(
                "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
                "keys/minimal.verifier"
            ))
            .to_vec(),
            ir_source,
        });
        prove_v3(&preimage, &params, &resolver, None)
            .await
            .expect("default V3 proof uses released heap path");

        let root = tempfile::tempdir().expect("private test directory");
        let mut mapped = ProverConfig::mapped_key_and_cosets();
        mapped.coset_spill_floor_k = 0;
        mapped.spill_dir = Some(root.path().join("missing"));
        assert!(matches!(
            prove_v3(&preimage, &params, &resolver, Some(&mapped))
                .await
                .expect_err("mapped policy must reach unavailable storage"),
            WorkError::InternalError(_)
        ));

        let mut malformed = resolver.0.clone();
        malformed.prover_key.truncate(1);
        assert!(matches!(
            prove_v3(
                &preimage,
                &params,
                &FixtureResolver(malformed),
                Some(&mapped)
            )
            .await
            .expect_err("malformed supplied key must fail"),
            WorkError::BadInput(_)
        ));
    }

    #[test]
    fn parameter_io_failure_survives_proving_error_erasure() {
        let source = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt companion");
        let marked = std::io::Error::new(source.kind(), ParamsLoadFailure(source));
        assert!(matches!(
            classify_proving_error(marked.into()),
            WorkError::InternalError(_)
        ));
        assert!(matches!(
            classify_proving_error(ProvingError::msg("invalid witness")),
            WorkError::BadInput(_)
        ));
        assert_eq!(
            classify_proving_error(
                ProveWithPolicyError::Storage(std::io::Error::other("private volume path")).into()
            ),
            WorkError::InternalError("server-owned proving storage failed".to_owned())
        );
    }
}
