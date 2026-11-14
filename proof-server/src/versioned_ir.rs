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

use base_crypto::data_provider::UnknownManagedArtifact;
use ledger::error::TransactionProvingError;
use ledger::prove::Resolver;
use ledger::structure::ProofVersioned;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use serialize::{peek_tag, tagged_deserialize};
use std::io::Cursor;
use transient_crypto::proofs::{Proof, ProofPreimage, ProvingError, Zkir};
use zkir as zkir_v2;

use crate::endpoints::PUBLIC_PARAMS;
use crate::worker_pool::WorkError;
use storage::db::DB;
use zswap::prove::ParamsLoadFailure;

fn classify_proving_error(error: ProvingError) -> WorkError {
    fn is_unknown_managed_artifact(cause: &(dyn std::error::Error + 'static)) -> bool {
        if cause.is::<UnknownManagedArtifact>() {
            return true;
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            return io_error
                .get_ref()
                .is_some_and(|inner| is_unknown_managed_artifact(inner));
        }
        if let Some(parameter_error) = cause.downcast_ref::<ParamsLoadFailure>() {
            return is_unknown_managed_artifact(&parameter_error.0);
        }
        false
    }

    if error.chain().any(is_unknown_managed_artifact) {
        return WorkError::BadInput(error.to_string());
    }
    let server_owned_params = error.chain().any(|cause| {
        cause.is::<ParamsLoadFailure>()
            || cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|inner| inner.is::<ParamsLoadFailure>())
    });
    if server_owned_params {
        WorkError::InternalError(error.to_string())
    } else {
        WorkError::BadInput(error.to_string())
    }
}

/// TransactionProvingError does not expose its Proving variant as an Error
/// source, so inspect the variant before the parameter provenance is erased.
pub(crate) fn classify_transaction_proving_error<D: DB>(
    error: TransactionProvingError<D>,
) -> WorkError {
    match error {
        TransactionProvingError::Proving(error) => classify_proving_error(error),
        TransactionProvingError::Tokio(error) => classify_proving_error(error.into()),
        other => WorkError::BadInput(other.to_string()),
    }
}

/// Ledger's proof wire version follows the verifier-key format, not the IR tag.
pub(crate) fn proof_envelope_for_vk(
    verifier_key: &[u8],
) -> Result<fn(Proof) -> ProofVersioned, WorkError> {
    let tag =
        peek_tag(&mut Cursor::new(verifier_key)).map_err(|e| WorkError::BadInput(e.to_string()))?;
    match tag.as_str() {
        "verifier-key[v6]" => Ok(ProofVersioned::V2),
        "verifier-key[v7]" => Ok(ProofVersioned::V3),
        _ => Err(WorkError::BadInput(format!(
            "Unsupported verifier key tag: '{tag}'"
        ))),
    }
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
        "ir-source[v3-generic]" => {
            //let ir_source = tagged_deserialize::<zkir_v3::IrSource>(ir_source).map_err(|e| e.to_string())?;
            ppi.prove::<zkir_v3::IrSource>(OsRng, &*PUBLIC_PARAMS, resolver)
                .await
                .map_err(classify_proving_error)
        }
        _ => Err(WorkError::BadInput(format!(
            "Unsupported ZKIR tag: '{tag}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage::db::InMemoryDB;

    #[test]
    fn released_v2_and_v3_keys_use_the_current_proof_envelope() {
        for key in [
            include_bytes!("../tests/release-v2-9.1.0.1/verifier-key.bin").as_slice(),
            include_bytes!("../tests/release-v3-9.1.0.1/verifier-key.bin").as_slice(),
        ] {
            let wrap = proof_envelope_for_vk(key).expect("released verifier key version");
            assert!(matches!(wrap(Proof(Vec::new())), ProofVersioned::V3(_)));
        }
        let legacy = include_bytes!("../../zswap/static/sign.verifier");
        let wrap = proof_envelope_for_vk(legacy).expect("legacy verifier key version");
        assert!(matches!(wrap(Proof(Vec::new())), ProofVersioned::V2(_)));
        assert!(matches!(
            proof_envelope_for_vk(&[]),
            Err(WorkError::BadInput(_))
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
    }

    #[tokio::test]
    async fn unsupported_managed_parameter_is_client_input() {
        use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

        let provider = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
            .expect("provider configuration");
        let error = provider
            .get_file(&MidnightDataProvider::name_k(26), "unsupported parameters")
            .await
            .expect_err("k=26 is not a managed SRS");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let marked = std::io::Error::new(error.kind(), ParamsLoadFailure(error));
        assert!(matches!(
            classify_proving_error(marked.into()),
            WorkError::BadInput(_)
        ));

        let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "known SRS missing");
        let marked = std::io::Error::new(missing.kind(), ParamsLoadFailure(missing));
        assert!(matches!(
            classify_proving_error(marked.into()),
            WorkError::InternalError(_)
        ));
    }

    #[test]
    fn transaction_proving_retains_parameter_error_provenance() {
        let marked = || {
            let source = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt companion");
            std::io::Error::new(source.kind(), ParamsLoadFailure(source))
        };
        assert!(matches!(
            classify_transaction_proving_error::<InMemoryDB>(TransactionProvingError::Proving(
                marked().into()
            )),
            WorkError::InternalError(_)
        ));
        assert!(matches!(
            classify_transaction_proving_error::<InMemoryDB>(TransactionProvingError::Tokio(
                marked()
            )),
            WorkError::InternalError(_)
        ));
        assert!(matches!(
            classify_transaction_proving_error::<InMemoryDB>(
                TransactionProvingError::MissingKeyset(transient_crypto::proofs::KeyLocation(
                    "missing".into()
                ))
            ),
            WorkError::BadInput(_)
        ));
    }
}
