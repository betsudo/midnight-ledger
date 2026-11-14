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
use midnight_proofs::config::ProverContext;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use serialize::{peek_tag, tagged_deserialize};
use std::io::Cursor;
use transient_crypto::proofs::{Proof, ProofPreimage, ProvingError, Zkir};
use zkir as zkir_v2;

use crate::endpoints::PUBLIC_PARAMS;
use crate::worker_pool::WorkError;
use zswap::prove::ParamsLoadFailure;

fn classify_proving_error(error: ProvingError) -> WorkError {
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<midnight_proofs::plonk::Error>(),
            Some(midnight_proofs::plonk::Error::Cancelled { .. })
        )
    }) {
        return WorkError::CancelledUnexpectedly;
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
    context: &ProverContext,
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
        "ir-source[v3-generic]" => ppi
            .prove_with_context::<zkir_v3::IrSource>(OsRng, &*PUBLIC_PARAMS, resolver, context)
            .await
            .map_err(classify_proving_error),
        _ => Err(WorkError::BadInput(format!(
            "Unsupported ZKIR tag: '{tag}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(
            classify_proving_error(
                midnight_proofs::plonk::Error::Cancelled {
                    phase: "trace.start"
                }
                .into()
            ),
            WorkError::CancelledUnexpectedly
        ));
    }
}
