// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

#![cfg(not(target_family = "wasm"))]

//! Cross-runtime gate for the published ZKIR 3.2.1 k=4 key and official SRS.

use std::fs;

use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::proofs::{ParamsVerifier, Proof, VerifierKey};
use zkir_v3::IrSource;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal"
);

#[test]
#[ignore = "run after the ZKIR 3.2.1 TypeScript/Wasm integration test exports IR and proof"]
fn released_v3_key_verifies_typescript_wasm_proof() {
    let ir_path = std::env::var("MIDNIGHT_V3_WASM_IR")
        .expect("MIDNIGHT_V3_WASM_IR must point to TypeScript/Wasm IR bytes");
    let proof_path = std::env::var("MIDNIGHT_V3_WASM_PROOF")
        .expect("MIDNIGHT_V3_WASM_PROOF must point to TypeScript/Wasm proof bytes");
    let ir = IrSource::load(
        fs::read(format!("{FIXTURE}/zkir/minimal.zkir"))
            .expect("read published-source JSON IR")
            .as_slice(),
    )
    .expect("load published-source IR");
    let mut native_ir = Vec::new();
    tagged_serialize(&ir, &mut native_ir).expect("encode native V3 IR");
    assert_eq!(
        fs::read(ir_path).expect("read TypeScript/Wasm IR"),
        native_ir
    );

    let proof: Proof = tagged_deserialize(
        fs::read(proof_path)
            .expect("read TypeScript/Wasm proof")
            .as_slice(),
    )
    .expect("decode TypeScript/Wasm proof");
    let vk: VerifierKey = tagged_deserialize(
        fs::read(format!("{FIXTURE}/keys/minimal.verifier"))
            .expect("read published-source verifier key")
            .as_slice(),
    )
    .expect("decode published-source verifier key");
    let params = ParamsVerifier::read(
        fs::read(format!("{FIXTURE}/params.bin"))
            .expect("read official k=4 SRS")
            .as_slice(),
    )
    .expect("decode official k=4 verifier parameters");
    vk.verify(&params, &proof, [42.into()].into_iter())
        .expect("native verifier accepts TypeScript/Wasm proof");
    assert!(vk.verify(&params, &proof, [43.into()].into_iter()).is_err());
}
