// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

#![cfg(not(target_family = "wasm"))]

//! Cross-runtime gate for the published ZKIR 3.2.1 k=4 key and official SRS.

use std::fs;

use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::proofs::{ParamsVerifier, Proof, ProofPreimage, VerifierKey};
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

#[test]
#[ignore = "run after the ZKIR 3.2.1 TypeScript/Wasm integration test exports the counter proof"]
fn compact_v3_counter_key_verifies_typescript_wasm_proof() {
    const COUNTER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/midnight-js-counter-increment"
    );
    let proof_path = std::env::var("MIDNIGHT_V3_WASM_COUNTER_PROOF")
        .expect("MIDNIGHT_V3_WASM_COUNTER_PROOF must point to the TypeScript/Wasm proof");
    let proof: Proof = tagged_deserialize(
        fs::read(proof_path)
            .expect("read Compact TypeScript/Wasm proof")
            .as_slice(),
    )
    .expect("decode Compact TypeScript/Wasm proof");
    let vk: VerifierKey = tagged_deserialize(
        fs::read(format!("{COUNTER}/increment.verifier"))
            .expect("read published Compact verifier key")
            .as_slice(),
    )
    .expect("decode published Compact verifier key");
    let params = ParamsVerifier::read(
        fs::read(format!("{COUNTER}/bls_midnight_2p6"))
            .expect("read official k=6 SRS")
            .as_slice(),
    )
    .expect("decode official k=6 verifier parameters");
    let preimage: ProofPreimage = tagged_deserialize(
        include_bytes!("compact-v3-counter/increment.ts-preimage.bin").as_slice(),
    )
    .expect("decode Compact TypeScript preimage");
    let mut public_inputs = vec![preimage.binding_input];
    if let Some((commitment, _)) = preimage.communications_commitment {
        public_inputs.push(commitment);
    }
    public_inputs.extend(preimage.public_transcript_inputs.iter().copied());
    public_inputs.extend(preimage.public_transcript_outputs.iter().copied());
    vk.verify(&params, &proof, public_inputs.iter().copied())
        .expect("native verifier accepts Compact TypeScript/Wasm proof");
    public_inputs[0] = if public_inputs[0] == 43.into() {
        44.into()
    } else {
        43.into()
    };
    assert!(
        vk.verify(&params, &proof, public_inputs.into_iter())
            .is_err()
    );
}
