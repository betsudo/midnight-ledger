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

//! Decode-only checks over the static test artifacts
//! (`MIDNIGHT_LEDGER_TEST_STATIC_DIR`).
//!
//! Proving tests only run under `--features proving`, which CI's PR gate does
//! not enable - so a zkir format change that breaks decoding of the compiled
//! artifacts is otherwise invisible until a full-proving (nightly) run. This
//! test decodes IR without paying for a proof. Set
//! `MIDNIGHT_REQUIRE_ZKIR_KEYS=1` to also initialize prover and verifier keys
//! from a fixture bundle that must contain both key types.

#![deny(warnings)]

use serialize::{peek_tag, tagged_deserialize};
use std::path::Path;
use std::{env, fs};

fn check_bzkir(path: &Path) {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let tag = peek_tag(&mut std::io::Cursor::new(&bytes))
        .unwrap_or_else(|e| panic!("peek tag of {path:?}: {e}"));
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            zkir_v2::IrSource::load_from_tagged(std::io::Cursor::new(&bytes))
                .unwrap_or_else(|e| panic!("decode v2 bzkir {path:?}: {e}"));
        }
        "ir-source[v3-generic]" => {
            let _: zkir_v3::IrSource = tagged_deserialize(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("decode v3 bzkir {path:?}: {e}"));
        }
        other => panic!("unknown zkir tag '{other}' in {path:?}"),
    }
}

fn check_zkir_json(path: &Path) {
    let contents = fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let doc: serde_json::Value =
        serde_json::from_slice(&contents).unwrap_or_else(|e| panic!("parse JSON {path:?}: {e}"));
    let major = doc["version"]["major"].as_u64();
    match major {
        Some(2) => {
            zkir_v2::IrSource::load(&contents[..])
                .unwrap_or_else(|e| panic!("load v2 zkir {path:?}: {e}"));
        }
        Some(3) => {
            zkir_v3::IrSource::load(&contents[..])
                .unwrap_or_else(|e| panic!("load v3 zkir {path:?}: {e}"));
        }
        v => panic!("unsupported zkir major version {v:?} in {path:?}"),
    }
}

fn check_prover_key(path: &Path) {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let tag = peek_tag(&mut std::io::Cursor::new(&bytes))
        .unwrap_or_else(|e| panic!("peek tag of {path:?}: {e}"));
    match tag.as_str() {
        "prover-key[v7](ir-source[v2])" => {
            let key = <zkir_v2::IrSource as transient_crypto_old::proofs::Zkir>::load_prover_key_from_tagged(
                std::io::Cursor::new(&bytes),
            )
            .unwrap_or_else(|e| panic!("decode legacy v2 prover key {path:?}: {e}"));
            key.init()
                .unwrap_or_else(|e| panic!("initialize legacy v2 prover key {path:?}: {e}"));
        }
        "prover-key[v7](ir-source[v2-generic])" => {
            let key =
                <zkir_v2::IrSource as transient_crypto::proofs::Zkir>::load_prover_key_from_tagged(
                    std::io::Cursor::new(&bytes),
                )
                .unwrap_or_else(|e| panic!("decode v2 prover key {path:?}: {e}"));
            key.init()
                .unwrap_or_else(|e| panic!("initialize v2 prover key {path:?}: {e}"));
        }
        "prover-key[v7](ir-source[v3-generic])" => {
            let key =
                <zkir_v3::IrSource as transient_crypto::proofs::Zkir>::load_prover_key_from_tagged(
                    std::io::Cursor::new(&bytes),
                )
                .unwrap_or_else(|e| panic!("decode v3 prover key {path:?}: {e}"));
            key.init()
                .unwrap_or_else(|e| panic!("initialize v3 prover key {path:?}: {e}"));
        }
        other => panic!("unknown prover-key tag '{other}' in {path:?}"),
    }
}

fn check_verifier_key(path: &Path) {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let tag = peek_tag(&mut std::io::Cursor::new(&bytes))
        .unwrap_or_else(|e| panic!("peek tag of {path:?}: {e}"));
    match tag.as_str() {
        "verifier-key[v6]" => {
            let key: transient_crypto_old::proofs::VerifierKey =
                tagged_deserialize(&mut &bytes[..])
                    .unwrap_or_else(|e| panic!("decode v2 verifier key {path:?}: {e}"));
            key.init()
                .unwrap_or_else(|e| panic!("initialize v2 verifier key {path:?}: {e}"));
        }
        "verifier-key[v7]" => {
            let key: transient_crypto::proofs::VerifierKey = tagged_deserialize(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("decode v3 verifier key {path:?}: {e}"));
            key.init()
                .unwrap_or_else(|e| panic!("initialize v3 verifier key {path:?}: {e}"));
        }
        other => panic!("unknown verifier-key tag '{other}' in {path:?}"),
    }
}

#[test]
fn static_zkir_artifacts_decode() {
    let test_dir = env::var("MIDNIGHT_LEDGER_TEST_STATIC_DIR")
        .expect("MIDNIGHT_LEDGER_TEST_STATIC_DIR should be set as env variable");
    let require_keys = env::var("MIDNIGHT_REQUIRE_ZKIR_KEYS").as_deref() == Ok("1");
    let mut checked = 0;
    let mut prover_keys = 0;
    let mut verifier_keys = 0;

    for contract in fs::read_dir(&test_dir).expect("read static dir") {
        let contract_dir = contract.expect("dir entry").path();
        let keys_dir = contract_dir.join("keys");
        if require_keys && keys_dir.is_dir() {
            for entry in fs::read_dir(&keys_dir).expect("read keys dir") {
                let path = entry.expect("dir entry").path();
                match path.extension().and_then(|e| e.to_str()) {
                    Some("prover") => {
                        check_prover_key(&path);
                        prover_keys += 1;
                    }
                    Some("verifier") => {
                        check_verifier_key(&path);
                        verifier_keys += 1;
                    }
                    _ => {}
                }
            }
        }
        let zkir_dir = contract_dir.join("zkir");
        if !zkir_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&zkir_dir).expect("read zkir dir") {
            let path = entry.expect("dir entry").path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("bzkir") => {
                    check_bzkir(&path);
                    checked += 1;
                }
                Some("zkir") => {
                    check_zkir_json(&path);
                    checked += 1;
                }
                _ => {}
            }
        }
    }
    assert!(
        checked > 0,
        "no zkir artifacts found under {test_dir:?} - static dir misconfigured?"
    );
    if require_keys {
        assert!(
            prover_keys > 0 && verifier_keys > 0,
            "no complete prover/verifier fixture pair found under {test_dir:?}"
        );
    }
}
