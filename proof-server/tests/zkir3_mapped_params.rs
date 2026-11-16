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

#![cfg(not(target_family = "wasm"))]

//! The released ZKIR v3 crate and Ledger9 must use the same mapped-parameter
//! and proof implementation as the in-tree provider. This small circuit tests
//! the actual crate boundary without a large proof or external parameter file.

use std::borrow::Cow;
use std::fs;
use std::io::{self, Cursor};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "native-memory")]
use base_crypto::data_provider::MidnightDataProvider;
use midnight_curves::Bls12;
use midnight_proofs::config::{ProverConfig, ProverContext};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::{Serializable, Tagged, tagged_deserialize, tagged_serialize};
use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_commit;
#[cfg(feature = "native-memory")]
use transient_crypto::proofs::{CompanionCache, MappedParams, TrustedParamsDir};
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, Proof, ProofPreimage,
    ProverKey, ProvingKeyMaterial, Resolver, VerifierKey, Zkir,
};
use zkir_v3::IrSource;

struct HeapParams(ParamsProver);

impl ParamsProverProvider for HeapParams {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

#[cfg(feature = "native-memory")]
struct NoFallback;

#[cfg(feature = "native-memory")]
impl ParamsProverProvider for NoFallback {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        panic!("mapped companion was not selected")
    }
}

struct KeyResolver {
    pk: ProverKey<IrSource>,
    vk: VerifierKey,
    ir: IrSource,
}

fn write_tagged_fixture<T: Serializable + Tagged>(dir: &Path, name: &str, value: &T) {
    let mut bytes = Vec::new();
    tagged_serialize(value, &mut bytes).expect("serialize interop fixture");
    fs::write(dir.join(name), bytes).expect("write interop fixture");
}

fn compact_ts_preimage_bytes() -> Vec<u8> {
    match std::env::var("MIDNIGHT_COMPACT_TS_PREIMAGE") {
        Ok(path) => fs::read(path).expect("read TypeScript-generated preimage"),
        Err(std::env::VarError::NotPresent) => {
            include_bytes!("compact-v3-counter/increment.ts-preimage.bin").to_vec()
        }
        Err(error) => panic!("invalid MIDNIGHT_COMPACT_TS_PREIMAGE: {error}"),
    }
}

impl Resolver for KeyResolver {
    async fn resolve_key(&self, _key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        let mut prover_key = Vec::new();
        let mut verifier_key = Vec::new();
        let mut ir_source = Vec::new();
        tagged_serialize(&self.pk, &mut prover_key)?;
        tagged_serialize(&self.vk, &mut verifier_key)?;
        tagged_serialize(&self.ir, &mut ir_source)?;
        Ok(Some(ProvingKeyMaterial {
            prover_key,
            verifier_key,
            ir_source,
        }))
    }
}

#[actix_web::test]
async fn zkir3_heap_and_mapped_params_produce_the_same_valid_proof() {
    let ir = IrSource::load(
        &br#"{
            "version": { "major": 3, "minor": 0 },
            "inputs": [{ "name": "%v_0", "type": "Scalar<BLS12-381>" }],
            "outputs": [],
            "do_communications_commitment": false,
            "instructions": [{ "op": "assert", "cond": "%v_0" }]
        }"#[..],
    )
    .expect("load v3 IR");
    exercise_heap_and_mapped(ir, vec![1.into()], None, vec![], false).await;
}

#[actix_web::test]
async fn compact_generated_zkir3_counter_uses_the_same_prover_paths() {
    // Compact 0.36.1 (7fa3a117c) emitted this ZKIR 3.1 circuit from the
    // adjacent counter.compact source with --skip-zk. It exercises an actual
    // Ledger9 impact and communications-commitment path.
    let ir = IrSource::load(include_str!("compact-v3-counter/increment.zkir").as_bytes())
        .expect("load Compact-generated v3 IR");
    let opening: Fr = 7.into();
    let commitment = transient_commit(&[] as &[Fr], opening);
    let public_transcript_inputs = [0x70, 0x01, 0x01, 0x00, 0x0e, 0x01, 0xa1]
        .into_iter()
        .map(Fr::from)
        .collect();
    exercise_heap_and_mapped(
        ir,
        vec![],
        Some((commitment, opening)),
        public_transcript_inputs,
        false,
    )
    .await;
}

// Build midnight-zkir-wasm for the nodejs target from the matching Ledger9
// integration graph, then point this opt-in test at its wasm-pack output.
#[actix_web::test]
#[ignore = "build midnight-zkir-wasm with wasm-pack and set MIDNIGHT_ZKIR_WASM_PACKAGE"]
async fn wasm_compact_v3_proof_verifies_with_native_ledger9() {
    let package = std::env::var("MIDNIGHT_ZKIR_WASM_PACKAGE")
        .expect("set MIDNIGHT_ZKIR_WASM_PACKAGE to the wasm-pack nodejs output directory");
    let ir = IrSource::load(include_str!("compact-v3-counter/increment.zkir").as_bytes())
        .expect("load Compact-generated v3 IR");
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params
        .0
        .write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize prover parameters");
    let verifier_params =
        ParamsVerifier::read(&params_bytes[..]).expect("read verifier parameters");
    let (pk, vk) = ir.keygen(&HeapParams(params)).await.expect("v3 keygen");
    let preimage_bytes = compact_ts_preimage_bytes();
    let preimage: ProofPreimage =
        tagged_deserialize(&mut &preimage_bytes[..]).expect("decode TypeScript-generated preimage");
    preimage.check(&ir).expect("preimage matches Compact V3 IR");
    let fixture = tempfile::tempdir().expect("private interop fixture directory");
    fs::write(fixture.path().join("params.bin"), params_bytes).expect("write parameters");
    write_tagged_fixture(fixture.path(), "prover-key.bin", &pk);
    write_tagged_fixture(fixture.path(), "verifier-key.bin", &vk);
    write_tagged_fixture(fixture.path(), "ir.bin", &ir);
    fs::write(fixture.path().join("preimage.bin"), preimage_bytes)
        .expect("copy exact TypeScript-generated preimage bytes");
    let output = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/zkir3_wasm_bridge.cjs"
        ))
        .env("MIDNIGHT_ZKIR_WASM_PACKAGE", package)
        .env("MIDNIGHT_ZKIR_INTEROP_DIR", fixture.path())
        .output()
        .expect("run Node/Wasm prover");
    assert!(
        output.status.success(),
        "Node/Wasm prover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let proof_bytes = fs::read(fixture.path().join("proof.bin")).expect("read Wasm proof");
    let proof: Proof = tagged_deserialize(&mut &proof_bytes[..]).expect("decode Wasm proof");
    let mut public_inputs = vec![preimage.binding_input];
    if let Some((commitment, _)) = preimage.communications_commitment {
        public_inputs.push(commitment);
    }
    public_inputs.extend(preimage.public_transcript_inputs.iter().copied());
    public_inputs.extend(preimage.public_transcript_outputs.iter().copied());
    vk.verify(&verifier_params, &proof, public_inputs.into_iter())
        .expect("native verifier accepts Wasm proof");
}

// The checked-in preimage was emitted by the Compact 0.36.1 TypeScript contract
// and matching runtime 0.21.0, not reconstructed in Rust. An override permits
// regeneration checks with the same V3.1 IR.
#[actix_web::test]
async fn compact_typescript_preimage_proves_and_verifies_with_native_ledger9() {
    let bytes = compact_ts_preimage_bytes();
    let preimage: ProofPreimage =
        tagged_deserialize(&mut &bytes[..]).expect("decode TypeScript-generated preimage");
    assert_eq!(preimage.key_location.0.as_ref(), "test");

    let ir = IrSource::load(include_str!("compact-v3-counter/increment.zkir").as_bytes())
        .expect("load Compact-generated V3 IR");
    preimage
        .check(&ir)
        .expect("TypeScript preimage matches V3 IR");
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params
        .0
        .write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize prover parameters");
    let verifier_params =
        ParamsVerifier::read(&params_bytes[..]).expect("read verifier parameters");
    let heap = HeapParams(params);
    let (pk, vk) = ir.keygen(&heap).await.expect("V3 keygen");
    let resolver = KeyResolver {
        pk,
        vk,
        ir: ir.clone(),
    };
    let context = ProverContext::new(ProverConfig::heap());
    let (proof, _) = preimage
        .prove_with_context::<IrSource>(
            ChaCha20Rng::from_seed([42; 32]),
            &heap,
            &resolver,
            &context,
        )
        .await
        .expect("prove TypeScript-generated preimage");
    let mut public_inputs = vec![preimage.binding_input];
    if let Some((commitment, _)) = preimage.communications_commitment {
        public_inputs.push(commitment);
    }
    public_inputs.extend(preimage.public_transcript_inputs.iter().copied());
    public_inputs.extend(preimage.public_transcript_outputs.iter().copied());
    resolver
        .vk
        .verify(&verifier_params, &proof, public_inputs.into_iter())
        .expect("native Ledger9 verifier accepts TypeScript preimage proof");
}

// These bytes were generated by published ZKIR 3.2.1 source 8825fb5a with
// its locked, registry-provided proofs 0.8.2 and stdlib 2.4.0 dependencies.
// This is a release-source compatibility fixture, not a distributed key.
#[actix_web::test]
async fn release_source_v3_key_and_proof_remain_usable() {
    exercise_release_source_v3_fixture(
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "zkir/minimal.zkir"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "keys/minimal.prover"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "keys/minimal.verifier"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "preimage.bin"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "proof.bin"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-v3-minimal/minimal/",
            "params.bin"
        )),
    )
    .await;
}

// The same published-source producer used the official k=4 SRS from the
// Ledger9 release manifest. The key is locally generated against that SRS;
// it is not a network-distributed production key.
#[actix_web::test]
async fn release_source_v3_key_with_official_k4_params_remains_usable() {
    exercise_release_source_v3_fixture(
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "zkir/minimal.zkir"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "keys/minimal.prover"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "keys/minimal.verifier"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "preimage.bin"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "proof.bin"
        )),
        include_bytes!(concat!(
            "../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal/",
            "params.bin"
        )),
    )
    .await;
}

async fn exercise_release_source_v3_fixture(
    ir_bytes: &[u8],
    key_bytes: &[u8],
    verifier_key_bytes: &[u8],
    preimage_bytes: &[u8],
    baseline_proof_bytes: &[u8],
    params_bytes: &[u8],
) {
    let ir = IrSource::load(ir_bytes).expect("load release-source V3 IR");
    let pk = <IrSource as Zkir>::load_prover_key_from_tagged(Cursor::new(key_bytes))
        .expect("decode release-source V3 proving key");
    pk.init().expect("initialize release-source V3 proving key");
    let vk: VerifierKey = tagged_deserialize(&mut &verifier_key_bytes[..])
        .expect("decode release-source V3 verifier key");
    vk.init()
        .expect("initialize release-source V3 verifier key");
    let preimage: ProofPreimage =
        tagged_deserialize(&mut &preimage_bytes[..]).expect("decode release-source V3 preimage");
    preimage.check(&ir).expect("preimage matches released IR");
    let baseline_proof: Proof =
        tagged_deserialize(&mut &baseline_proof_bytes[..]).expect("decode release-source V3 proof");
    let verifier_params =
        ParamsVerifier::read(&params_bytes[..]).expect("read release-source verifier parameters");
    let public_inputs = [preimage.binding_input];
    vk.verify(&verifier_params, &baseline_proof, public_inputs.into_iter())
        .expect("optimized Ledger9 verifies release-source V3 proof");

    let mut reencoded_key = Vec::new();
    tagged_serialize(&pk, &mut reencoded_key).expect("reencode V3 proving key");
    assert_eq!(reencoded_key, key_bytes, "proving-key format changed");
    let params = HeapParams(ParamsProver::read(&params_bytes[..]).expect("read prover parameters"));
    let resolver = KeyResolver { pk, vk, ir };
    #[cfg(feature = "native-memory")]
    let mut policies = vec![ProverConfig::heap()];
    #[cfg(not(feature = "native-memory"))]
    let policies = vec![ProverConfig::heap()];
    #[cfg(feature = "native-memory")]
    let spill_dir = tempfile::tempdir().expect("private spill directory");
    #[cfg(feature = "native-memory")]
    let mut mapped = ProverConfig::mapped_key_and_cosets();
    #[cfg(feature = "native-memory")]
    {
        mapped.coset_spill_floor_k = 0;
        mapped.spill_dir = Some(spill_dir.path().to_path_buf());
        assert!(mapped.spills_cosets_at(resolver.ir.k() as u32));
        policies.push(mapped);
    }
    for policy in policies {
        let context = ProverContext::new(policy);
        let (proof, _) = preimage
            .prove_with_context::<IrSource>(
                ChaCha20Rng::from_seed([42; 32]),
                &params,
                &resolver,
                &context,
            )
            .await
            .expect("prove with release-source V3 key");
        resolver
            .vk
            .verify(&verifier_params, &proof, public_inputs.into_iter())
            .expect("verify proof from release-source V3 key");
    }

    #[cfg(feature = "native-memory")]
    {
        // The key was initialized above. Spilling cosets alone must not
        // require it to be deserialized again or change its heap backing.
        let mut spill_only = ProverConfig::heap();
        spill_only.spill_cosets = true;
        spill_only.coset_spill_floor_k = 0;
        spill_only.spill_dir = Some(spill_dir.path().to_path_buf());
        let (proof, _, _) = resolver
            .ir
            .prove_with_context(
                ChaCha20Rng::from_seed([43; 32]),
                &params,
                resolver.pk.clone(),
                &preimage,
                &ProverContext::new(spill_only),
            )
            .await
            .expect("prove with initialized heap key and spilled cosets");
        resolver
            .vk
            .verify(&verifier_params, &proof, public_inputs.into_iter())
            .expect("verify proof with spilled cosets");

        let companion_dir = tempfile::tempdir().expect("private release-source companion dir");
        // The test owns this directory and does not mutate published files
        // while the mapped companion is alive.
        let trusted = unsafe { TrustedParamsDir::new(companion_dir.path()) };
        let cache = CompanionCache::from_trusted_dir(trusted.clone());
        let name = MidnightDataProvider::name_k(resolver.ir.k());
        cache
            .open_or_build(&name, || Ok(params.0.clone()))
            .expect("publish release-source SRS companion");
        let mapped_params = MappedParams::new(NoFallback, trusted);
        let mut mapped_policy = ProverConfig::mapped_key_and_cosets();
        mapped_policy.coset_spill_floor_k = 0;
        mapped_policy.spill_dir = Some(spill_dir.path().to_path_buf());
        let (proof, _) = preimage
            .prove_with_context::<IrSource>(
                ChaCha20Rng::from_seed([44; 32]),
                &mapped_params,
                &resolver,
                &ProverContext::new(mapped_policy),
            )
            .await
            .expect("prove with mapped release-source SRS, key, and cosets");
        resolver
            .vk
            .verify(&verifier_params, &proof, public_inputs.into_iter())
            .expect("verify proof with mapped release-source SRS");
    }
}

#[test]
fn compact_generated_zkir3_hash_chain_cost_model() {
    // Compact 0.36.1 (7fa3a117c), using --skip-zk. This larger circuit
    // provides a reproducible k/row baseline before running proof timings.
    let ir = IrSource::load(include_str!("compact-v3-hash-chain/hashAndIncrement.zkir").as_bytes())
        .expect("load Compact-generated v3 hash-chain IR");
    let model = ir.model();
    assert_eq!((model.k(), model.rows()), (15, 32_185));
}

#[actix_web::test]
#[ignore = "focused Ledger9 proof timing for heap and explicit native-memory policy"]
async fn compact_generated_zkir3_hash_chain_proof_timing() {
    // Set MIDNIGHT_V3_BENCH_POLICY=heap or mapped to run one proof per
    // process. This separates policy timings, though setup/keygen still count
    // toward the process RSS peak.
    if let Ok(policy) = std::env::var("MIDNIGHT_V3_BENCH_POLICY") {
        assert!(
            policy == "heap" || policy == "mapped",
            "unknown V3 bench policy"
        );
    }
    let ir = IrSource::load(include_str!("compact-v3-hash-chain/hashAndIncrement.zkir").as_bytes())
        .expect("load Compact-generated v3 hash-chain IR");
    let opening: Fr = 7.into();
    let value: Fr = 7.into();
    let commitment = transient_commit(&[value], opening);
    let public_transcript_inputs = [0x70, 0x01, 0x01, 0x00, 0x0e, 0x01, 0xa1]
        .into_iter()
        .map(Fr::from)
        .collect();
    exercise_heap_and_mapped(
        ir,
        vec![value],
        Some((commitment, opening)),
        public_transcript_inputs,
        true,
    )
    .await;
}

async fn exercise_heap_and_mapped(
    ir: IrSource,
    inputs: Vec<Fr>,
    communications_commitment: Option<(Fr, Fr)>,
    public_transcript_inputs: Vec<Fr>,
    report_timing: bool,
) {
    let k = ir.k();
    let rows = if report_timing { ir.model().rows() } else { 0 };
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        k as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params
        .0
        .write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize params");
    let verifier_params = ParamsVerifier::read(&params_bytes[..]).expect("verifier params");

    let heap = HeapParams(params.clone());
    let (pk, vk) = ir.keygen(&heap).await.expect("v3 keygen");
    let resolver = KeyResolver {
        pk,
        vk,
        ir: ir.clone(),
    };
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment,
        inputs,
        private_transcript: vec![],
        public_transcript_inputs,
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("test")),
    };
    let rng = || ChaCha20Rng::from_seed([42; 32]);
    let mut public_inputs = vec![42.into()];
    if let Some((commitment, _)) = communications_commitment {
        public_inputs.push(commitment);
    }
    public_inputs.extend(preimage.public_transcript_inputs.iter().copied());
    let single_policy = report_timing
        .then(|| std::env::var("MIDNIGHT_V3_BENCH_POLICY").ok())
        .flatten();
    let heap_result = if single_policy.as_deref() == Some("mapped") {
        None
    } else {
        let heap_start = Instant::now();
        let (proof, _) = preimage
            .prove::<IrSource>(rng(), &heap, &resolver)
            .await
            .expect("heap proof");
        let elapsed = heap_start.elapsed();
        resolver
            .vk
            .verify(&verifier_params, &proof, public_inputs.iter().copied())
            .expect("verify heap proof");
        Some((proof, elapsed))
    };

    if !report_timing {
        let context = ProverContext::new(ProverConfig::heap());
        let (context_proof, _) = preimage
            .prove_with_context::<IrSource>(rng(), &heap, &resolver, &context)
            .await
            .expect("explicit-context v3 proof");
        resolver
            .vk
            .verify(
                &verifier_params,
                &context_proof,
                public_inputs.iter().copied(),
            )
            .expect("verify explicit-context v3 proof");

        #[cfg(feature = "native-memory")]
        {
            let spill_dir = tempfile::tempdir().expect("private v3 spill dir");
            let mut policy = ProverConfig::mapped_key_and_cosets();
            policy.coset_spill_floor_k = 0;
            policy.spill_dir = Some(spill_dir.path().to_path_buf());
            assert!(policy.spills_cosets_at(k as u32));
            let mapped_context = ProverContext::new(policy);
            let (optimized_proof, _) = preimage
                .prove_with_context::<IrSource>(rng(), &heap, &resolver, &mapped_context)
                .await
                .expect("mapped-key and coset-spill v3 proof");
            resolver
                .vk
                .verify(
                    &verifier_params,
                    &optimized_proof,
                    public_inputs.iter().copied(),
                )
                .expect("verify mapped-key and coset-spill v3 proof");
        }
    }

    if single_policy.as_deref() == Some("heap") {
        let (proof, elapsed) = heap_result.expect("heap proof was selected");
        eprintln!(
            "v3 hash chain k={k} rows={rows} policy=heap proof={elapsed:?} bytes={}",
            proof.0.len(),
        );
        return;
    }

    #[cfg(not(feature = "native-memory"))]
    assert_ne!(
        single_policy.as_deref(),
        Some("mapped"),
        "mapped V3 proof requires native-memory"
    );

    #[cfg(feature = "native-memory")]
    {
        let dir = tempfile::tempdir().expect("private companion dir");
        // The test owns this temporary directory, publishes the companion only
        // through CompanionCache, and keeps it immutable while mapped values live.
        let trusted = unsafe { TrustedParamsDir::new(dir.path()) };
        let cache = CompanionCache::from_trusted_dir(trusted.clone());
        let name = MidnightDataProvider::name_k(k);
        cache
            .open_or_build(&name, || Ok(params))
            .expect("publish companion");
        let mapped = MappedParams::new(NoFallback, trusted);
        let mapped_start = Instant::now();
        let (mapped_proof, _) = if report_timing {
            let spill_dir = tempfile::tempdir().expect("private V3 coset spill dir");
            let mut policy = ProverConfig::mapped_key_and_cosets();
            policy.coset_spill_floor_k = 0;
            policy.spill_dir = Some(spill_dir.path().to_path_buf());
            assert!(policy.spills_cosets_at(k as u32));
            preimage
                .prove_with_context::<IrSource>(
                    rng(),
                    &mapped,
                    &resolver,
                    &ProverContext::new(policy),
                )
                .await
                .expect("mapped SRS/key and spilled-coset proof")
        } else {
            preimage
                .prove::<IrSource>(rng(), &mapped, &resolver)
                .await
                .expect("mapped proof")
        };
        let mapped_elapsed = mapped_start.elapsed();
        resolver
            .vk
            .verify(&verifier_params, &mapped_proof, public_inputs.into_iter())
            .expect("verify mapped proof");
        if !report_timing {
            assert_eq!(
                heap_result
                    .as_ref()
                    .expect("ordinary case includes heap proof")
                    .0,
                mapped_proof
            );
        }
        if report_timing {
            if let Some((heap_proof, heap_elapsed)) = heap_result {
                eprintln!(
                    "v3 hash chain k={k} rows={rows} heap_proof={heap_elapsed:?} mapped_srs_key_cosets_proof={mapped_elapsed:?} bytes={} identical={}",
                    heap_proof.0.len(),
                    heap_proof == mapped_proof,
                );
            } else {
                eprintln!(
                    "v3 hash chain k={k} rows={rows} policy=mapped proof={mapped_elapsed:?} bytes={}",
                    mapped_proof.0.len(),
                );
            }
        }
    }
}
