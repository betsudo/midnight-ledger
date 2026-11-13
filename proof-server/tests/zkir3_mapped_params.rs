#![cfg(not(target_family = "wasm"))]

//! The released ZKIR v3 crate and Ledger9 must use the same mapped-parameter
//! and proof implementation as the in-tree provider. This small circuit tests
//! the actual crate boundary without a large proof or external parameter file.

use std::borrow::Cow;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use base_crypto::data_provider::MidnightDataProvider;
use midnight_curves::Bls12;
use midnight_proofs::config::{CancelToken, ProverConfig, ProverContext};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::tagged_deserialize;
use serialize::tagged_serialize;
use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_commit;
use transient_crypto::proofs::{
    CompanionCache, KeyLocation, MappedParams, ParamsProver, ParamsProverProvider, ParamsVerifier,
    ProofPreimage, ProverKey, ProvingKeyMaterial, Resolver, TrustedParamsDir, VerifierKey, Zkir,
};
use zkir_v3::IrSource;

struct HeapParams(ParamsProver);

impl ParamsProverProvider for HeapParams {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

struct NoFallback;

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
async fn explicit_key_cache_reuses_only_the_same_policy() {
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
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([9; 32]),
    )));
    let (generated, _) = ir.keygen(&HeapParams(params)).await.expect("keygen");
    let mut bytes = Vec::new();
    tagged_serialize(&generated, &mut bytes).expect("serialize key");
    generated.warm_pk_cache().expect("warm legacy cache");
    let legacy_key = generated.init().expect("initialized generated key");

    let deserialize = || -> ProverKey<IrSource> {
        tagged_deserialize(io::Cursor::new(&bytes)).expect("deserialize lazy key")
    };
    let legacy_reloaded = deserialize().init().expect("legacy cache hit");
    assert!(Arc::ptr_eq(&legacy_key, &legacy_reloaded));
    let heap = ProverConfig::heap();
    let first = deserialize().init_with_policy(&heap).expect("heap key");
    assert!(!Arc::ptr_eq(&first, &legacy_key));
    let same = deserialize()
        .init_with_policy(&heap)
        .expect("cached heap key");
    assert!(Arc::ptr_eq(&first, &same));

    let spill_dir = tempfile::tempdir().expect("mapped-key directory");
    let mut mapped = ProverConfig::mapped_key();
    mapped.spill_dir = Some(spill_dir.path().to_path_buf());
    let different = deserialize().init_with_policy(&mapped).expect("mapped key");
    assert!(!Arc::ptr_eq(&first, &different));
    let same_mapped = deserialize()
        .init_with_policy(&mapped)
        .expect("cached mapped key");
    assert!(Arc::ptr_eq(&different, &same_mapped));

    let other_dir = tempfile::tempdir().expect("second mapped-key directory");
    mapped.spill_dir = Some(other_dir.path().to_path_buf());
    let other_dir_key = deserialize()
        .init_with_policy(&mapped)
        .expect("different directory key");
    assert!(!Arc::ptr_eq(&different, &other_dir_key));
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
#[ignore = "focused Ledger9 proof timing; run explicitly with or without forced spill"]
async fn compact_generated_zkir3_hash_chain_proof_timing() {
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
    if std::env::var("MIDNIGHT_SPILL_COSETS").as_deref() == Ok("1") {
        assert!(
            midnight_proofs::config::ProverConfig::process().spills_cosets_at(k as u32),
            "forced-spill run must select this circuit's k"
        );
    }
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
    let heap_start = Instant::now();
    let (heap_proof, _) = preimage
        .prove_with_context::<IrSource>(
            rng(),
            &heap,
            &resolver,
            &ProverContext::new(ProverConfig::heap()),
        )
        .await
        .expect("heap proof");
    let heap_elapsed = heap_start.elapsed();
    resolver
        .vk
        .verify(&verifier_params, &heap_proof, public_inputs.iter().copied())
        .expect("verify heap proof");

    let cancelled = CancelToken::new();
    cancelled.cancel();
    let error = preimage
        .prove_with_context::<IrSource>(
            rng(),
            &heap,
            &resolver,
            &ProverContext::new(ProverConfig::heap()).with_cancel(cancelled),
        )
        .await
        .expect_err("cancelled request must stop before key resolution");
    assert!(matches!(
        error.downcast_ref::<midnight_proofs::plonk::Error>(),
        Some(midnight_proofs::plonk::Error::Cancelled { .. })
    ));

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
    let (mapped_proof, _) = preimage
        .prove_with_context::<IrSource>(
            rng(),
            &mapped,
            &resolver,
            &ProverContext::new(ProverConfig::process().clone()),
        )
        .await
        .expect("mapped proof");
    let mapped_elapsed = mapped_start.elapsed();
    resolver
        .vk
        .verify(&verifier_params, &mapped_proof, public_inputs.into_iter())
        .expect("verify mapped proof");
    if !report_timing {
        assert_eq!(heap_proof, mapped_proof);
    }
    if report_timing {
        eprintln!(
            "v3 hash chain k={k} rows={rows} forced_spill={} heap_proof={heap_elapsed:?} mapped_proof={mapped_elapsed:?} bytes={} identical={}",
            std::env::var("MIDNIGHT_SPILL_COSETS").as_deref() == Ok("1"),
            heap_proof.0.len(),
            heap_proof == mapped_proof,
        );
    }
}
