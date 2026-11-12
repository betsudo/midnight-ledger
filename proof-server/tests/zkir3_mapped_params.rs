#![cfg(not(target_family = "wasm"))]

//! The released ZKIR v3 crate and Ledger9 must use the same mapped-parameter
//! and proof implementation as the in-tree provider. This small circuit tests
//! the actual crate boundary without a large proof or external parameter file.

use std::borrow::Cow;
use std::io;
#[cfg(feature = "zkir3-context")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base_crypto::data_provider::MidnightDataProvider;
use midnight_curves::Bls12;
use midnight_proofs::config::{CancelToken, ProverConfig, ProverContext};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "zkir3-context")]
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

#[cfg(feature = "zkir3-context")]
struct CancellingResolver {
    inner: KeyResolver,
    token: CancelToken,
}

#[cfg(feature = "zkir3-context")]
impl Resolver for CancellingResolver {
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        let material = self.inner.resolve_key(key).await?;
        self.token.cancel();
        Ok(material)
    }
}

#[actix_web::test]
#[cfg(feature = "zkir3-context")]
async fn cancellation_after_resolution_stops_before_key_load() {
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
    let params = HeapParams(ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([13; 32]),
    ))));
    let (pk, vk) = ir.keygen(&params).await.expect("keygen");
    let token = CancelToken::new();
    let resolver = CancellingResolver {
        inner: KeyResolver {
            pk,
            vk,
            ir: ir.clone(),
        },
        token: token.clone(),
    };
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("test")),
    };
    let context = ProverContext::new(ProverConfig::mapped_key()).with_cancel(token);
    let error = preimage
        .prove_with_context::<IrSource>(
            ChaCha20Rng::from_seed([42; 32]),
            &params,
            &resolver,
            &context,
        )
        .await
        .expect_err("resolver cancellation must stop before key load");
    assert!(matches!(
        error.downcast_ref::<midnight_proofs::plonk::Error>(),
        Some(midnight_proofs::plonk::Error::Cancelled {
            phase: "prover_key.init"
        })
    ));
}

#[cfg(feature = "zkir3-context")]
struct FileKeyResolver {
    prover_key_path: PathBuf,
    verifier_key: Vec<u8>,
    ir_source: Vec<u8>,
}

#[cfg(feature = "zkir3-context")]
impl Resolver for FileKeyResolver {
    async fn resolve_key(&self, _key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        Ok(Some(ProvingKeyMaterial {
            prover_key: std::fs::read(&self.prover_key_path)?,
            verifier_key: self.verifier_key.clone(),
            ir_source: self.ir_source.clone(),
        }))
    }
}

#[actix_web::test]
#[cfg(feature = "zkir3-context")]
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

#[actix_web::test]
#[cfg(feature = "zkir3-context")]
#[ignore = "focused one-arm Ledger9 key-policy memory measurement"]
async fn compact_generated_zkir3_hash_chain_context_only() {
    let ir = IrSource::load(include_str!("compact-v3-hash-chain/hashAndIncrement.zkir").as_bytes())
        .expect("load Compact-generated v3 hash-chain IR");
    let k = ir.k();
    assert_eq!((k, ir.model().rows()), (15, 32_185));
    let opening: Fr = 7.into();
    let value: Fr = 7.into();
    let commitment = transient_commit(&[value], opening);
    let public_transcript_inputs: Vec<Fr> = [0x70, 0x01, 0x01, 0x00, 0x0e, 0x01, 0xa1]
        .into_iter()
        .map(Fr::from)
        .collect();

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
    drop(params_bytes);

    let heap = HeapParams(params.clone());
    let (pk, vk) = ir.keygen(&heap).await.expect("v3 keygen");
    drop(heap);
    let key_dir = tempfile::tempdir().expect("private key dir");
    let prover_key_path = key_dir.path().join("prover.key");
    let mut prover_key = Vec::new();
    let mut verifier_key = Vec::new();
    let mut ir_source = Vec::new();
    tagged_serialize(&pk, &mut prover_key).expect("serialize prover key");
    tagged_serialize(&vk, &mut verifier_key).expect("serialize verifier key");
    tagged_serialize(&ir, &mut ir_source).expect("serialize IR");
    std::fs::write(&prover_key_path, &prover_key).expect("write temporary prover key");
    drop(prover_key);
    drop(pk);
    let resolver = FileKeyResolver {
        prover_key_path,
        verifier_key,
        ir_source,
    };

    let params_dir = tempfile::tempdir().expect("private companion dir");
    let trusted = unsafe { TrustedParamsDir::new(params_dir.path()) };
    let cache = CompanionCache::from_trusted_dir(trusted.clone());
    cache
        .open_or_build(&MidnightDataProvider::name_k(k), || Ok(params))
        .expect("publish companion");
    let mapped = MappedParams::new(NoFallback, trusted);
    let spill_dir = tempfile::tempdir().expect("private spill dir");
    let heap_key = std::env::var("MIDNIGHT_BENCH_HEAP_KEY").as_deref() == Ok("1");
    let mut policy = if heap_key {
        ProverConfig::heap()
    } else {
        ProverConfig::mapped_key_and_cosets()
    };
    policy.spill_cosets = true;
    policy.coset_spill_floor_k = 0;
    policy.spill_dir = Some(
        std::env::var_os("MIDNIGHT_SPILL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| spill_dir.path().to_path_buf()),
    );
    assert!(policy.spills_cosets_at(k as u32));
    let context = ProverContext::new(policy);
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: Some((commitment, opening)),
        inputs: vec![value],
        private_transcript: vec![],
        public_transcript_inputs: public_transcript_inputs.clone(),
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("test")),
    };
    let start = Instant::now();
    let (proof, _) = preimage
        .prove_with_context::<IrSource>(
            ChaCha20Rng::from_seed([42; 32]),
            &mapped,
            &resolver,
            &context,
        )
        .await
        .expect("context-only v3 proof");
    let prove_elapsed = start.elapsed();
    let public_inputs = [42.into(), commitment]
        .into_iter()
        .chain(public_transcript_inputs);
    vk.verify(&verifier_params, &proof, public_inputs)
        .expect("verify context-only proof");
    eprintln!(
        "v3 context-only hash chain k={k} rows=32185 heap_key={heap_key} proof={prove_elapsed:?} bytes={}",
        proof.0.len()
    );
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
        .prove::<IrSource>(rng(), &heap, &resolver)
        .await
        .expect("heap proof");
    let heap_elapsed = heap_start.elapsed();
    resolver
        .vk
        .verify(&verifier_params, &heap_proof, public_inputs.iter().copied())
        .expect("verify heap proof");

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
    let spill_dir = tempfile::tempdir().expect("private spill dir");
    let mapped_context = if report_timing {
        ProverContext::new(ProverConfig::process().clone())
    } else {
        let mut policy = ProverConfig::heap();
        policy.spill_cosets = true;
        policy.coset_spill_floor_k = 0;
        policy.spill_dir = Some(spill_dir.path().to_path_buf());
        assert!(policy.spills_cosets_at(k as u32));
        ProverContext::new(policy)
    };
    if cfg!(feature = "zkir3-context") && !report_timing {
        let token = CancelToken::new();
        token.cancel();
        let cancelled = mapped_context.clone().with_cancel(token);
        let error = preimage
            .prove_with_context::<IrSource>(rng(), &mapped, &resolver, &cancelled)
            .await
            .expect_err("a cancelled v3 request must stop");
        assert!(matches!(
            error.downcast_ref::<midnight_proofs::plonk::Error>(),
            Some(midnight_proofs::plonk::Error::Cancelled { .. })
        ));
    }
    let mapped_start = Instant::now();
    let (mapped_proof, _) = if cfg!(feature = "zkir3-context") {
        preimage
            .prove_with_context::<IrSource>(rng(), &mapped, &resolver, &mapped_context)
            .await
            .expect("mapped proof with explicit context")
    } else {
        preimage
            .prove::<IrSource>(rng(), &mapped, &resolver)
            .await
            .expect("mapped proof with released ZKIR")
    };
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
