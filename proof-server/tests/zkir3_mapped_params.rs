#![cfg(not(target_family = "wasm"))]

//! The released ZKIR v3 crate and Ledger9 must use the same mapped-parameter
//! and proof implementation as the in-tree provider. This small circuit tests
//! the actual crate boundary without a large proof or external parameter file.

use std::borrow::Cow;
use std::io;
use std::sync::Arc;

use base_crypto::data_provider::MidnightDataProvider;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::tagged_serialize;
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
    let k = ir.k();
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
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("test")),
    };
    let rng = || ChaCha20Rng::from_seed([42; 32]);
    let (heap_proof, _) = preimage
        .prove::<IrSource>(rng(), &heap, &resolver)
        .await
        .expect("heap proof");
    resolver
        .vk
        .verify(&verifier_params, &heap_proof, [42.into()].into_iter())
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
    let (mapped_proof, _) = preimage
        .prove::<IrSource>(rng(), &mapped, &resolver)
        .await
        .expect("mapped proof");
    resolver
        .vk
        .verify(&verifier_params, &mapped_proof, [42.into()].into_iter())
        .expect("verify mapped proof");
    assert_eq!(heap_proof, mapped_proof);
}
