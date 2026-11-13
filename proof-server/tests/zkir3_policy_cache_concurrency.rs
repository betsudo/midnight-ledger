#![cfg(all(not(target_family = "wasm"), feature = "zkir3-context"))]

use std::io;
use std::sync::{Arc, Barrier};

use midnight_curves::Bls12;
use midnight_proofs::config::ProverConfig;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::proofs::{ParamsProver, ParamsProverProvider, ProverKey, Zkir};
use zkir_v3::IrSource;

struct HeapParams(ParamsProver);

impl ParamsProverProvider for HeapParams {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

#[actix_web::test]
async fn simultaneous_explicit_key_requests_share_one_build() {
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
        ChaCha20Rng::from_seed([11; 32]),
    )));
    let (generated, _) = ir.keygen(&HeapParams(params)).await.expect("keygen");
    let mut bytes = Vec::new();
    tagged_serialize(&generated, &mut bytes).expect("serialize key");
    drop(generated);

    let dir = tempfile::tempdir().expect("private mapped-key directory");
    let mut policy = ProverConfig::mapped_key();
    policy.spill_dir = Some(dir.path().to_path_buf());
    let key: ProverKey<IrSource> =
        tagged_deserialize(io::Cursor::new(&bytes)).expect("deserialize shared lazy key");
    let barrier = Barrier::new(3);
    let (first, second) = std::thread::scope(|scope| {
        let load = || {
            barrier.wait();
            key.init_with_policy(&policy).expect("load mapped key")
        };
        let a = scope.spawn(load);
        let b = scope.spawn(load);
        barrier.wait();
        (
            a.join().expect("first worker"),
            b.join().expect("second worker"),
        )
    });
    assert!(Arc::ptr_eq(&first, &second));
    let another_key: ProverKey<IrSource> =
        tagged_deserialize(io::Cursor::new(&bytes)).expect("deserialize another lazy key");
    let third = another_key
        .init_with_policy(&policy)
        .expect("reuse key across lazy objects");
    assert!(Arc::ptr_eq(&first, &third));
}
