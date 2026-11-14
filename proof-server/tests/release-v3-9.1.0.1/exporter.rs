use std::{borrow::Cow, io, sync::Arc};

use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::tagged_serialize;
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, ProofPreimage, ProverKey,
    ProvingKeyMaterial, Resolver, VerifierKey, Zkir,
};
use zkir_v3::IrSource;

const IR: &[u8] = br#"{
    "version": { "major": 3, "minor": 0 },
    "inputs": [{ "name": "%v_0", "type": "Scalar<BLS12-381>" }],
    "outputs": [],
    "do_communications_commitment": false,
    "instructions": [{ "op": "assert", "cond": "%v_0" }]
}"#;

struct Params(ParamsProver);

impl ParamsProverProvider for Params {
    async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
        Ok(self.0.clone())
    }
}

struct Keys {
    pk: ProverKey<IrSource>,
    vk: VerifierKey,
    ir: IrSource,
}

impl Resolver for Keys {
    async fn resolve_key(&self, _key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        let mut prover_key = Vec::new();
        let mut verifier_key = Vec::new();
        let mut ir_source = Vec::new();
        tagged_serialize(&self.pk, &mut prover_key)?;
        tagged_serialize(&self.vk, &mut verifier_key)?;
        tagged_serialize(&self.ir, &mut ir_source)?;
        Ok(Some(ProvingKeyMaterial { prover_key, verifier_key, ir_source }))
    }
}

#[actix_web::test]
async fn export_release_v3_fixture() {
    let out = std::path::PathBuf::from(std::env::var_os("LEDGER9_FIXTURE_OUT").expect("set LEDGER9_FIXTURE_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let ir = IrSource::load(IR).unwrap();
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params.0.write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked).unwrap();
    let verifier_params = ParamsVerifier::read(&params_bytes[..]).unwrap();
    let (pk, vk) = ir.keygen(&Params(params.clone())).await.unwrap();
    let keys = Keys { pk, vk, ir };
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("release-v3")),
    };
    let (proof, _) = preimage.prove::<IrSource>(ChaCha20Rng::from_seed([42; 32]), &Params(params), &keys).await.unwrap();
    keys.vk.verify(&verifier_params, &proof, [42.into()].into_iter()).unwrap();
    for (name, value) in [
        ("prover-key.bin", tagged(&keys.pk)),
        ("verifier-key.bin", tagged(&keys.vk)),
        ("proof.bin", tagged(&proof)),
        ("ir.bin", tagged(&keys.ir)),
        ("params.bin", params_bytes),
        ("ir.json", IR.to_vec()),
    ] {
        std::fs::write(out.join(name), value).unwrap();
    }
}

fn tagged<T: serialize::Serializable + serialize::Tagged>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    tagged_serialize(value, &mut bytes).unwrap();
    bytes
}
