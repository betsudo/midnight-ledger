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

//! Temporary integration test copied into the published ZKIR 3.2.1 source
//! when regenerating the adjacent release-source compatibility fixture.
//! This file is not compiled as part of the Ledger workspace.

use std::borrow::Cow;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use midnight_zkir::IrSource;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::{Serializable, Tagged, tagged_serialize};
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ParamsVerifier, ProofPreimage, ProverKey,
    ProvingKeyMaterial, Resolver, VerifierKey, Zkir,
};

const IR: &str = r#"{
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
    async fn resolve_key(&self, _: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
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

fn write_tagged<T: Serializable + Tagged>(path: PathBuf, value: &T) {
    let mut bytes = Vec::new();
    tagged_serialize(value, &mut bytes).expect("serialize tagged release fixture");
    fs::write(path, bytes).expect("write release fixture");
}

#[actix_rt::test]
async fn produce_release_source_v3_fixture() {
    let out = PathBuf::from(std::env::var("MIDNIGHT_RELEASE_V3_OUT").expect("fixture output path"));
    let root = out.join("minimal");
    fs::create_dir_all(root.join("keys")).expect("create keys directory");
    fs::create_dir_all(root.join("zkir")).expect("create IR directory");
    let ir = IrSource::load(IR.as_bytes()).expect("load V3 IR");
    let params = ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        ir.k() as u32,
        ChaCha20Rng::from_seed([7; 32]),
    )));
    let mut params_bytes = Vec::new();
    params
        .0
        .write_custom(&mut params_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize parameters");
    let verifier_params =
        ParamsVerifier::read(&params_bytes[..]).expect("read verifier parameters");
    let provider = Params(params);
    let (pk, vk) = ir
        .keygen(&provider)
        .await
        .expect("release source V3 keygen");
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("minimal")),
    };
    let keys = Keys { pk, vk, ir };
    let (proof, _) = preimage
        .prove::<IrSource>(ChaCha20Rng::from_seed([42; 32]), &provider, &keys)
        .await
        .expect("release source V3 proof");
    keys.vk
        .verify(&verifier_params, &proof, [42.into()].into_iter())
        .expect("release source V3 verification");
    fs::write(root.join("zkir/minimal.zkir"), IR).expect("write IR");
    fs::write(root.join("params.bin"), params_bytes).expect("write parameters");
    write_tagged(root.join("keys/minimal.prover"), &keys.pk);
    write_tagged(root.join("keys/minimal.verifier"), &keys.vk);
    write_tagged(root.join("preimage.bin"), &preimage);
    write_tagged(root.join("proof.bin"), &proof);
    eprintln!(
        "release-source fixture k={} at {}",
        keys.ir.k(),
        root.display()
    );
}
