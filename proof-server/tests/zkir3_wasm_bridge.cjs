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

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

globalThis.crypto ??= webcrypto;

const wasm = require(process.env.MIDNIGHT_ZKIR_WASM_PACKAGE);
const dir = process.env.MIDNIGHT_ZKIR_INTEROP_DIR;
const read = (name) => new Uint8Array(fs.readFileSync(path.join(dir, name)));

const provider = {
  async lookupKey(location) {
    assert.equal(location, 'test');
    return {
      proverKey: read('prover-key.bin'),
      verifierKey: read('verifier-key.bin'),
      ir: read('ir.bin'),
    };
  },
  async getParams() {
    return read('params.bin');
  },
};

(async () => {
  const preimage = read('preimage.bin');
  await wasm.check(preimage, provider);
  const proof = await wasm.prove(preimage, provider);
  fs.writeFileSync(path.join(dir, 'proof.bin'), Buffer.from(proof));
})().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
