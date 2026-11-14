// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { readFile, writeFile } from 'node:fs/promises';
import { expect, it } from 'vitest';
import { Zkir, jsonIrToBinary, provingProvider } from '@midnightntwrk/zkir-v3';

const fixture = (name: string) => new URL(`../../../../proof-server/tests/release-v3-9.1.0.1/${name}`, import.meta.url);

it('reads the Ledger 9.1.0.1 IR with the released ZKIR V3 WASM package', async () => {
  const json = await readFile(fixture('ir.json'), 'utf8');
  const ir = new Uint8Array(await readFile(fixture('ir.bin')));

  expect(jsonIrToBinary(json)).toEqual(ir);
  expect(Zkir.fromJson(json).serialize()).toEqual(ir);
  expect(Zkir.deserialize(ir).serialize()).toEqual(ir);
  expect(Zkir.deserialize(ir).getK()).toBe(4);
  expect(() => Zkir.deserialize(ir.subarray(0, ir.length - 1))).toThrow();
});

it('checks and proves with release-tag key material through the TS provider', async () => {
  const [ir, proverKey, verifierKey, params, preimage] = await Promise.all([
    readFile(fixture('ir.bin')),
    readFile(fixture('prover-key.bin')),
    readFile(fixture('verifier-key.bin')),
    readFile(fixture('params.bin')),
    readFile(fixture('preimage.bin'))
  ]);
  const provider = provingProvider({
    async lookupKey(keyLocation: string) {
      expect(keyLocation).toBe('release-v3');
      return { ir, proverKey, verifierKey };
    },
    async getParams(k: number) {
      expect(k).toBe(4);
      return params;
    }
  });

  expect(await provider.check(preimage, 'release-v3')).toEqual([]);
  const proof = await provider.prove(preimage, 'release-v3');
  expect(proof.length).toBeGreaterThan(0);

  // CI passes this artifact to the native verifier on the same release key.
  if (process.env.MIDNIGHT_V3_WASM_PROOF_OUT) {
    await writeFile(process.env.MIDNIGHT_V3_WASM_PROOF_OUT, proof);
  }
});
