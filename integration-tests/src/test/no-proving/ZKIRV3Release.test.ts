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

const fixtureRoot = '../../../../ledger/tests/fixtures/release-zkir-3.2.1-official-k4-minimal/minimal';
const fixture = (name: string) => new URL(`${fixtureRoot}/${name}`, import.meta.url);
const counter = (name: string) => new URL(`../../../../proof-server/tests/${name}`, import.meta.url);

it('serializes the official-k4 release-source IR with the released ZKIR V3 WASM package', async () => {
  const json = await readFile(fixture('zkir/minimal.zkir'), 'utf8');
  const ir = jsonIrToBinary(json);

  expect(Zkir.fromJson(json).serialize()).toEqual(ir);
  expect(Zkir.deserialize(ir).serialize()).toEqual(ir);
  expect(Zkir.deserialize(ir).getK()).toBe(4);
  expect(() => Zkir.deserialize(ir.subarray(0, ir.length - 1))).toThrow();
  if (process.env.MIDNIGHT_V3_WASM_IR_OUT) {
    await writeFile(process.env.MIDNIGHT_V3_WASM_IR_OUT, ir);
  }
});

it('checks and proves with release-tag key material through the TS provider', async () => {
  const [ir, proverKey, verifierKey, params, preimage] = await Promise.all([
    readFile(fixture('zkir/minimal.zkir'), 'utf8'),
    readFile(fixture('keys/minimal.prover')),
    readFile(fixture('keys/minimal.verifier')),
    readFile(fixture('params.bin')),
    readFile(fixture('preimage.bin'))
  ]);
  const provider = provingProvider({
    async lookupKey(keyLocation: string) {
      expect(keyLocation).toBe('minimal');
      return { ir: jsonIrToBinary(ir), proverKey, verifierKey };
    },
    async getParams(k: number) {
      expect(k).toBe(4);
      return params;
    }
  });

  expect(await provider.check(preimage, 'minimal')).toEqual([]);
  const proof = await provider.prove(preimage, 'minimal');
  expect(proof.length).toBeGreaterThan(0);

  // CI passes this artifact to the native verifier on the same release key.
  if (process.env.MIDNIGHT_V3_WASM_PROOF_OUT) {
    await writeFile(process.env.MIDNIGHT_V3_WASM_PROOF_OUT, proof);
  }
});

it('proves the independent Compact k=6 counter bundle through the TS provider', async () => {
  const [ir, proverKey, verifierKey, params, preimage] = await Promise.all([
    readFile(counter('compact-v3-counter/increment.zkir'), 'utf8'),
    readFile(counter('fixtures/midnight-js-counter-increment/increment.prover')),
    readFile(counter('fixtures/midnight-js-counter-increment/increment.verifier')),
    readFile(counter('fixtures/midnight-js-counter-increment/bls_midnight_2p6')),
    readFile(counter('compact-v3-counter/increment.ts-preimage.bin'))
  ]);
  const irBytes = jsonIrToBinary(ir);
  expect(Zkir.deserialize(irBytes).getK()).toBe(6);
  const provider = provingProvider({
    async lookupKey(keyLocation: string) {
      expect(keyLocation).toBe('test');
      return { ir: irBytes, proverKey, verifierKey };
    },
    async getParams(k: number) {
      expect(k).toBe(6);
      return params;
    }
  });

  expect(await provider.check(preimage, 'test')).toEqual([]);
  const proof = await provider.prove(preimage, 'test');
  expect(proof.length).toBeGreaterThan(0);
  if (process.env.MIDNIGHT_V3_WASM_COUNTER_PROOF_OUT) {
    await writeFile(process.env.MIDNIGHT_V3_WASM_COUNTER_PROOF_OUT, proof);
  }
});
