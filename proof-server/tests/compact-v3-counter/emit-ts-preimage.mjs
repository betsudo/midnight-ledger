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

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [generatedDir, runtimeDir, outputFile] = process.argv.slice(2);
if (!generatedDir || !runtimeDir || !outputFile) {
  throw new Error('usage: node emit-ts-preimage.mjs <generated-dir> <runtime-dir> <output-file>');
}

const generatedContract = pathToFileURL(path.resolve(generatedDir, 'contract/index.js'));
const matchingRuntime = pathToFileURL(path.resolve(runtimeDir, 'dist/index.js'));
const { Contract, ledger } = await import(generatedContract.href);
const {
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  proofDataIntoSerializedPreimage,
} = await import(matchingRuntime.href);

const contract = new Contract({});
const initial = await contract.initialState(createConstructorContext(undefined, '0'.repeat(64)));
const context = createCircuitContext({
  circuitId: 'increment',
  contractAddress: dummyContractAddress(),
  coinPublicKeyOrZswapState: initial.currentZswapLocalState.coinPublicKey,
  contractState: initial.currentContractState,
  privateState: initial.currentPrivateState,
});
const result = await contract.circuits.increment(context);
const trace = result.context.callProofDataTrace;
const round = ledger(result.context.callContext.currentQueryContext.state).round;
if (round !== 1n || trace.length !== 1) {
  throw new Error(`unexpected counter result: round=${round}, calls=${trace.length}`);
}

const call = trace[0];
const preimage = proofDataIntoSerializedPreimage(
  call.input,
  call.output,
  call.publicTranscript,
  call.privateTranscriptOutputs,
  'test',
);
fs.writeFileSync(outputFile, preimage);
console.log(JSON.stringify({
  round: String(round),
  publicTranscript: call.publicTranscript,
  preimageBytes: preimage.length,
  gasCost: result.gasCost,
}, (_, value) => typeof value === 'bigint' ? value.toString() : value));
