# Compact TypeScript to Ledger9 proof smoke

`increment.ts-preimage.bin` is the 78-byte proof preimage emitted by the
generated TypeScript contract from Compact 0.36.1 (`7fa3a117c`) with
`@midnight-ntwrk/compact-runtime` 0.21.0. Its SHA-256 is
`62c6e481cf818b6d1f67ffa19621dc027a878410861500071c294539df576f0e`.
The ordinary native Ledger9 test uses this fixture; it was not reconstructed
from Rust values. To regenerate it, compile the same contract and require the
ZKIR V3.1 output to match before accepting the new preimage:

```sh
compact compile +0.36.1 --skip-zk counter.compact "$generated_dir"
cmp "$generated_dir/zkir/increment.zkir" increment.zkir
node --version
npm install --prefix "$generated_dir" --no-save \
  @midnight-ntwrk/compact-runtime@0.21.0
runtime_dir="$generated_dir/node_modules/@midnight-ntwrk/compact-runtime"
node emit-ts-preimage.mjs "$generated_dir" "$runtime_dir" "$preimage_file"
cmp "$preimage_file" increment.ts-preimage.bin
```

The generated contract resolves the exact runtime from its own `node_modules`.
The emitter writes the binary preimage produced by the TypeScript contract.

The ordinary `compact_typescript_preimage_proves_and_verifies_with_native_ledger9`
test proves and verifies this fixture. Set `MIDNIGHT_COMPACT_TS_PREIMAGE` to
exercise a freshly regenerated preimage instead. To include the ZKIR Wasm
prover, build `midnight-zkir-wasm` with `wasm-pack` for Node.js and run the
ignored `wasm_compact_v3_proof_verifies_with_native_ledger9` test with
`MIDNIGHT_ZKIR_WASM_PACKAGE` set to its output directory. It uses the same
TypeScript fixture by default. Both tests generate a small local key; neither
validates released per-k proving artifacts.
