# Published Compact V3 counter key for Ledger9

The prover and verifier keys are the `increment` circuit artifacts published in
the [Midnight JS testkit counter bundle](https://github.com/midnightntwrk/midnight-js/tree/66096e0e35d46709ae3227349d71a7652e06422e/testkit-js/testkit-js-e2e/src/contract/compiled/counter).
The bundle's `compiler/contract-manifest.json` records Compact compiler 0.36.1
(`7fa3a117c5e7efe9d2c51da04263e5f0b3509144`), language 0.28.0, and
runtime 0.21.0. Its `zkir/increment.zkir` SHA-256
`6b894828e34f757fec5df0e5872a5fbede9c7cb8fa2fbbb20c7e827717914670`
matches `proof-server/tests/compact-v3-counter/increment.zkir`; the TypeScript preimage
used by the test is the separately checked-in `increment.ts-preimage.bin`.

The published `increment.prover` is stored with Git LFS in the source repo.
The raw Git URL yields only its pointer; the actual 58,166-byte object was
fetched through `media.githubusercontent.com/media` at the pinned commit.
Both key hashes match the upstream manifest:

| File | SHA-256 |
| --- | --- |
| `increment.prover` | `6fa13f54b055be31d4809c59dfd96b08e809641f43bc0d83951cbfb4162ac010` |
| `increment.verifier` | `e5e72349fbd569eb276a3945165659fc68daebc58b94a1d66e52b977027924ef` |

`bls_midnight_2p6` is the official k=6 SRS object at the `param-for 6` URL
in Ledger 9.1.0.1's `flake.nix`. Its SHA-256
`cf2ad6be7d0fedf5bec2aaa35f6be4aca33053d74268fdf5aa54fcb2891ea6df`
matches the manifest's `sha256-zyrWvn0P7fW+wqqjX2vkrKMwU9dCaP31qlT8sokept8=`.
The circuit model has k=6 and 31 rows.

`published_midnight_js_counter_key_proves_with_official_params` loads these
published bytes without regenerating the key, checks that the TypeScript
preimage matches the IR, re-encodes the key byte-for-byte, then proves and
verifies through the default heap path and, when `native-memory` is enabled,
mapped key, mapped SRS, and forced coset spill. This checks compatibility with
an independent SDK testkit artifact. It does not represent a deployed dApp
key or demonstrate high-k capacity or resident-memory improvement.

The opt-in `wasm_compact_v3_proof_verifies_with_native_ledger9` test uses the
same published key and SRS with `midnight-zkir-wasm` 3.2.1. Build its Node.js
package from the matching Ledger9 integration graph, set
`MIDNIGHT_ZKIR_WASM_PACKAGE` to that package directory, and run the ignored
test. Its Wasm-produced proof must verify with the native Ledger9 verifier.
