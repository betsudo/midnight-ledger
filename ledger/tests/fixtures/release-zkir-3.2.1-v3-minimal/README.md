# ZKIR 3.2.1 release-source V3 fixture

This k=4 fixture was generated and verified with the **published ZKIR 3.2.1
crate source** at `midnightntwrk/midnight-zkir` commit `8825fb5a`. Its locked
registry dependencies include `midnight-proofs` 0.8.2,
`midnight-zk-stdlib` 2.4.0, and `midnight-transient-crypto` 3.0.0. This is a
small **release-source compatibility** fixture. It is not a
network-distributed proving key or a released per-k production parameter set:
the test uses `ParamsKZG::unsafe_setup(k=4, seed=[7; 32])`.

The Ledger9 `release_source_v3_key_and_proof_remain_usable` test decodes and
re-encodes its tagged proving key, verifies the release-source proof, then
proves and verifies again through both the heap and mapped-key/forced-coset
policies. The existing `zkir-artifacts` test can also decode this directory
with `MIDNIGHT_REQUIRE_ZKIR_KEYS=1`.

To regenerate, copy `generate.rs` to `zkir/tests/release_fixture_local.rs`
in a detached checkout of published source `8825fb5a`, then run:

```sh
MIDNIGHT_RELEASE_V3_OUT=/path/to/temporary-output \
  cargo test -p midnight-zkir --test release_fixture_local --locked -- \
  --exact produce_release_source_v3_fixture --nocapture
```

Compare the generated key, IR, and parameter encodings with this fixture and
verify the proof before updating it. The seeded proof is not required to be
byte-identical on regeneration; the hashes below identify the checked-in
bytes. Keep the producer's lockfile on registry packages; a fork-patched
producer would not establish release-source compatibility.

| File under `minimal/` | SHA-256 |
|---|---|
| `zkir/minimal.zkir` | `789372be8426c8a60651d79920a8d90e062f484ed40a562da1f36bf6206eb391` |
| `params.bin` | `8632a976de81c4362a110ab696f74a91c2dea5622bbf11f5b9e1de0afcc490eb` |
| `keys/minimal.prover` | `d17c6ad720659a45726ec48cba834766e1b8fc2e5e17a79d376ea54bf728cec1` |
| `keys/minimal.verifier` | `7b953d3fce3f9abe8275add6d885a4ee8c8b3f2f6cc0db5665e3c002f6ed7256` |
| `preimage.bin` | `8184e75fe928208f4469789caf47480a4fb176dd97b04ea9ba058e569f927183` |
| `proof.bin` | `03ad60e63fd57c830c7a7fbb023f743f94814801897c0eed074ac406bf4360be` |
