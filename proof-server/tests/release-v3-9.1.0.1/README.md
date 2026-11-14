# Released Ledger9 V3 proving fixture

These files were generated from the unmodified upstream `midnight-ledger`
`ledger-9.1.0.1` tag (`a2b30128`) on 2026-11-13. That tag uses the released
`midnight-zkir` `zkir-3.2.0` revision `446c7fec` and registry
`midnight-proofs 0.8.2`. No betsudo optimizations are in the exporter build.

The circuit is the small scalar assertion in `ir.json`. The exporter uses
ChaCha20 seeds `[7; 32]` for KZG setup and `[42; 32]` for proof creation. The
same release build verifies its own proof before writing the files.

To regenerate, create a detached worktree at the upstream tag, add
`midnight-curves = "0.3.1"`, `midnight-proofs = "0.8.2"`, and
`rand_chacha = "0.3.1"` as `proof-server` dev dependencies, copy `exporter.rs`
to `proof-server/tests/release_fixture_export.rs`, then run:

```sh
LEDGER9_FIXTURE_OUT=/tmp/ledger9-release-fixtures \
  cargo test --offline -p midnight-proof-server \
  --test release_fixture_export -- --nocapture
```

The generated files have these SHA-256 digests:

| File | SHA-256 |
| --- | --- |
| `ir.bin` | `523d65c25ee1c4ff5158670001a865634bf06c38e351eed7e4d2e9d869d5cfde` |
| `ir.json` | `299fb6272d2475c30b2ce4feaba11ef32d1868a1389100502a4980081005d01c` |
| `params.bin` | `8632a976de81c4362a110ab696f74a91c2dea5622bbf11f5b9e1de0afcc490eb` |
| `proof.bin` | `03ad60e63fd57c830c7a7fbb023f743f94814801897c0eed074ac406bf4360be` |
| `prover-key.bin` | `d17c6ad720659a45726ec48cba834766e1b8fc2e5e17a79d376ea54bf728cec1` |
| `verifier-key.bin` | `7b953d3fce3f9abe8275add6d885a4ee8c8b3f2f6cc0db5665e3c002f6ed7256` |

`release_v3_compat.rs` checks that the current fork deserializes and verifies
the released bytes and can create new proofs using the released key material
with both heap and mapped-parameter/forced-spill policies. Both new proofs
verify with the released verifier key and have identical proof bytes. It also
rejects truncated key/proof bytes and a mismatched public statement. Run with
`MIDNIGHT_BENCH_REQUIRE_SPILL=1` to turn a failed spill attempt into a test
failure rather than a heap fallback.
