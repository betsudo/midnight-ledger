# Released Ledger9 V2 proving fixture

These files were generated from the upstream `midnight-ledger`
`ledger-9.1.0.1` tag (`a2b30128`) on 2026-11-13. That release uses the
in-tree `midnight-zkir` 2.2.0 route and registry `midnight-proofs 0.8.2` for
V2 proving. No betsudo optimizations are in the exporter build.

The circuit is the small scalar assertion in `ir.json`, matching the V2
assertion case in `zkir/tests/proofs_v2.rs`. The exporter uses ChaCha20 seeds
`[7; 32]` for KZG setup and `[42; 32]` for proof creation. The release build
verifies its proof before writing the files.

To regenerate, create a detached worktree at the upstream tag, add
`midnight-curves = "0.3.1"`, `midnight-proofs = "0.8.2"`, and
`rand_chacha = "0.3.1"` as `proof-server` dev dependencies, copy `exporter.rs`
to `proof-server/tests/release_v2_fixture_export.rs`, then run:

```sh
LEDGER9_FIXTURE_OUT=/tmp/ledger9-release-v2 \
  cargo test --offline -p midnight-proof-server \
  --test release_v2_fixture_export -- --nocapture
```

The generated files have these SHA-256 digests:

| File | SHA-256 |
| --- | --- |
| `ir.bin` | `58caa259cb537861cc406b8ba07b7dc7f0db4024a71d447be847e87edb495473` |
| `ir.json` | `402e64cf0e22c16c633a5bc3fac39a49b2463c1d145c81c828a85d6a953cbf3e` |
| `params.bin` | `8632a976de81c4362a110ab696f74a91c2dea5622bbf11f5b9e1de0afcc490eb` |
| `proof.bin` | `03ad60e63fd57c830c7a7fbb023f743f94814801897c0eed074ac406bf4360be` |
| `prover-key.bin` | `44079522207dcc667249ea70b00a171468a7ca35b8a198f3f89d60a85e0b687e` |
| `verifier-key.bin` | `7b953d3fce3f9abe8275add6d885a4ee8c8b3f2f6cc0db5665e3c002f6ed7256` |

`release_v2_compat.rs` checks that the current fork reads, verifies, and proves
with the released bytes using both heap and mapped parameters. It also checks
truncated key/proof rejection and a mismatched public statement. Run with
`MIDNIGHT_SPILL_COSETS=1 MIDNIGHT_SPILL_FLOOR_K=0`
`MIDNIGHT_BENCH_REQUIRE_SPILL=1` to exercise the V2 compatibility entry
point's process spill policy and fail on a spill error.
