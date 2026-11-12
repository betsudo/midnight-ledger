# Local Ledger9 fork sync and proof migration

This records the local integration for [betsudo/midnight-ledger#29](https://github.com/betsudo/midnight-ledger/issues/29) and [#30](https://github.com/betsudo/midnight-ledger/issues/30). It does not change Ledger8. Recheck upstream heads before publishing or rebasing.

| Line | Baseline | Local head | Purpose |
| --- | --- | --- | --- |
| Stable release | upstream `ledger-9.1.0.1` `a2b30128` | `sync/ledger9-9.1.0.1` `cf93b9e4` | Released proof format, external `midnight-zkir` 3.2.0 |
| Current branch | upstream `ledger-9` `0978af43` | `sync/ledger9-current` `45e63ae5` | External `midnight-zkir` 3.2.1 and proof-server 9.0.2-rc.1 |
| ZK consumer | upstream-compatible proofs 0.8.2 | betsudo `397b2424b972b3ec338722839c109f01c2fcf9f1` | Exact `[patch.crates-io]` source for both Ledger9 lines |

The current Cargo tree resolves one proofs **0.8.2** instance from that betsudo SHA for the v2 and v3 paths, local `midnight-transient-crypto` 3.1.0, local ZKIR v2 2.2.0, external ZKIR v3 3.2.1, and zk-stdlib 2.4.0. The additional registry proofs 0.7.3 and zk-stdlib 1.3.0 are the intentional V0/V1 compatibility stack, not a second 0.8.2 implementation. The stable release branch keeps its external ZKIR 3.2.0 tag and the same optimized proofs SHA. Upstream ZK `main` advertises proofs 0.8.3 with a changed transcript; it is a separate port target described in `betsudo/midnight-zk` branch `sync/proofs-0.8.3-port-plan`.

## Disposition of the old `ledger-9-patched` commits

The old line starts from `0d364eb9`, 324 upstream commits behind the current `ledger-9` comparison. The table accounts for its local commits by hash; “deferred” means the work remains on that branch, not that its behavior was silently dropped from a released consumer.

| Old commits | Disposition on the new Ledger9 lines |
| --- | --- |
| `1814f1f0`, `2051772c`, `461fb242`, `1a84de5b`, `3865f44c`, `efb4c8e3` | Selected mmap/lazy-parameter, per-target feature, typed policy, trust-boundary and immutable-publication behavior was rebuilt as `a473cecd`/`3f9ef46e` on the stable release and `bf858e4c`/`95244cc9` on current. The old combined mobile caches/mimalloc changes were not copied wholesale. |
| `0a88b065`, `d75e442b`, `d54db7e9`, `49163d94`, `49e50ad5`, `fde5cd03`, `d0c5b3e9`, `f6a4a247`, `f404f96b`, `9c97181f`, `e91ccbcc` | Historical proofs repins were superseded by the exact `397b2424` 0.8.2 pin. The patched prover has a `ProverContext`, but external ZKIR 3.2.x and stdlib 2.4.0 still use its compatibility `prove` entry point; these repins alone do not establish request-scoped cancellation through v3. |
| `ae2dca11` | Atomic pending-job admission was ported as `cf93b9e4` on stable and `e6fe793f` on current. This does not solve large-body ingress before admission; existing issue #13 remains open. |
| `c2513bff` | Server-owned parameter failures retain 500 provenance through the new `versioned_ir` mapping in `3f9ef46e`/`95244cc9`; malformed client IR remains a 400. |
| `8a73fcf9`, `a91be239` | The old sequence representation is not ported. Current upstream Rust uses a map and `onchain-runtime-v4.d.ts` exposes `Map<[TokenType, PublicAddress], bigint>`. Existing issue #11 owns propagation and TypeScript boundary coverage; no new representation is introduced here. |
| `c77de8ff`, `706ded7d`, `0e45bb19` | Disk-cached compressed PK behavior is not ported. The old fast path has the key-identity and publication race described in existing issue #14. Reintroduce it only with an identity check and unique no-clobber publication. The current in-memory PK cache remains. |
| `28cb9f15`, `8e077fac` | The upstream Ledger9 proof-server has its own no-fetch mode and post-release API changes. Re-evaluate any broader data-provider no-fetch contract against those APIs before a port. |
| `8aecabb0`, `ccf57a06` | Superseded by the current lockfile: rustls 0.23.46 and memmap2 0.9.12. Re-run the audit gate before publication. |
| `d60824e7`, `70e9d9b5`, `b25f225f` | Fork runner/token work is deferred. Keep upstream's current CI/DCO configuration; design replacement fork CI only when the local branches are ready for remote review. |
| `32482f4d`, `7b3c0599`, `e22acdf5`, `8c143886`, `6d495a55`, `39f70952`, `8a11da79`, `878313a8`, `969f6d90`, `8160f009`, `57bec4ff`, `5f1f42d0`, `f562d358`, `f1401a04`, `77ce153a`, `ff5140d3`, `e503dd22`, `b867268a`, `25e364e8`, `1e1c7a83`, `2fd2b25e`, `1567f96c` | Mobile and broad benchmark infrastructure, old scaffolding, and its maintenance commits are deferred from this released Ledger9 proof integration. The focused Compact v3 probe is a new, smaller qualification artifact, not a replacement for mobile/device measurements. |

## Local gates and remaining work

- A Compact 0.36.1 generated ZKIR 3.1 counter circuit passed v3 keygen, heap and mapped proof, verification, and forced spill on both Ledger9 lines. The current line also has an ignored `k=15`, 32,185-row hash-chain probe with reproducible commands and single-run timing in `proof-server/tests/compact-v3-hash-chain/README.md`. The pinned proof features include native `mmap` and `disk-spill`; the external v3 wasm package was checked without those features.
- The current line passed all eight proof-server library tests, including concurrent queue admission, and the v3 test target (three passing, one ignored). The V2 `/k` endpoint passed. The local V2 minimal prove/verify and wrong-statement rejection tests passed using a SHA-256-verified `k=4` public parameter; their temporary target and parameter file were removed.
- The HTTP V2 transaction proof test still requires generated `fallible` key fixtures under `MIDNIGHT_LEDGER_TEST_STATIC_DIR`. It was not qualified by the minimal V2 test. Request-scoped cancellation across the external v3/stdlib API, ingress admission before large-body buffering (#13), PK disk-cache identity (#14), and cross-version proof/VK fixtures remain open.
- The current v3 benchmark verified both proofs, but they were not byte-identical under the seeded test RNG. Verification, rather than byte equality, is its correctness gate. A separate forced-spill run observed about 997 MiB peak RSS for the whole test process and at most 40 MiB of anonymous mapped spill files alive together, sampled with `lsof`; see the fixture README for the method and limits. These observations do not isolate per-arm memory or establish throughput.
- No local Ledger9 commit has current-head CI because these branches have not been pushed. Remote PRs #15/#16 and the old `ledger-9-patched` head were not moved. The two dirty Claude worktrees and preexisting untracked proof fixtures remain untouched. All disposable build targets from completed local iterations were removed.
