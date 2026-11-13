# Local Ledger9 fork sync and proof migration

## 0.8.3 package graph candidate (local only)

The separate local candidate heads advance proofs 0.8.3, stdlib 2.5.0,
base-crypto 1.1.2, transient-crypto 3.2.0, and external ZKIR/Wasm 3.3.0.
Circuits remains 7.3.0 because this port has no local circuits source change.
The transient and ZKIR manifests now set floors that require the context
adapter sources. This is staged separately from the qualified Ledger9
0.8.2 pin and cannot be resolved from released packages yet.

An isolated Cargo harness with local source patches resolved exactly one
proofs 0.8.3, stdlib 2.5.0, transient-crypto 3.2.0, and ZKIR 3.3.0, then
passed `cargo check --offline --locked` for native and
`wasm32-unknown-unknown`. The unlocked first Wasm resolution failed:
`midnight-base-crypto`'s `atomic-write-file ^0.3.0` selected 0.3.1, which
pulled `getrandom` 0.4 without the Wasm backend. Both existing Ledger and
ZKIR locks used 0.3.0. The candidate base-crypto 1.1.2 therefore pins
`atomic-write-file =0.3.0`; a fresh unlocked resolution selected that
version and both native and Wasm checks passed. The harness also resolves
`midnight-curves` 0.2.1 only through the external `sha3-circuit` and 0.3.1
for this stack; it has no duplicate 0.8.3 proofs crate.

Release order for this candidate is proofs/stdlib and base-crypto first,
then transient-crypto, then ZKIR, then a deliberate Ledger9 repin and
lockfile update. The candidate manifest branches are not yet a publishable
workspace: their respective release dependencies are not available in the
registry, and the Ledger root intentionally retains its 0.8.2 patch. Native
and Wasm compile checks do not prove published-package resolution, exact-head
CI, runtime browser behavior, or large-circuit memory and disk admission.
The disposable harness and target are removed after this iteration.

The next disposable Ledger9 proof-server build used local source patches for
the candidate ZK, transient-crypto and ZKIR packages while leaving the
released 0.8.2 root pin in the committed manifest. Cargo resolved one
proofs 0.8.3 for the current v2/v3 paths, alongside the intentional proofs
0.7.3 V0/V1 compatibility stack. The `zkir3_http_context` test passed a
Compact-generated v3 `/prove` request using the tracked k=14 ceremony SRS,
downsized to the test circuit, a mapped parameter companion, and forced
coset spill (`MIDNIGHT_BENCH_REQUIRE_SPILL=1`). The in-tree ZKIR v2
`proofs_v2_083_compat` test then passed all three minimal/ECC/hash-to-curve
proofs on the same candidate graph. This is a local source test; the new
package versions are not published, and it does not cover browser runtime,
HTTP disconnect cancellation, representative k=18 load, or current-head CI.

Refreshing this Ledger workspace lock exposed an independent resolver issue:
the in-tree ZKIR v2 Wasm crate's `wasm-bindgen-test ^0.3.58` can select
0.3.71, which requires `wasm-bindgen =0.2.121` while Ledger9 pins
`=0.2.108`. The local candidate fixes the test dependency at 0.3.58,
matching the existing lock. The disposable proof build used that constraint;
the lockfile and source patches were restored before committing this note.

This records the local integration for [betsudo/midnight-ledger#29](https://github.com/betsudo/midnight-ledger/issues/29) and [#30](https://github.com/betsudo/midnight-ledger/issues/30). It does not change Ledger8. Recheck upstream heads before publishing or rebasing.

| Line | Baseline | Local head | Purpose |
| --- | --- | --- | --- |
| Stable release | upstream `ledger-9.1.0.1` `a2b30128` | `sync/ledger9-9.1.0.1` `cf93b9e4` | Released proof format, external `midnight-zkir` 3.2.0 |
| Current branch | upstream `ledger-9` `0978af43` | `sync/ledger9-current` (this checkout) | External `midnight-zkir` 3.2.1 and proof-server 9.0.2-rc.1 |
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
- The current proof-server admits at most two concurrent request bodies by default, caps each at 512 MiB, and gives each body 120 seconds to arrive. `/prove`, `/check`, and `/prove-tx` reject a full job queue before reading the body; `/k` shares the ingress cap. A declared or streamed body over the cap receives 413; excess ingress or a full job queue receives 429; a slow body receives 408. The server CLI exposes all three ingress limits. The `/prove` key is shared through an `Arc` until the resolver actually requests an owned copy; the resolver API can still clone on use. Five focused `/prove` rejection tests, including full-queue and declared/chunked oversize cases, six `/k`/`/check` rejection tests, and eight library tests passed locally. This mitigates #13; large-key burst memory evidence and a policy for deliberately unlimited (`job_capacity=0`) queues remain open.
- The HTTP V2 transaction proof test still requires generated `fallible` key fixtures under `MIDNIGHT_LEDGER_TEST_STATIC_DIR`. It was not qualified by the minimal V2 test. The two transaction-body rejection tests requiring that fixture likewise could not run; the three fixture-free rejection tests passed. Request-scoped cancellation across the external v3/stdlib API, PK disk-cache identity (#14), and cross-version proof/VK fixtures remain open.
- The current v3 benchmark verified both proofs, but they were not byte-identical under the seeded test RNG. Verification, rather than byte equality, is its correctness gate. A separate forced-spill run observed about 997 MiB peak RSS for the whole test process and at most 40 MiB of anonymous mapped spill files alive together, sampled with `lsof`; see the fixture README for the method and limits. These observations do not isolate per-arm memory or establish throughput.
- No local Ledger9 commit has current-head CI because these branches have not been pushed. Remote PRs #15/#16 and the old `ledger-9-patched` head were not moved. The two dirty Claude worktrees and preexisting untracked proof fixtures remain untouched. All disposable build targets from completed local iterations were removed.

## External ZKIR v3 request-context boundary

The current line resolves registry `midnight-zkir` 3.2.1. Its `IrSource` implementation of `transient_crypto::proofs::Zkir::prove` calls `midnight_zk_stdlib::prove` with parameters, key, circuit, public inputs, witness and RNG, but no proof context. The local `Zkir` trait and `ProofPreimage::prove` likewise have no policy or cancel-token argument. Consequently the existing provider can select mapped parameters and the process-wide compatibility policy can force coset spill, but neither proves request-scoped spill selection or cancellation isolation for v3. The existing Compact v3 proof tests establish the former behavior only.

A disposable `midnight-proof-server` example checked the actual v3 dependency graph by calling `ProofPreimage::prove::<zkir_v3::IrSource>(rng, params, resolver, &context)` with a `ProverContext`. `cargo check -p midnight-proof-server --example zkir3_context_probe` reached the proof server and failed with `E0061`: the method takes three arguments and the context is an unexpected fourth argument. The compiler located the method at local `transient-crypto/src/proofs.rs:1427`. The example, its 701 MiB target, and its temporary worktree were removed after this expected failure.

To pass an explicit context through v3, the local patch extends the `transient-crypto` call boundary, the external `midnight-zkir` implementation, and the matching `midnight-zk-stdlib` entry point. A separate `midnight-zkir` fork is required before publishing that API path; the low-level mmap/spill storage stays in `midnight-proofs`. The negative probe above established the missing boundary, and existing betsudo Ledger issue #30 owns its propagation. No remote fork or release dependency has been changed.

The local `sync/ledger9-context` branch adds `Zkir::prove_with_context` and `ProofPreimage::prove_with_context` while keeping the old `prove` calls. An IR that has not opted in returns an explicit unsupported-context error. The local `midnight-zkir` branch starts from the `zkir-3.2.1` tag, whose source files match crates.io 3.2.1; its manifest is aligned from 3.2.0 to 3.2.1 and `IrSource` forwards the context to stdlib. The local ZK stdlib branch starts from optimized proofs 0.8.2 and aligns the stdlib source and dependency versions to published 2.4.0 before adding `prove_with_context`. Its synthetic SRS test proved and verified through both the context and original entry points.

The Compact-generated v3 counter test passed with the three local packages supplied as Cargo path patches: a pre-cancelled request returned `Error::Cancelled`, and a live request with mapped parameters and an explicit spill policy produced a proof that verified. The test asserts the policy selects this circuit's `k`; it does not measure spill bytes or prove that every coset used a mapped file. The original heap proof still verifies. The path patches were supplied only on the Cargo command line, and `Cargo.lock` was restored to the released registry sources afterward. The default Ledger9 build remains on the published 3.2.1/2.4.0 packages and the pinned optimized proofs 0.8.2 SHA.

With proof-server feature `zkir3-context` enabled, the v3 `/prove` dispatch calls `ProofPreimage::prove_with_context` with `ProverContext::process()`. The feature is off by default so the released ZKIR 3.2.1, which does not implement the new trait method, continues through the original `prove` call. The process context preserves the compatibility policy and cancellation flag; v2 keeps its existing provider. A typed `Cancelled` error maps to the server's cancellation result instead of a malformed-input response. The proof-server library check passed with the feature and local ZKIR/stdlib path patches; a locked default build check passed against the released packages. The focused error-classification test passed with the local patches before the feature guard was added. This is context propagation through the v3 API, not request isolation: there is no per-request token or in-flight HTTP cancellation test. Lazy prover-key initialization still follows `ProverKey::init` → `Zkir::read_raw_pk` → `MidnightPK::read` → `ProvingKey::read`, which uses the process memory policy rather than the request context; the mapped SRS directory is likewise configured process-wide. The Compact 0.36.1 generated v3 counter passed `/prove` and verification through both the opt-in local context path and the default released-package path, each using the same immutable mapped parameter companion. Both runs set `MIDNIGHT_SPILL_COSETS=1`, `MIDNIGHT_SPILL_FLOOR_K=0`, and `MIDNIGHT_BENCH_REQUIRE_SPILL=1`; the test asserts that the process policy selects this circuit size. It does not measure spill bytes or prove that every eligible coset used a mapped file. The opt-in context path now has three focused `k=15`, 32,185-row runs with verified proofs, 7.24–7.45 s heap-parameter and 6.11–6.32 s mapped-parameter proving times, about 989–998 MiB whole-process peak RSS, and a deduplicated sampled peak of 40 MiB in live spill files. The fixture README records exact heads, host, commands, method, and limits; these samples do not isolate per-arm memory or establish throughput. Current-head CI remains open.

The next local key-policy iteration adds `MidnightPK::read_with_policy` in stdlib, `Zkir::read_raw_pk_with_policy` and `ProverKey::init_with_policy` in transient-crypto, and routes v3 context proving through them. Tagged deserialization now retains raw key bytes until initialization; the original `init()` still consults the process cache. Explicit-policy loading bypasses that bytes-only cache and leaves the raw key available for a later request with another policy. It currently rebuilds the key per explicit-policy proof, so throughput and key-load peak memory remain open; an initialized in-process key returns an explicit error on this path because its original storage policy is unknown. The Compact-generated v3 counter and opt-in HTTP path proved and verified with local package patches, including a forced-spill run. The locked default proof-server build still compiles against released ZKIR/stdlib. These small proofs establish wiring and compatibility, not a high-k memory or throughput win. The proof-server still constructs a process context, and the SRS companion directory remains process-wide; request-owned HTTP cancellation and policy-aware key caching are not yet qualified.

The first `k=15` hash-chain sample on this key-policy route verified but took 7.49/8.01 s for its heap/mapped-parameter arms and reached 1.31 GB whole-process peak RSS, compared with the prior three-run 7.24–7.45/6.11–6.32 s and about 1.04 GB. The fixture README gives exact heads and sampled spill evidence. This two-arm process retains the initial heap key and does not isolate mapped-key memory; the single sample is enough to flag key-load cost, not to claim a throughput regression distribution. Policy-aware cache admission by key size and high-k/private-footprint qualification remain open.

The one-arm `k=15` fixture now drops its generated heap key before loading one serialized key per process. With identical mapped parameters and forced coset spill, two mapped-key processes verified in 7.20/7.17 s and peaked at 876/859 MB RSS, with 303 MB sampled live spill; the heap-key process verified in 6.94 s and peaked at 643 MB RSS, with 42 MB sampled live spill. The fixture README records exact byte counts, heads, commands, and limitations. RSS includes file-backed pages, and all process peaks include setup; these samples show a small-circuit cost of mapping the key, not a high-k memory conclusion. The shared counter fixture now uses `prove` with released ZKIR when `zkir3-context` is off and `prove_with_context` with the local opt-in packages when it is on; both Compact-generated counter gates passed, and the locked default small-circuit gate passed.

A later local cache iteration keeps the legacy bytes-only LRU unchanged and adds one process-wide explicit-policy entry keyed by raw-key hash, ZKIR type, and exact `ProverConfig` equality. Same-policy requests can reuse the initialized key; another policy or spill directory cannot. The one-entry cap bounds additional mapped files held open after a request, but does not impose a byte-size or disk-space admission limit. A process-wide build gate admits one explicit key construction at a time; cache hits bypass it, and a waiter rechecks the cache before building. The context-aware ZKIR3 path checks its request token while waiting at this gate (10 ms poll); the policy-only API retains blocking admission. A single low-level key read, or waiting on the per-object key mutex, still cannot be interrupted mid-operation. A focused local test warmed the legacy cache, verified it was not reused by explicit loading, and checked same-policy hits and distinct-policy misses. A separate two-worker ZKIR v3 test confirmed that simultaneous same-key requests receive the same initialized key. The non-ignored opt-in v3 tests (four passed), opt-in HTTP test, locked released-package tests (three passed), and locked HTTP test also passed. A local gate test cancelled a queued waiter while another builder held admission; a v3 resolver test cancelled after key resolution and observed a typed `Cancelled` before key loading. The non-ignored opt-in v3 tests (five passed), opt-in HTTP test, concurrent-cache test, locked released-package tests (three passed), and locked HTTP test passed. This establishes cache identity, serialized key-build admission, and these cancellation checkpoints, not high-k throughput, mid-read cancellation, request-owned HTTP cancellation, or a disk-byte limit.

The opt-in `/prove` handler now creates a fresh cancellation token for each request while retaining the process memory configuration. A guard signals that token if the handler future is dropped; the blocking proof can observe it at the existing key-build and proving checkpoints. A focused async test aborted one handler and confirmed that its token was cancelled while another request's token stayed live. The opt-in Compact-generated v3 HTTP proof still verified. This establishes request token isolation and handler-drop signalling, but does not establish that Actix drops a handler when its network client disconnects. The worker pool still rejects cancellation of a running job, and a low-level key read cannot be interrupted. The default released-package route retains its prior context and dependency graph.

The next local key-loader iteration stores serialized key bytes in an `Arc<Vec<u8>>`, removing the full raw-key clone made by legacy `init()` and allowing the explicit-policy loader to release its per-key mutex while it waits for global build admission. Context-aware requests can now cancel while waiting for either mutex. After admission, the loader reacquires the key mutex and checks its state before reading so a concurrent legacy initializer cannot silently change the policy decision. The per-key cancellation test, same-object and cross-object cache reuse test, five non-ignored opt-in v3 tests, opt-in HTTP proof, and locked released-package HTTP proof passed locally. A low-level key read remains non-interruptible, and the one-entry cache still has no disk-byte admission limit. No high-k memory result follows from these small tests.

The next Compact 0.36.1 fixture has 50 chained hashes and ZKIR 3.2.1 model k=17 / 94,324 rows. Two mapped-key plus forced-coset-spill proofs, two heap-key plus forced-spill proofs, and one heap-key/no-spill proof all verified. The mapped-key pairs used 207–326 MiB less sampled proof-phase RSS than heap keys with the same coset policy, but roughly 996 MiB more sampled live spill and about 2.6 seconds more proof time per pair. The heap/no-spill sample had no observed spill and similar or lower RSS than the heap/spill runs. This is below the default coset-spill floor k=18 and does not justify enabling spill at k=17. The fixture README records exact numbers, source hashes, run order, host, and measurement limits; k=18/k=20, private physical memory, and load remain open.

The next Compact 0.36.1 fixture chains 78 hashes and models at k=18 / 147,048 rows, the default coset-spill floor. Two heap-key/no-spill, two heap-key/spill, and two mapped-key/spill proofs all verified. The mapped-key/spill runs used 205–325 MiB less sampled proof-phase RSS than adjacent heap-key/spill runs, with 1,992 MiB more sampled live spill and about 3.4 seconds more proof time. The heap/no-spill RSS samples straddled the heap/spill samples, so these runs do not establish a coset-spill memory benefit at k=18 or justify changing the default floor. `proof-server/tests/compact-v3-hash-chain-k18/README.md` records exact values, hashes, run order, commands, and measurement limits; k=20, private physical footprint, and load remain open.

A standalone build of the modified ZKIR 3.2.1 CLI against released registry dependencies failed because released transient-crypto 3.0.0, stdlib 2.4.0, and proofs do not expose the new context interfaces. The same CLI successfully modeled the k=17 fixture with local patches for Ledger transient-crypto 3.1.0, modified stdlib, and optimized proofs, after updating its temporary lockfile to those local packages. Its committed lockfile was restored. Publishing this opt-in API requires a compatible dependency release order and version floor; current local builds use path patches, and no remote fork or release has been changed.

For local reproduction from `sync/ledger9-context`, use the two path patches below with `cargo check -p midnight-proof-server --lib --features zkir3-context` or `cargo test -p midnight-proof-server --test zkir3_mapped_params compact_generated_zkir3_counter_uses_the_same_prover_paths`. For the forced-spill HTTP gate, prefix both commands with `MIDNIGHT_SPILL_COSETS=1 MIDNIGHT_SPILL_FLOOR_K=0 MIDNIGHT_BENCH_REQUIRE_SPILL=1`. The opt-in command is `cargo test -p midnight-proof-server --features zkir3-context --test zkir3_http_context` with both path patches; the released-package command is `cargo test -p midnight-proof-server --locked --test zkir3_http_context` without them. Keep the existing proofs 0.8.2 Git patch in the Ledger manifest. Restore the temporary Cargo lockfile changes after the local run.

```text
--config 'patch.crates-io.midnight-zk-stdlib.path="/Users/ysh/iohk/midnight-zk-082-stdlib/zk_stdlib"'
--config 'patch.crates-io.midnight-zkir.path="/Users/ysh/iohk/midnight-zkir/zkir"'
```

## Exploratory proofs 0.8.3 consumer branch

`sync/ledger9-proofs-083-v2-compat` keeps the released Ledger9 0.8.2 line
untouched. With temporary local paths to `betsudo/midnight-zk`
`sync/proofs-0.8.3-memory` and the adapted external ZKIR 3.2.1 branch
`sync/proofs-083-adapter`, it updates the in-tree ZKIR v2 compatibility crate
for the new stdlib `KZG` type argument, cost-model signature, ECC coordinate
API, and arithmetic-column field. A fixture-free v2 test generated its own
parameters and verified minimal, ECC, and hash-to-curve proofs; the minimal
proof also rejected a wrong public statement. The opt-in ZKIR v3 HTTP proof
test passed with forced coset spill. These gates establish v2 source and proof
compatibility with the local 0.8.3 stack, not cross-version artifact
compatibility or a memory win.

The subsequent local ZK branch `sync/proofs-083-quotient-rng` at
`e86149654704a52478e4259ba301d1f252f8c10a` adds mapped proving-key
storage for phase-0, fixed, and permutation Lagrange columns. It also routes
quotient-limb blinding through the caller's cryptographic RNG. Before that
fix, two valid v3 proofs differed despite identical seeded caller RNGs because
the quotient limbs drew from `OsRng` directly. With the fix, the
`zkir3_mapped_params` heap and mapped-parameter/forced-spill proofs verify
and are byte-identical. The policy-cache and Compact-generated v3 counter
tests also pass on `sync/ledger9-proofs-083-mapped-consumer` with this local
ZK branch and the ZKIR adapter.

These consumer checks used temporary local path patches for proofs, curves,
circuits, stdlib, and ZKIR, plus a Git-source patch for the external SHA3
circuit's proofs dependency. The registry curves package lacks APIs required
by this local 0.8.3 proofs branch, so the result does not establish a released
dependency build. The released Ledger9 consumer stays pinned to proofs 0.8.2.

The follow-up ZK branch `sync/proofs-083-key-load-stream` at
`a395eed1ca4b1b207d52fc20871dbf350872d3ea` deserializes fixed and
permutation Lagrange columns one at a time into reserved read-only mappings.
The same three focused Ledger9 v3 consumer tests passed against that exact
commit. The next ZK branch `sync/proofs-083-phase0-stream` at
`7ecf7190ba680808d7a04a0323adb2b713c25f0c` derives each phase-0
coefficient column into a reserved mapping before processing the next. Its
local proof test compares seeded KZG proof bytes across generated mapped,
deserialized mapped, and heap keys, and verifies mapped FFLONK keys. The same
three focused Ledger9 v3 consumer tests pass against this exact commit.
Keygen and the three extended-domain Lagrange polynomials still allocate on
the heap. At that commit, representative `k>=18` load/proof memory and disk
measurements, current-head CI, wasm, and artifact gates remained open. Existing
betsudo Ledger issue #30 owns
the v2 and v3 acceptance gate.

A one-arm `k=15`, 32,185-row Compact-generated ZKIR v3 probe against this
local 0.8.3 stack observed lower macOS physical footprint with mapped keys
under both coset policies, while process RSS and open tempfile sizes grew.
Forcing coset spill below its default `k=18` floor gave no footprint benefit
in these single samples. The commands, four policy configurations, and
measurement limits are in the [fixture README](../proof-server/tests/compact-v3-hash-chain/README.md).
This is not a `k=18` crossover or throughput result; keep the default floor
until a representative larger-circuit gate establishes it.

The later local 0.8.3 stack at proofs `8c2459bd`, this Ledger consumer
`109fe868`, and ZKIR v3 adapter `9976f4c` passed the proof-server's
`zkir3_mapped_params` test (7 passed; 4 intentionally ignored measurement
arms), the opt-in v3 HTTP context test (1), policy-cache concurrency test
(1), and all three in-tree ZKIR v2 compatibility proofs. The server tests
exercise generated heap and mapped/spilled proofs, byte equality, wrong
statements, cancellation, and policy isolation at the local patched graph.
ZKIR v3's 53 library tests and browser Wasm compile check also passed at
these local source heads. The new proofs key payload carries VK version
`0x04`; its 0.8.2 fixture gate is recorded in the ZK port note. Cargo used
temporary local source patches and a disposable lockfile update; this does
not establish released-package alignment, browser runtime behavior,
production SRS compatibility, or current-head CI. Upstream ZK `main`
`20b10959`, Ledger `ledger-9` `0978af43`, and ZKIR `zkir-v3` `f7b433d`
were unchanged at this check.

The same local 0.8.3 source stack also passed the Compact-generated ZKIR v3
k=18 / 147,048-row cost-model gate and three separate verified proof arms on
2026-11-13. With coset spill selected in two arms, mapped-key proving used
106 MiB less sampled proof RSS and about 205 MiB less reported peak macOS
physical footprint than heap-key proving, at the cost of 688 MiB more sampled
live spill files. The heap-key/no-spill arm used about 302 MiB less sampled
proof RSS than heap/spill but about 922 MiB more reported peak physical
footprint, with no live spill. The [k=18 fixture README](../proof-server/tests/compact-v3-hash-chain-k18/README.md)
has exact numbers and raw JSON. Each arm ran once with `vmmap` sampling, so
the timing differences are inconclusive. This is synthetic SRS and one
circuit; the default coset-spill floor remains k=18.
Production SRS, load, disk capacity, and release-package alignment remain
open.

The opt-in Compact-generated v3 counter test can now use Ledger9's tracked
`transient-crypto/static/bls_midnight_2p14` parameters by setting
`MIDNIGHT_LEDGER_TEST_CEREMONY_SRS` to that file. Its SHA-256 is
`fc253016885ec830e97808c9ec920bb5cab5c21af590380a6cb5eb0538e2b244`.
Against local proofs `d86d96b5`, this Ledger consumer, and ZKIR v3
`9976f4c`, the exact `compact_generated_zkir3_counter_uses_the_same_prover_paths`
test passed with `zkir3-context` and the temporary local dependency patches.
It loaded the file through `ParamsProver::read` (`RawBytesUnchecked`),
downsized to the counter circuit's k, generated a key, proved with heap and
private mapped-companion parameters, checked pre-cancelled context behavior,
required equal seeded proof bytes, and verified both proofs. The same test
passed without the environment variable to preserve its synthetic default.
This is a direct proof-server integration test, not an HTTP request or a
full-k=14 proof. The published Ledger9 dependency graph still uses proofs
0.8.2; no release pin or remote branch was changed.

The same tracked SRS now also passes the opt-in v3 `/prove` endpoint test
`prove_endpoint_accepts_v3_with_mapped_params` on the local proofs 0.8.3,
ZKIR v3, and Ledger9 patch graph. With `MIDNIGHT_LEDGER_TEST_CEREMONY_SRS`
pointing at the tracked file, the test loaded via `ParamsProver::read`,
downsized to the Compact counter circuit's k, published a private mapped
companion, sent an HTTP proof request, and verified its response. It passed
again without the SRS environment variable, and passed with that variable
plus `MIDNIGHT_SPILL_COSETS=1`, `MIDNIGHT_SPILL_FLOOR_K=0`, and
`MIDNIGHT_BENCH_REQUIRE_SPILL=1` to require the streamed coset path. This
checks one local HTTP proof, not a full-k=14 proof, disconnect cancellation,
concurrent load, or a released-package build.

The local keygen-policy follow-up uses ZK `sync/zkstdlib-083-keygen-policy`
`962bb214` and external ZKIR `sync/zkir-083-keygen-policy` `e0e08f7`, with
this Ledger consumer based on `59963463`. It adds an opt-in
`Zkir::keygen_with_policy` entry point; the old `keygen` API and the released
Ledger9 proofs 0.8.2 pin are unchanged. The `zkir3_mapped_params` suite passed
seven non-ignored tests against temporary local path patches, including
same-byte key generation, an explicit mapping failure, and existing v3 proof
and cancellation checks. The Compact k=18 / 147,048-row fixture verified a
4,164-byte proof with both heap and mapped keygen while keeping the proving
policy constant. On the single Apple M2 Max pair, sampled keygen RSS was
3,270,160 versus 2,934,336 KiB, sampled mapped-keygen spill was 721,420,288
bytes, and keygen took 14.03 versus 23.16 seconds. Raw samples and caveats
are in `proof-server/tests/compact-v3-hash-chain-k18/README.md`. This is a
local source and synthetic-SRS result, not a published-package or CI gate.

A follow-up negative v3 cache test selected a nonexistent directory for an
explicit mapped-key load. The load returned an error instead of falling back
to a heap key; a subsequent request with the prior valid mapped policy reused
its original cached key. The focused `explicit_key_cache_reuses_only_the_same_policy`
test passed on the same local 0.8.3 source graph.

The same heads also passed a focused external ZKIR/Wasm browser-target compile:
`CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check
--offline --locked --target wasm32-unknown-unknown -p midnight-zkir-wasm`,
using temporary Cargo patches to the three local source worktrees. The
`midnight-zkir-wasm` tree resolved one proofs 0.8.3 and no target dependency on
`memmap2` or proofs `mmap`/`disk-spill` features. Apple clang lacked a Wasm
C target for `blst`; Homebrew LLVM 20.1.6 supplied it. This is a compile
check, not a browser runtime or published-package test. The temporary lock,
patches, worktrees, and 653 MiB target were removed afterward.

A focused Ledger9-only v2/v3 comparison now uses two hand-constructed IRs
with the same 16,384 scalar assertions, k=15, and 16,386 model rows. Both
current v2 and external v3 paths verified a 2,548-byte proof under heap and
forced mapped-key/coset-spill process policies on the same Apple M2 Max host.
The mapped arms observed 52,428,800 bytes of live keygen files and up to
232,783,872 bytes of sampled live proof files. The six raw runs, RSS and
latency values, exact commands, and caveats are in
`proof-server/tests/v2-v3-assert/README.md`. The SRS stays heap-backed in
this comparison; the separate Compact v3 fixture exercises mapped SRS.
This is a matched small circuit baseline, not a production or mobile claim.

The next local candidate retains the explicit memory policy on an already
generated ZKIR v3 key. A direct `prove_with_context` accepts that key only
under the same `ProverConfig`; a different policy fails explicitly. The
policy is process-local metadata and does not change serialized key bytes.
Policy-tagged keys do not enter the legacy bytes-only cache. The focused
`zkir3_mapped_params` suite passed (7 tests; 4 measurement arms ignored),
including a verified proof directly from the mapped generated key. The
external ZKIR adapter uses `ProverKey::from_raw_with_policy`; legacy
`keygen` and `from_raw` keep their original paths.

This test used temporary local patches for curves 0.3.1, circuits 7.3.0,
proofs 0.8.3, stdlib 2.5.0, and ZKIR 3.3.0, plus a Git-source patch that
deduplicated `sha3-circuit`'s proofs dependency. Without those patches,
the candidate did not compile against the current registry curves/circuits:
the proofs and circuits sources refer to APIs missing from their published
same-version packages. The committed Ledger9 lockfile and release pin were
restored; this is a local-source gate, not a released-package or CI gate.

The opt-in v3 HTTP test now also accepts
`MIDNIGHT_LEDGER_TEST_CEREMONY_FULL_K=1` together with
`MIDNIGHT_LEDGER_TEST_CEREMONY_SRS` pointing to the tracked Ledger9 k=14
file. It keeps the SRS at k=14 for v3 keygen and registers the private mapped
companion under the loaded parameter k, which is the k requested during
proof self-verification. On the local proofs `de847239`, ZKIR v3 `e0e08f7`,
and Ledger consumer based on `99f88696`, the focused `zkir3-context`
`prove_endpoint_accepts_v3_with_mapped_params` test returned an HTTP proof
and verified it. The same full-k test passed with
`MIDNIGHT_SPILL_COSETS=1`, `MIDNIGHT_SPILL_FLOOR_K=0`, and
`MIDNIGHT_BENCH_REQUIRE_SPILL=1`; the test asserts that the spill policy
selects the circuit, and the bench-internal prover gate rejects a failed
spill instead of silently accepting heap fallback. Its ordinary
synthetic-SRS path passed again after the provider-key change. The temporary
Cargo graph resolved one local proofs 0.8.3 for the v2/v3 line; its 0.7.3
proofs package remained for legacy
compatibility. The test circuit has fewer rows than k=14 capacity, so this
checks full-size parameter consumption and server routing, not a k=14-sized
workload, memory benefit, released-package graph, or current-head CI.
After restoring the committed manifest and lockfile, the same branch's
`cargo test --locked` could not resolve `midnight-zk-stdlib ^2.5.0` required
by its local `midnight-transient-crypto` 3.2.0: the registry offered 2.4.0
as its latest matching line at this check. This is a package availability
gate, not a failing full-k proof; the released Ledger9 branch must be tested
separately on its 0.8.2 / stdlib 2.4.0 graph.

On the combined local branch, Ledger `sync/ledger9-083-integrated` at
`7b92acd8`, ZK `de847239`, and ZKIR `0e03d5e` passed the same full-k=14
v3 HTTP gate with the tracked ceremony SRS
(`fc253016885ec830e97808c9ec920bb5cab5c21af590380a6cb5eb0538e2b244`)
and forced coset spill. The `zkir3_mapped_params` suite also passed
(7 non-ignored tests, 4 measurement arms ignored) on these combined heads.
This run used temporary local patches for curves, circuits, proofs, stdlib,
and ZKIR, plus a Git-source patch for `sha3-circuit`'s proofs dependency.
The committed Ledger manifest and lockfile still select the release graph;
this local qualification does not establish published-package or CI status.

## Compact ZKIR v3 release-artifact compatibility gate

A separate Ledger9 release-compatible line (`sync/ledger9-current` at
`3fd8a891`) generated a key pair and proof from the same Compact 0.36.1
ZKIR v3 counter IR used by the candidate suite. It used its locked proofs
0.8.2 / stdlib 2.4.0 / ZKIR 3.2.1 graph, a deterministic synthetic SRS,
and verified the proof before export. The three tagged artifacts and their
hashes are recorded in `proof-server/tests/fixtures/v3_082/README.md`.

The local proofs 0.8.3 candidate at `de847239`, external ZKIR v3 adapter at
`725f5a5`, and this Ledger consumer reject those release artifacts in the
focused `rejects_release_082_compact_v3_keys_and_proof` test. The old prover
key's outer tag reads, but inner initialization reports PCS id 6 where 0 is
expected. The old verifier key's outer tag reads, but verification fails on
its inner key read. The old proof wrapper reads, but verification under a
new 0.8.3 key fails. This is a concrete Ledger ZKIR v3 incompatibility:
0.8.3 rollout needs either an explicit versioned conversion or regeneration
of stored keys, with a defined policy for existing proofs. The test used
temporary local source patches for the unreleased package graph. It does
not establish released-package compatibility or current-head CI.
