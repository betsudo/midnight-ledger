# Ledger9 optimization integration

The current fork candidate starts from the official `ledger-9.1.0.2` tag
(`055e413d`) and merges the tested 9.1.0.1 optimization head (`b493ac5f`).
It pins the published `midnight-proofs` 0.8.2 and ZKIR 3.2.1 source lines by
Git revision. The `native-memory` Cargo feature enables native storage
capability; it does not select mapped storage for a request. Default proving
remains heap-backed, and V2 retains its compatibility route.

The intended result is lower peak memory on selected native V3 workloads
with an explicit tradeoff in disk I/O and latency. This is an opt-in
architecture proposal, not a change to Ledger9's wire formats or default
proof behavior. The release-base approach and branch roles are described
in [branch naming](branching.md).

## Ledger 9.1.0.2 release delta

The [official 9.1.0.2 release](https://github.com/midnightntwrk/midnight-ledger/releases/tag/ledger-9.1.0.2)
is a client-side patch on Ledger9. It adds `TransactionShape` and sizes
transcript partitioning against the predicted transaction's dismissal
allowance and widest possible commitment-tree indices. Client-side Wasm
loading accepts a short extension chain that an ordinary map write can
produce; node and consensus decoding must keep the strict default. The
co-tagged proof server 9.0.2 passes container arguments through and provides
an optional parameter-cache mount at `MIDNIGHT_PP`.

The merged graph resolves `midnight-ledger-v9` 1.0.2, proof-server 9.0.2,
storage 3.1.0, transient-crypto 3.1.0, the optimized proofs 0.8.2 source at
`bca8db4d`, and the ZKIR 3.2.1 fork at `3e980fbe`. The ZK revision contains
the reviewed native-storage implementation plus the patch-free Git-consumer
closure from ZK PR #17: the published SHA3 and Blake2b helper sources use
repository-relative dependencies on the same curves and proofs packages.
Applications no longer need a four-package proof patch table to consume this
Ledger source graph. Default heap and Wasm behavior remains a compatibility
gate, not an assumption.

At local merge head `0a14fda3`, locked offline checks of Ledger and proof
server passed. The native-memory V3 fixture test passed seven active cases
with two intentional ignores; the checked-in official-k4 artifact and key
decode test passed. A direct host Wasm check stopped in the host `clang`
toolchain before compiling Ledger because that compiler lacks the Wasm C
target. The repository's full Nix shell began building unrelated flake
inputs and was stopped to conserve disk. Feature-enabled Wasm, release
transaction-shape behavior, proof-server integration, and current-head CI
remain gates for the 9.1.0.2 review branch. The opt-in Node/Wasm-to-native
proof test is not part of ordinary hosted CI.

## Request path

1. Proof-server admission bounds simultaneous body reads and decoded jobs before the worker queue. A queued job can be cancelled; its transition to running is exclusive with cancellation.
2. The server derives a V3 `ProverConfig` from `--v3-memory-policy` (`heap`, `mapped-key`, or `mapped-key-and-cosets`). The default is `heap`. `--v3-coset-spill-floor-k` defaults to 18, and `--v3-spill-dir` selects the temporary volume.
3. `transient-crypto` loads universal parameters under `ParamsLoadPolicy`. `MIDNIGHT_MMAP_BUILD` and `MIDNIGHT_LAZY_PARAMS` remain legacy process-policy inputs. A policy-aware provider receives explicit `lazy_params`; a provider that cannot honor a requested lazy load returns `Unsupported`.
4. The mapped SRS companion is a trusted, immutable, read-only file in the operator-selected directory. A private temporary file is validated and then atomically published. A miss follows the selected load policy. Treat this directory as a trust boundary.
5. ZKIR V3 receives the per-request context for key loading and proving. A mapped request fails explicitly when native capability is unavailable. Running-proof cancellation is cooperative at phase boundaries.

```text
HTTP body -> ingress permit -> bounded decode -> queued work -> worker
                                                       |
                           V2: released proving route -+
                           V3: request ProverContext ---+-> ZKIR -> proofs
                                |                             |
                                +-> storage policy/cancel      +-> params provider
```

The routing lives in [`proof-server/src/versioned_ir.rs`](../proof-server/src/versioned_ir.rs).
[`transient-crypto/src/proofs/key_cache.rs`](../transient-crypto/src/proofs/key_cache.rs)
owns policy-aware key admission. The storage primitives and unsafe mapped
SRS reader live in
[`midnight-zk`](https://github.com/betsudo/midnight-zk/blob/d530c2694ae2c366aed59a3d72259e23730b6586/proofs/docs/ledger9-native-memory.md);
the V3 forwarding API lives in
[`midnight-zkir`](https://github.com/betsudo/midnight-zkir/blob/556f3c4457a3b5e5ee544eca9e4893ebbde2b446/docs/ledger9-v3-context.md).

## Build and runtime policy

Build the native proof server with its opt-in `native-memory` feature
before selecting mapped storage. The default CLI policy is `heap`;
feature-enabled binaries still use the released compatibility path unless
an operator selects a mapped V3 policy.

| CLI option | Default | Meaning |
| --- | --- | --- |
| `--v3-memory-policy` | `heap` | `heap`, `mapped-key`, or `mapped-key-and-cosets` for V3 only |
| `--v3-coset-spill-floor-k` | `18` | Minimum circuit `k` for requested coset spill |
| `--v3-spill-dir` | OS temporary directory | Private temporary mapped key and coset files |
| `--trusted-mmap-dir` | Unset | Immutable SRS companion directory, a separate trust boundary |
| `--max-body-bytes` | 512 MiB | Maximum buffered request body |
| `--max-ingress` | 2 | Simultaneous body readers/decoders |
| `--job-capacity` | 10 | Pending work closures retained by the queue |
| `--num-workers` | 2 | Proof workers |

The matching `MIDNIGHT_PROOF_SERVER_*` environment variables are defined
in [`proof-server/src/main.rs`](../proof-server/src/main.rs). For example,
a native feature-enabled server can select
`--v3-memory-policy mapped-key-and-cosets --v3-coset-spill-floor-k 18`.
Selecting a spill directory with `heap` is rejected. Mapped policy is
rejected when the native feature is unavailable. V2 and Wasm continue to
use heap behavior.

`--trusted-mmap-dir` controls the universal-parameter companion directory separately from `--v3-spill-dir`, which controls temporary mapped key and coset files. The server rejects a spill directory with `heap` policy. Native mapped storage requires a native target and the `native-memory` build feature; Wasm remains on heap behavior even if that feature is enabled.

Queue capacity counts closures still held by the work channel, including jobs whose status records were cancelled or expired. A worker releases a slot when it dequeues and drops the work item; garbage collection alone cannot admit replacement bodies while old queued work still retains memory. The configured ingress limit independently caps simultaneous body readers. Set both limits for the expected proof-server load; capacity `0` retains the explicit unlimited-queue mode.

The body size and read timeout are enforced while holding the ingress
permit. A saturated queue or ingress gate responds with HTTP 429 before
accepting more decoded work. A client should retry 429 with bounded backoff
appropriate to its request deadline. Test harnesses can choose a larger
**bounded** ingress and queue limit for parallel test traffic; this does
not change the server defaults. The queue implementation is in
[`proof-server/src/worker_pool.rs`](../proof-server/src/worker_pool.rs),
and body admission is in
[`proof-server/src/endpoints.rs`](../proof-server/src/endpoints.rs).

## Trust, failures, and compatibility

`--trusted-mmap-dir` and `--v3-spill-dir` serve different purposes.
The former is an operator-controlled cache for reusable universal
parameter companions. Its [`TrustedParamsDir`](../transient-crypto/src/proofs/companion_cache.rs)
constructor is unsafe because no process may modify, truncate, or replace
a published file while any mapping is alive. Use a private, immutable
directory; do not use a shared mutable or synchronized folder. The latter
holds disposable, request-scoped key/coset spill files and needs available
backing storage.

On a companion miss, the selected parameter load policy still applies.
An explicit lazy request to a provider that cannot honor it returns
`Unsupported`. A requested native spill or mapped key failure is returned
as an error rather than silently allocating a potentially large heap
substitute. V3 cancellation is request-local and cooperative at key
admission and prover phase checkpoints. It cannot undo a partially written
transcript. The default API, released proof/key encodings, and V2 route
remain compatible.

## Delivery gates

- Preserve released per-`k` artifact behavior and serialized proof/key formats for Ledger9.
- Check default and feature-enabled native/Wasm builds and exact cross-repository pins.
- Verify the V3 TypeScript preimage and Node/Wasm proof against native Ledger9. The local k=4 test uses an official SRS and a key generated from published ZKIR 3.2.1 source; the k=6 test uses an official SRS and an independently published SDK testkit key. Deployed-dApp key and browser execution remain separate gates.
- Record separate-process high-`k` peak RSS, latency, source heads, target/device, and storage policy before claiming a memory benefit.
- Require current-head CI and external review before merging contribution PRs.

Keep a table of exact source revisions, feature sets, target triple, `k`,
parameter/key fixture, policy, peak RSS, elapsed time, disk usage, and proof
verification result. Compare the same released fixture on heap and mapped
paths. In upstream review, separate published-source alignment, queue
admission, parameter trust boundary, V3 context propagation, and measured
storage behavior so each change has its own compatibility argument.

Tracking: [Ledger #14](https://github.com/betsudo/midnight-ledger/issues/14), [Ledger #29](https://github.com/betsudo/midnight-ledger/issues/29), and [ZK #5](https://github.com/betsudo/midnight-zk/issues/5). See [branch naming](branching.md) for future release upgrades.

## Prior 9.1.0.1 fork qualification

[Ledger PR #39](https://github.com/betsudo/midnight-ledger/pull/39) pins
the k=4 and k=6 fixtures described above. On the pre-documentation
executable head `2b3ee462`, the focused `native-memory` V3 test had seven
passes and two intentional ignores. That head's
[build-and-test workflow](https://github.com/betsudo/midnight-ledger/actions/runs/43834105721)
passed eight jobs, including feature-enabled Ledger9 Wasm compilation and
the integration suite; [coverage](https://github.com/betsudo/midnight-ledger/actions/runs/43834104987)
also passed. The Node/Wasm-to-native proof test passed locally using the
ZKIR 3.2.1 Node package but is opt-in and ignored in ordinary CI.

These results establish small-circuit format and cross-runtime
interoperability, not high-`k` resident-memory relief, mobile capacity, or
deployed-dApp artifact coverage. [Ledger #30](https://github.com/betsudo/midnight-ledger/issues/30)
tracks the remaining V3 acceptance gates, and
[Ledger #12](https://github.com/betsudo/midnight-ledger/issues/12) owns the
repeatable capacity benchmark. The cross-repository PR and upstream review
map is in [ZK PR #13](https://github.com/betsudo/midnight-zk/pull/13).
