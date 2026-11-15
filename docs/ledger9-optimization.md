# Ledger9 optimization integration

This contribution series starts from the official `ledger-9.1.0.1` tag. It pins the published `midnight-proofs` 0.8.2 and ZKIR 3.2.1 source lines by Git revision. The `native-memory` Cargo feature enables native storage capability; it does not select mapped storage for a request. Default proving remains heap-backed, and V2 retains its compatibility route.

## Request path

1. Proof-server admission bounds simultaneous body reads and decoded jobs before the worker queue. A queued job can be cancelled; its transition to running is exclusive with cancellation.
2. The server derives a V3 `ProverConfig` from `--v3-memory-policy` (`heap`, `mapped-key`, or `mapped-key-and-cosets`). The default is `heap`. `--v3-coset-spill-floor-k` defaults to 18, and `--v3-spill-dir` selects the temporary volume.
3. `transient-crypto` loads universal parameters under `ParamsLoadPolicy`. `MIDNIGHT_MMAP_BUILD` and `MIDNIGHT_LAZY_PARAMS` remain legacy process-policy inputs. A policy-aware provider receives explicit `lazy_params`; a provider that cannot honor a requested lazy load returns `Unsupported`.
4. The mapped SRS companion is a trusted, immutable, read-only file in the operator-selected directory. A private temporary file is validated and then atomically published. A miss follows the selected load policy. Treat this directory as a trust boundary.
5. ZKIR V3 receives the per-request context for key loading and proving. A mapped request fails explicitly when native capability is unavailable. Running-proof cancellation is cooperative at phase boundaries.

`--trusted-mmap-dir` controls the universal-parameter companion directory separately from `--v3-spill-dir`, which controls temporary mapped key and coset files. The server rejects a spill directory with `heap` policy. Native mapped storage requires a native target and the `native-memory` build feature; Wasm remains on heap behavior even if that feature is enabled.

## Delivery gates

- Preserve released per-`k` artifact behavior and serialized proof/key formats for Ledger9.
- Check default and feature-enabled native/Wasm builds and exact cross-repository pins.
- Verify the V3 TypeScript preimage and Node/Wasm proof against native Ledger9. The local small-circuit exchange passed; released V3 keys and browser execution need separate evidence.
- Record separate-process high-`k` peak RSS, latency, source heads, target/device, and storage policy before claiming a memory benefit.
- Require current-head CI and external review before merging contribution PRs.

Tracking: [Ledger #14](https://github.com/betsudo/midnight-ledger/issues/14), [Ledger #29](https://github.com/betsudo/midnight-ledger/issues/29), and [ZK #5](https://github.com/betsudo/midnight-zk/issues/5). See [branch naming](branching.md) for future release upgrades.
