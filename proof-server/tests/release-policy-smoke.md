# Ledger 9.1.0.1 V2/V3 proof policy smoke baseline

This measures the released V2 and V3 fixture tests on the Ledger9 integration
graph. It is a small-circuit compatibility and measurement baseline for
[betsudo/midnight-ledger#30](https://github.com/betsudo/midnight-ledger/issues/30),
not a high-`k` memory or performance claim.

## Reproduce

From the repository root, run `python3 proof-server/tests/release_policy_smoke.py 128`
twice on the same host. The script builds the two compatibility tests with
`--locked --offline`, then runs each V2/V3 heap and mapped arm in a separate
process. Each arm proves 128 times with a fixed seeded RNG and verifies every
proof against its released verifier key. The mapped arm requests forced coset
spill, uses mapped parameters, and supplies a private spill directory. The V2
legacy key reader uses the process spill policy; V3 receives an explicit
`ProverContext`. Ordinary test runs still execute and compare both policies.

Measurement harness commit: `d3ed039a` (signed and DCO). Dependency pins:
optimized proofs/stdlib `6b71786d`, external ZKIR V3 `3c4e2a6a`. Fixtures
come from the unmodified Ledger `9.1.0.1` release, and both circuits have
`k=4`. Host: macOS 26.2, arm64 Apple M2 Max, rustc 1.98.1. Runs were made
consecutively on 2026-11-13; no other benchmark was run concurrently.

| Fixture | Policy | Prove ms/proof A | Prove ms/proof B | Peak process RSS MiB A/B | Max sampled open spill bytes A/B |
| --- | --- | ---: | ---: | ---: | ---: |
| V2 | heap | 24.571 | 24.029 | 16.22 / 16.06 | 0 / 0 |
| V2 | mapped | 27.065 | 26.774 | 16.23 / 16.20 | 105,472 / 105,472 |
| V3 | heap | 24.281 | 23.467 | 18.36 / 18.50 | 0 / 0 |
| V3 | mapped | 27.622 | 26.970 | 18.59 / 18.67 | 105,472 / 105,472 |

`prove_ms` times the proof call only; verification, fixture loading, and test
setup are outside that timer. Peak RSS covers the entire test process, so it
does not isolate the proving allocation. The script samples sizes of open
files in its external spill directory with `lsof` every 50 ms. Nonzero mapped
samples were observed in 29–30 scans per arm. That value is a lower bound on
peak open spill disk use, excludes the test-owned mapped-parameter companion,
and zero observed bytes do not prove zero spill. The k=4 circuit is too small
to show a memory benefit; mapped/spill proving took longer in both passes.

The remaining qualification is an exact-head high-`k` comparison on the same
circuit and host, including a key-load memory gate and a more complete spill
disk measurement. The ignored Compact hash-chain fixture at `k=15` supplies a
larger functional path, but its existing single run is not that comparison.
