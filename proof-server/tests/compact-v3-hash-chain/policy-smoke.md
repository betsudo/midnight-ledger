# Separate-process high-k V3 policy smoke

This focused measurement uses the Compact 0.36.1 hash-chain ZKIR 3.1 fixture
described in [README.md](README.md). Its ZKIR 3.2.1 cost model is `k=15` and
32,185 rows. The harness commit is signed and DCO-marked `4ebb3428`; it pins
optimized proofs/stdlib at `6b71786d` and external ZKIR V3 at `3c4e2a6a`.
The same generated parameters, prover key, and verifier key are used by every
arm. Their exported bytes were:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Parameters | 6,291,844 | `05960c5b27c93da7becb58ef47326102fd1b8b8feea937255d1061233374bfcd` |
| Prover key | 45,094,315 | `ca35f48ca707393dae8a1b667b9722e78a2e0e5fe46e875cb80aae78609e0d23` |
| Verifier key | 2,121 | `e86a6f9359fa6bd2024c29eb364322b7560cd31ba16cbc3367c05729ad601bc2` |

From the repository root, run:

```sh
python3 -B proof-server/tests/hash_chain_policy_smoke.py 2
```

The script builds the one test target, exports artifacts into a private
temporary directory, then starts a fresh process for each policy arm. It
alternates arm order across two passes. The heap arm loads the key and SRS
eagerly. The mapped arm requests mapped key and SRS plus forced coset spill;
`MIDNIGHT_BENCH_REQUIRE_SPILL=1` makes a missing spill fail the test. Both
proofs verify against the exported verifier key. Artifacts and spill files are
removed when the script exits.

Two passes ran consecutively on 2026-11-13 on macOS 26.2, Apple M2 Max arm64,
rustc 1.98.1. All times are milliseconds. Sampled RSS at the key-loaded pause
is the process's `ps` RSS after policy key loading and before SRS provider
construction or proving. The process peak is `wait4`'s `ru_maxrss` over the
entire measured child, including setup, key load, proof and verification.

| Pass | Arm | Key load ms | Key-loaded RSS MiB | Prove ms | Peak process RSS MiB | Max sampled open spill bytes |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | heap | 1,038.627 | 467.8 | 5,728.153 | 650.5 | 0 |
| 1 | mapped | 468.989 | 332.7 | 6,691.885 | 705.6 | 407,896,064 |
| 2 | mapped | 463.840 | 332.7 | 6,617.598 | 676.5 | 407,896,064 |
| 2 | heap | 1,214.630 | 466.6 | 8,949.800 | 647.2 | 0 |

The mapped key-load checkpoint used less sampled RSS in both passes. The
mapped/spill arm had a higher **whole-process** RSS peak in both passes; this
benchmark therefore makes no end-to-end RSS improvement claim at `k=15`.
Prove time also varied, notably in the second heap pass, so these samples do
not establish a throughput ordering. `lsof` sampled open files in the private
spill directory every roughly 20 ms; 64–65 nonzero scans were observed in
each mapped pass. The 407,896,064-byte figure is an observed lower bound on
peak live spill disk bytes, not an exact allocation peak. It excludes the
published SRS companion and treats a zero observation as inconclusive.
macOS RSS counts touched file-backed mappings; it is not a measurement of
evictable versus private physical footprint or a mobile-device envelope.

The benchmark covers one V3 high-k circuit and the released V2/V3 `k=4`
fixture smoke covers both versions. It does not replace the broader
cross-version and storage-failure negatives in ledger issue #30.
