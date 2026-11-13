# Ledger9 ZKIR v2/v3 policy comparison

`v2_v3_assert_policy.rs` constructs two IRs at runtime. Each asserts the same
public scalar is nonzero 16,384 times. The in-tree ZKIR v2 2.2.0 and external
ZKIR v3 3.3.0 models both report **k=15, 16,386 rows**. This makes a small,
exactly matched logical and cost-model class for comparing the two Ledger9
routes. The fixture uses no Ledger8 compiler or source. It complements the
Compact-generated v3 hash-chain fixture; it is not a production workload.

The ignored `compare_assert_policy` test generates the same synthetic seeded
KZG parameters in each process, generates a key, proves, and verifies. The
sampler sets the compatibility process policy before the test starts:
`heap` uses heap key and cosets; `mapped-spill` sets `MIDNIGHT_MAP_PK=1`,
`MIDNIGHT_SPILL_COSETS=1`, and spill floor k=0. It keeps the SRS on the heap
in both policies, so these measurements isolate the mapped-key and coset
spill path, not the mapped SRS provider. The existing Compact v3 tests cover
the mapped SRS provider and opt-in request context separately.

Build with `zkir3-context` and temporary local ZK/ZKIR Cargo path patches as
described in `docs/ledger9-local-sync.md`, then run one arm per process:

```sh
python3 proof-server/tests/v2-v3-assert/measure.py <test-binary> \
  --version v2 --policy heap
python3 proof-server/tests/v2-v3-assert/measure.py <test-binary> \
  --version v3 --policy heap
python3 proof-server/tests/v2-v3-assert/measure.py <test-binary> \
  --version v2 --policy mapped-spill
python3 proof-server/tests/v2-v3-assert/measure.py <test-binary> \
  --version v3 --policy mapped-spill
```

## Local observations, 2026-11-13

Apple M2 Max, 96 GiB RAM, macOS 26.2, rustc 1.98.1, Cargo test profile.
Sources: Ledger candidate base `324c1592`, ZK proofs/stdlib `962bb214`,
external ZKIR v3 `e0e08f7`. Temporary Cargo patches resolved one proofs
0.8.3 implementation for both paths. Every row is a separate process and
verified a 2,548-byte proof. The run order was v2 mapped, v3 mapped, v3
mapped, v2 mapped, v2 heap, v3 heap.

| IR / policy | Keygen s | Prove s | Sampled proof peak RSS KiB | Whole-process peak RSS bytes | Sampled live proof spill bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| v2 / mapped-spill 1 | 7.351 | 1.307 | 757,520 | 775,700,480 | 232,783,872 |
| v3 / mapped-spill 1 | 1.410 | 1.036 | 745,184 | 763,150,336 | 232,783,872 |
| v3 / mapped-spill 2 | 1.384 | 0.992 | 740,320 | 758,087,680 | 232,783,872 |
| v2 / mapped-spill 2 | 3.106 | 0.974 | 783,968 | 802,783,232 | 220,200,960 |
| v2 / heap | 3.078 | 0.656 | 701,824 | 718,684,160 | 0 |
| v3 / heap | 1.341 | 0.654 | 699,296 | 716,079,104 | 0 |

The six adjacent JSON files preserve all samples and test output. Both
mapped-spill versions showed 52,428,800 bytes of live keygen files; the proof
spill values above vary with `lsof` sampling. `ps` RSS includes file-backed
mapped pages, so the mapped-spill arm can report more RSS than heap even if
private physical memory is lower. Whole-process peaks include SRS setup and
keygen. V2 keygen timing varied between two runs; these samples establish
reproducible proof correctness and policy activation, not a cross-version
speed ranking or a default spill policy. They do not cover production SRS,
mapped-SRS behavior, browser runtime, disk capacity, or concurrent load.
