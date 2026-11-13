# Ledger9 ZKIR v3 k=18 memory probe

`hash-and-increment.compact` chains 78 persistent hashes and increments a
ledger counter. Compact 0.36.1 (`7fa3a117c`, Ledger target `zkir-3.2.1`)
generated `hashAndIncrement.zkir` with `--skip-zk`. The ZKIR 3.2.1 cost model
reports **k=18, 147,048 rows**; the non-ignored cost-model test checks this.
The source and IR SHA-256 hashes are
`0bd96db61cc243c43f9775e8689ef903dac4457e8d5a3c62e507718a8add43ed` and
`47ad5040afa543f1846b7ae1a378db4b8ea900103609d0e6206238125d039abb`.

Reproduce the IR from this directory with:

```sh
compact compile +0.36.1 --skip-zk hash-and-increment.compact generated
cmp generated/zkir/hashAndIncrement.zkir hashAndIncrement.zkir
```

The ignored `compact_generated_zkir3_hash_chain_k18_context_only` test runs one
explicit-context proof per process. It creates synthetic parameters and keys,
serializes and drops the generated key, loads that key through the v3 resolver,
uses the same immutable mapped parameter companion in every arm, and verifies
the 5,392-byte proof. `--heap-key` selects heap key storage;
`--no-coset-spill` disables coset spill. Build the test with proof-server feature
`zkir3-context` and both local Cargo path patches in `docs/ledger9-local-sync.md`,
then run each arm through the adjacent `compact-v3-hash-chain/measure-spill.py`:

```sh
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k18_context_only --spill-floor-k 18
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k18_context_only --spill-floor-k 18 --heap-key
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k18_context_only --spill-floor-k 18 --heap-key --no-coset-spill
```

## Local measurements

Apple M2 Max with 96 GiB RAM, macOS 26.2, rustc 1.98.1, Cargo debug/test
profile. Ledger base `483a842c` plus this fixture, ZKIR `8c93bf7`, stdlib
`bb67a88b`, and Ledger-pinned optimized proofs 0.8.2 revision `397b2424`.
Each row is a separate process. The run order below is chronological. All six
proofs verified. The spill floor was k=18 for every arm; the no-spill arms
explicitly disabled coset spill.

| Key / cosets | Proof seconds | Sampled peak RSS during proof (KiB) | `wait4` process peak RSS (bytes) | Peak sampled live spill (bytes) |
| --- | ---: | ---: | ---: | ---: |
| heap / no spill | 54.18 | 4,287,712 | 4,399,054,848 | 0 |
| heap / spill | 55.62 | 4,582,960 | 4,692,967,424 | 335,544,320 |
| mapped / spill | 59.09 | 4,373,376 | 4,511,891,456 | 2,424,307,712 |
| heap / spill | 55.76 | 4,656,368 | 4,768,120,832 | 335,544,320 |
| heap / no spill | 56.35 | 4,754,592 | 4,868,702,208 | 0 |
| mapped / spill | 59.18 | 4,324,032 | 4,427,808,768 | 2,424,307,712 |

The script samples `ps` RSS and deduplicated `lsof` file names during a
test-marked proving phase, and uses `wait4` for whole-process peak RSS. Spill
counts include mapped-key and coset files in a private directory; they are
file lengths, not resident pages. The mapped-key samples used 205–325 MiB less
sampled proof RSS than the adjacent heap-key/spill samples and about 1,992 MiB
more sampled live spill. Their proof calls took 3.3–3.6 seconds longer.

The two heap/no-spill samples straddled both heap/spill samples in RSS. The
coset-spill benefit at the default k=18 floor is therefore inconclusive from
these runs; no default-policy change follows. This is a single circuit on one
host, not a throughput, private physical footprint, disk-capacity, or k=20
qualification. RSS counts mapped pages, and `lsof` sampling can miss
short-lived files. The script imposes a 20-minute ceiling per process and
removes each private temporary directory on exit.

## Exploratory local proofs 0.8.3 stack

On 2026-11-13, the same fixture passed its k=18 / 147,048-row cost-model
test and three explicit-context proof arms against local proofs `8c2459bd`,
ZKIR v3 `9976f4c`, and Ledger `5df112d6` (plus a documentation-only
follow-up at `a5c09a49`). Cargo resolved those source
heads through temporary path patches; this is not the released Ledger9
dependency graph. The host was the same Apple M2 Max with 96 GiB RAM,
macOS 26.2, and rustc 1.98.1. All arms used synthetic seeded parameters,
the mapped parameter companion, and the `measure_context.py --vmmap`
sampler; both spill arms selected floor k=0. All proofs verified at 4,164
bytes.
After building `zkir3_mapped_params` with `zkir3-context` and the local path
patches described in `docs/ledger9-local-sync.md`, run one policy per process:

```sh
python3 proof-server/tests/compact-v3-hash-chain/measure_context.py <test-binary> \
  --policy heap --vmmap --test-name compact_generated_zkir3_hash_chain_k18_context_only
python3 proof-server/tests/compact-v3-hash-chain/measure_context.py <test-binary> \
  --policy mapped --vmmap --test-name compact_generated_zkir3_hash_chain_k18_context_only
python3 proof-server/tests/compact-v3-hash-chain/measure_context.py <test-binary> \
  --policy heap --no-coset-spill --vmmap \
  --test-name compact_generated_zkir3_hash_chain_k18_context_only
```

| Key / cosets | Proof seconds | Sampled proof peak RSS (KiB) | Whole-process peak RSS (bytes) | Reported peak physical footprint (bytes) | Peak sampled live spill (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| heap / spill | 136.36 | 4,922,128 | 5,040,259,072 | 3,543,348,019 | 2,315,255,808 |
| mapped / spill | 102.39 | 4,813,584 | 4,933,189,632 | 3,328,599,654 | 3,036,676,096 |
| heap / no spill | 105.68 | 4,612,416 | 4,755,128,320 | 4,509,715,660 | 0 |

The raw sampler results are in the adjacent `proofs-083-*.json` files.
In the two spill arms, mapped keys reduced sampled
proof RSS by 106 MiB and reported peak physical footprint by about 205 MiB,
while increasing sampled live spill by 688 MiB. These file lengths are not
resident pages. Relative to heap/spill, heap/no-spill used about 302 MiB less
sampled proof RSS but about 922 MiB more reported peak physical footprint
and no live spill files. RSS includes file-backed mapped pages, so these
two memory metrics can move in opposite directions. The reported
physical-footprint peak comes from repeated
`vmmap -summary` calls; that sampling perturbs proof timing, and one run per
arm cannot establish a latency difference. The test includes synthetic SRS
generation and keygen before its marked proof phase; whole-process peaks
cannot be attributed solely to proof execution. These three samples do not
qualify production SRS or load, disk capacity, or a default coset-spill policy
change.

## Explicit ZKIR v3 keygen policy probe (local 0.8.3 stack)

The later local candidate exposes an opt-in `Zkir::keygen_with_policy` through
ZKIR v3 and zk-stdlib. The compatibility `keygen` entry point remains in place.
The same Compact k=18 / 147,048-row fixture ran once per keygen policy on the
Apple M2 Max host above (macOS 26.2, Cargo test profile). Both arms used
synthetic seeded parameters and the **same mapped-key plus coset-spill proof
policy**, and both proofs verified at 4,164 bytes. The sampler now marks
keygen separately after SRS setup and observes its configured spill directory.

```sh
python3 proof-server/tests/compact-v3-hash-chain/measure_context.py <test-binary> \
  --policy mapped --test-name compact_generated_zkir3_hash_chain_k18_context_only
python3 proof-server/tests/compact-v3-hash-chain/measure_context.py <test-binary> \
  --policy mapped --keygen-mapped \
  --test-name compact_generated_zkir3_hash_chain_k18_context_only
```

| Keygen policy | Keygen seconds | Sampled keygen peak RSS (KiB) | Sampled live keygen spill (bytes) | Whole-process peak RSS (bytes) |
| --- | ---: | ---: | ---: | ---: |
| heap | 14.03 | 3,270,160 | 0 | 4,977,229,824 |
| mapped | 23.16 | 2,934,336 | 721,420,288 | 4,810,047,488 |

The raw results are `proofs-083-heap-keygen-mapped-proof.json` and
`proofs-083-mapped-keygen-mapped-proof.json`. Mapped keygen saved 335,824 KiB
of sampled keygen RSS in this pair, with about 9.1 seconds more keygen time.
The whole-process peak includes setup and proving, and RSS includes file-backed
mapped pages. Live spill is sampled file length, not physical memory or final
disk usage. One run per arm does not establish repeatable latency, production
SRS behavior, or a release default. These source branches remain local; the
released Ledger9 dependency pin stays on optimized proofs 0.8.2.
