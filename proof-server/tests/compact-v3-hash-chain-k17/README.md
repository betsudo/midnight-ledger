# Ledger9 ZKIR v3 k=17 memory probe

`hash-and-increment.compact` chains 50 persistent hashes and increments a
ledger counter. Compact 0.36.1 (`7fa3a117c`, Ledger target `zkir-3.2.1`)
generated `hashAndIncrement.zkir` with `--skip-zk`. The ZKIR 3.2.1 cost model
reports **k=17, 94,324 rows**; the non-ignored cost-model test checks this.
The source and IR SHA-256 hashes are `57eea3b5f1409c87cd166a86e766602aeb3083c0fed118561e16bd6406dd27c5`
and `4218edf8a9959073ff64887983c109572ad11e1704de5d9385ad7c3d7d82011d`.

Reproduce the IR from this directory with:

```sh
compact compile +0.36.1 --skip-zk hash-and-increment.compact generated
cmp generated/zkir/hashAndIncrement.zkir hashAndIncrement.zkir
```

The ignored `compact_generated_zkir3_hash_chain_k17_context_only` test runs one
explicit-context proof per process. It creates synthetic parameters and keys,
serializes and drops the generated key, loads that key through the v3 resolver,
uses the same immutable mapped parameter companion in every arm, and verifies
the resulting 5,392-byte proof. The `--heap-key` option selects heap rather
than mapped key storage; `--no-coset-spill` disables the otherwise forced coset
spill. Build with proof-server feature `zkir3-context` and both local Cargo path
patches shown in `docs/ledger9-local-sync.md`, then run the ignored test through
the adjacent `compact-v3-hash-chain/measure-spill.py` script:

```sh
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k17_context_only
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k17_context_only --heap-key
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_k17_context_only --heap-key --no-coset-spill
```

## Local measurements

Apple M2 Max with 96 GiB RAM, macOS 26.2, rustc 1.98.1, Cargo debug/test
profile. Ledger base `57f156dd` plus this fixture, ZKIR `8c93bf7`, stdlib
`bb67a88b`, and the Ledger-pinned optimized proofs 0.8.2 revision
`397b2424`. Each row is a separate test process. The run order was mapped,
heap, heap, mapped, then heap without coset spill. All five proofs verified.

| Key / cosets | Proof seconds | Sampled peak RSS during proof (KiB) | `wait4` process peak RSS (bytes) | Peak sampled live spill (bytes) |
| --- | ---: | ---: | ---: | ---: |
| mapped / spill | 37.09 | 2,269,024 | 2,323,480,576 | 1,212,153,856 |
| heap / spill | 34.46 | 2,603,008 | 2,665,480,192 | 167,772,160 |
| heap / spill | 27.67 | 2,499,472 | 2,559,459,328 | 167,772,160 |
| mapped / spill | 30.23 | 2,287,168 | 2,342,060,032 | 1,212,153,856 |
| heap / no spill | 27.22 | 2,376,592 | 2,433,630,208 | 0 |

The script samples `ps` RSS and deduplicated `lsof` file names during a
test-marked proving phase, and uses `wait4` for whole-process peak RSS. The
spill count includes mapped-key and coset files in the private spill directory;
it does not identify which pages were resident. Both mapped-key runs used
about 1,156 MiB of sampled live spill versus 160 MiB for heap-key runs with
coset spill. Paired mapped-key runs used 207–326 MiB less sampled RSS than
heap-key runs with the same coset policy, while taking about 2.6 seconds more
for `prove_with_context` in each pair. Setup and key generation are outside
that timer but inside the `wait4` process measurement.

The heap/no-spill sample used 2,321 MiB sampled proof-phase RSS, close to or
below the two heap/spill samples. This is below the default coset-spill floor
of k=18, so the data do not support forcing coset spill at k=17. They also do
not establish k=18 or k=20 behavior, throughput under load, private physical
footprint, or a statistical speed result. RSS counts mapped pages; `lsof`
sampling can miss short-lived files. The script keeps all test tempfiles in a
private directory, imposes a 20-minute ceiling per process, and removes that
directory on exit.
