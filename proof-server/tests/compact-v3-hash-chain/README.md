# Ledger9 ZKIR v3 hash-chain probe

`hash-and-increment.compact` was compiled with Compact 0.36.1
(`7fa3a117c`, Ledger target `zkir-3.2.1`):

```sh
compact compile +0.36.1 --skip-zk hash-and-increment.compact generated
cmp generated/zkir/hashAndIncrement.zkir hashAndIncrement.zkir
```

The IR is ZKIR 3.1. Its 17 persistent hashes and counter impact give the
ZKIR 3.2.1 cost model `k=15`, 32,185 rows. The cost-model test is cheap;
the proof timing test is ignored by default because it generates its own
parameters and proves twice. Run it explicitly from the Ledger workspace:

```sh
cargo test -p midnight-proof-server --test zkir3_mapped_params \
  compact_generated_zkir3_hash_chain_proof_timing --locked -- \
  --ignored --exact --nocapture
MIDNIGHT_SPILL_COSETS=1 MIDNIGHT_SPILL_FLOOR_K=0 \
  MIDNIGHT_BENCH_REQUIRE_SPILL=1 \
  cargo test -p midnight-proof-server --test zkir3_mapped_params \
  compact_generated_zkir3_hash_chain_proof_timing --locked -- \
  --ignored --exact --nocapture
```

On an Apple M2 Max, one debug-profile run at the pinned proofs 0.8.2
revision `397b2424` measured 7.36 s heap / 5.84 s mapped with the
default spill policy, then 7.04 s heap / 6.20 s mapped with forced spill.
Both paths produced 5,392-byte proofs that verified. The proofs were not
byte-identical. These are single samples, with setup, key generation, and
companion creation excluded from the timers.

In a separate forced-spill run of the same test, macOS `wait4` reported
1,045,184,512 bytes of peak process RSS (about 997 MiB). A 20 ms `ps` poll
observed 1,020,688 KiB. Sampling the process's mapped tempfiles with
`lsof -p <test-pid> -F ns` observed at most 41,943,040 bytes (40 MiB) of
spill files alive together: two files, the larger 33,554,432 bytes. The
files use `tempfile_in` and are unlinked immediately, so listing
`MIDNIGHT_SPILL_DIR` is **not** a spill measurement. This is an observed
peak for a process that performs setup and both proof arms in sequence;
it does not isolate heap versus mapped RSS or establish throughput.

The opt-in context route was remeasured locally at Ledger
`8893f38233fa3b5e2af433496785f2a742a93bd1`, ZKIR
`ac515dd1a65aa43cca859e3579df35beb3059d2d`, and stdlib
`b32d4fdcd6d4af32b9f37466f7b799a96020ae65` with the same pinned
proofs 0.8.2 SHA. On an Apple M2 Max (macOS 26.2, rustc 1.90.0, debug
profile), the ignored test was built with `--features zkir3-context` and
the two local Cargo path patches in `docs/ledger9-local-sync.md`, then its
test binary was run directly with `MIDNIGHT_SPILL_COSETS=1`,
`MIDNIGHT_SPILL_FLOOR_K=0`, `MIDNIGHT_BENCH_REQUIRE_SPILL=1`, and a private
`MIDNIGHT_SPILL_DIR`. Three sequential runs produced verified 5,392-byte
proofs: 7.38/6.11 s, 7.24/6.15 s, and 7.45/6.32 s for
heap-parameter/mapped-parameter proving respectively. `wait4` measured
whole-process peaks of 1,037,156,352, 1,046,462,464, and 1,037,090,816
bytes. The second and third runs sampled `ps` and `lsof -p <pid> -F ns`
with 20 ms sleeps. Each observed at most 41,943,040 bytes (8 MiB + 32 MiB)
across **unique named** spill files. Counting duplicate `lsof` entries for
the same file overstated the first run's spill sample, so that value is
excluded. The third run used `measure-spill.py`, which also reported
1,012,784 KiB sampled peak RSS over 163 samples. These are whole-process
observations including setup and both proving arms. They do not establish
per-arm peak memory, throughput, or an upper bound on spill files between
samples.

The later explicit key-policy route was measured once at Ledger `0aea7392`,
ZKIR `f928517`, stdlib `bb67a88b`, and the same pinned proofs 0.8.2 SHA,
with the same host and forced-spill script. The verified 5,392-byte proof
required 7.49 s for the heap-parameter arm and 8.01 s for the mapped-parameter
arm. `wait4` recorded 1,314,029,568 bytes whole-process peak RSS; sampling
observed 1,283,232 KiB RSS and 41,943,040 bytes in two unique live spill
files over 189 samples. The explicit path now reloads the serialized key under
its own policy. This test first proves with a heap key and retains its
initialized resolver key, so its process peak cannot isolate the mapped key's
memory effect or establish a comparable one-arm baseline. The one-run timing
suggests a key-load cost and does not establish a throughput distribution.

To repeat the measurement, build the ignored test with `--no-run`,
`--features zkir3-context`, and the two Cargo path patches from
`docs/ledger9-local-sync.md`. Pass the printed test executable path to
`python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary>`.
The script sets the forced-spill variables, creates and removes a private
spill directory, samples live files by unique name, and prints the test
result plus a JSON measurement record. Remove the disposable Cargo target
after recording the run.

## One-arm key-policy comparison

The ignored `compact_generated_zkir3_hash_chain_context_only` test isolates
one explicit-context proof per process. It serializes the generated key to a
private file, drops the initialized key, then resolves the serialized key for
proving. Both modes use the same mapped parameters, Compact IR, witness,
forced coset-spill floor (`k=0`), and private spill directory. The default
maps the proving key; `--heap-key` changes only the key-storage policy.
Build with `--features zkir3-context` and the two local path patches, then run:

```sh
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_context_only
python3 proof-server/tests/compact-v3-hash-chain/measure-spill.py <test-binary> \
  --test-name compact_generated_zkir3_hash_chain_context_only --heap-key
```

At local Ledger base `d3b5fae2` plus this one-arm fixture, ZKIR `f928517`,
stdlib `bb67a88b`, and pinned proofs 0.8.2, the mapped-key mode verified a
5,392-byte proof in 7.20 and 7.17 s in two processes. `wait4` peak process
RSS was 875,986,944 and 858,947,584 bytes; sampled live spill files peaked
at 303,038,464 bytes in each. The matched heap-key mode verified in 6.94 s,
with 643,137,536 bytes peak RSS and 41,943,040 bytes sampled live spill.
All three processes include setup and key generation in their RSS peak. The
comparison shows that mapping this `k=15` key increases observed RSS and
tempfile use; RSS includes file-backed pages and does not measure private
physical footprint. These few samples do not justify enabling mapped keys
for small circuits or claim a high-`k` result. The earlier two-arm samples
above retain both keys and should not be used for this policy comparison.
