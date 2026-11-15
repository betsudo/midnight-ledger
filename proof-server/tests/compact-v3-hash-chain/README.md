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
parameters and, without a policy selector, proves twice. Run it explicitly
from the Ledger workspace:

```sh
cargo test -p midnight-proof-server --features native-memory --test zkir3_mapped_params \
  compact_generated_zkir3_hash_chain_proof_timing --locked -- \
  --ignored --exact --nocapture
```

The current release-base proof policy is explicit per request. This timing
test compares the released heap path with mapped SRS, mapped proving-key
columns, and forced coset spill (`coset_spill_floor_k = 0`). Both proofs are
verified. Setup, key generation, and companion creation are excluded from the
reported proof durations. The two proofs run in one process, which retains
the heap key in its test resolver, so its process peak RSS cannot isolate the
native-memory policy's savings. A separate-process measurement with released
keys and device-specific repeats is required before claiming a memory or
latency improvement.

For process RSS, first compile the test, then run its executable directly so
the compiler is outside the measurement. On macOS, repeat this command in
separate processes and retain the `maximum resident set size` output:

```sh
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=.codex-target \
  cargo test --offline --locked -p midnight-proof-server \
  --features native-memory --test zkir3_mapped_params --no-run
test_bin=$(find .codex-target/debug/deps -maxdepth 1 -type f -perm -111 \
  -name 'zkir3_mapped_params-*' -print -quit)
RUST_TEST_THREADS=1 /usr/bin/time -l "$test_bin" \
  compact_generated_zkir3_hash_chain_proof_timing \
  --ignored --exact --nocapture
```

Three debug-profile runs on an Apple M2 Max with Rust 1.98.1, Ledger base
`3307205e`, ZK `a63bd8b5`, and ZKIR `48194a47` produced:

| Run | Heap proof | Mapped SRS/key + forced coset spill proof | Whole-process peak RSS |
|---|---:|---:|---:|
| 1 | 5.825 s | 6.170 s | 1,288,896,512 bytes |
| 2 | 5.842 s | 6.313 s | 1,303,609,344 bytes |
| 3 | 5.832 s | 6.346 s | 1,332,363,264 bytes |

Both proofs verified in every run; the logged heap proof was 5,392 bytes and
the proof bytes differed.
The default spill floor is `k=18`, so this `k=15` forced-spill probe measures
the policy path under stress, not its default selection. Median proof times
were 5.832 s heap and 6.313 s mapped/spilled. The process RSS includes setup,
key generation, a retained heap key, and both proofs, so it is not a comparison
of the policies' peak memory. This result does not qualify the optimization's
memory benefit or a high-k performance claim.

On an Apple M2 Max, one historical debug-profile run at the pinned proofs 0.8.2
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

## One policy per process

Set `MIDNIGHT_V3_BENCH_POLICY=heap` or `mapped` to run only that proof arm in
each process. The mapped arm forces coset spill at `k=15`; set
`MIDNIGHT_BENCH_REQUIRE_SPILL=1` to make a failed requested spill fatal. Use
the same built executable from the command above, once per policy:

```sh
MIDNIGHT_V3_BENCH_POLICY=heap /usr/bin/time -l "$test_bin" \
  compact_generated_zkir3_hash_chain_proof_timing --ignored --exact --nocapture
MIDNIGHT_V3_BENCH_POLICY=mapped MIDNIGHT_BENCH_REQUIRE_SPILL=1 \
  /usr/bin/time -l "$test_bin" \
  compact_generated_zkir3_hash_chain_proof_timing --ignored --exact --nocapture
```

At local Ledger `codex/ledger9-v3-process-probe-082`, based on `5327beb1`,
ZK `44250791`, and ZKIR `c14aaf3`, three separate processes per policy on an
Apple M2 Max (Rust 1.98.1, debug symbols disabled) verified 5,392-byte V3
proofs:

| Policy | Proof duration, seconds | Whole-process peak RSS, bytes |
|---|---|---|
| Heap | 5.969 / 6.089 / 6.391 | 909,590,528 / 915,210,240 / 909,737,984 |
| Mapped SRS/key + forced coset spill | 6.501 / 6.422 / 6.336 | 962,904,064 / 945,766,400 / 943,898,624 |

Median proof duration was 6.089 s heap versus 6.422 s mapped/spilled. Median
whole-process RSS was 909,737,984 versus 945,766,400 bytes. An additional
mapped run passed with the required-spill guard. Both policies still generate
parameters and a heap key before proving, and the resolver retains that key.
Thus even these separate-process peaks include shared setup and cannot isolate
the proof-phase memory effect. The circuit also lies below the normal `k=18`
spill floor. This evidence shows a slower forced-spill path at this size; it
does not qualify a high-k memory benefit.
