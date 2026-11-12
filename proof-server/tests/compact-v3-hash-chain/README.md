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
