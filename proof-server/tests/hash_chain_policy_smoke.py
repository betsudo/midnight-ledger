#!/usr/bin/env python3
"""Measure the same Compact ZKIR V3 k=15 key/proof under two policies.

The script creates artifacts once in a private directory, then runs each arm
in its own test process. It performs two passes by default. It is a focused
host smoke benchmark, not a device envelope or broad proof matrix.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from release_policy_smoke import ROOT, build_test, open_spill_bytes


TEST = "compact_generated_zkir3_hash_chain_policy_benchmark"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def invoke(binary):
    return [binary, "--ignored", "--exact", TEST, "--nocapture"]


def export(binary, directory):
    env = os.environ.copy()
    env.update({
        "MIDNIGHT_HASH_BENCH_STAGE": "export",
        "MIDNIGHT_HASH_BENCH_ARTIFACT_DIR": str(directory),
    })
    process = subprocess.run(invoke(binary), cwd=ROOT, env=env,
                             capture_output=True, text=True)
    if process.returncode:
        sys.stderr.write(process.stdout + process.stderr)
        raise RuntimeError("hash-chain artifact export failed")
    if "hash-chain-bench stage=export k=15 rows=32185" not in process.stderr:
        raise RuntimeError("export did not report the expected circuit")
    return {
        name: {
            "bytes": (directory / name).stat().st_size,
            "sha256": sha256_file(directory / name),
        }
        for name in ("params.bin", "prover-key.bin", "verifier-key.bin")
    }


def rss_kib(pid):
    output = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)],
                            capture_output=True, text=True, check=False).stdout.strip()
    return int(output) if output.isdigit() else 0


def measure(binary, artifact_dir, pass_number, arm):
    with tempfile.TemporaryDirectory(prefix=f"hash-chain-{arm}-") as temp:
        spill_dir = Path(temp)
        marker = artifact_dir / f"key-loaded-{pass_number}-{arm}"
        ack = artifact_dir / f"key-ack-{pass_number}-{arm}"
        env = os.environ.copy()
        env.update({
            "MIDNIGHT_HASH_BENCH_STAGE": "prove",
            "MIDNIGHT_HASH_BENCH_ARTIFACT_DIR": str(artifact_dir),
            "MIDNIGHT_HASH_BENCH_ARM": arm,
            "MIDNIGHT_HASH_BENCH_SPILL_DIR": str(spill_dir),
            "MIDNIGHT_HASH_BENCH_KEY_LOADED_MARKER": str(marker),
            "MIDNIGHT_HASH_BENCH_KEY_LOADED_ACK": str(ack),
            "MIDNIGHT_BENCH_REQUIRE_SPILL": "1" if arm == "mapped" else "0",
        })
        with tempfile.TemporaryFile(mode="w+t") as log:
            start = time.monotonic()
            process = subprocess.Popen(invoke(binary), cwd=ROOT, env=env,
                                       stdout=log, stderr=subprocess.STDOUT)
            peak_keyload_rss_kib = 0
            key_loaded_rss_kib = 0
            peak_open_spill = 0
            spill_scans = 0
            acknowledged = False
            while True:
                current_rss = rss_kib(process.pid)
                if not acknowledged:
                    peak_keyload_rss_kib = max(peak_keyload_rss_kib, current_rss)
                    if marker.exists():
                        key_loaded_rss_kib = current_rss
                        ack.write_text("sampled")
                        acknowledged = True
                spill = open_spill_bytes(process.pid, spill_dir)
                peak_open_spill = max(peak_open_spill, spill)
                spill_scans += spill > 0
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.02)
            log.seek(0)
            output = log.read()
            if process.returncode:
                sys.stderr.write(output)
                raise RuntimeError(f"hash-chain {arm} proof failed")
            if not acknowledged:
                raise RuntimeError("key-loaded marker was not observed")
            match = re.search(
                rf"hash-chain-bench stage=prove arm={arm} k=15 rows=32185 "
                r"key_load_ms=([0-9.]+) prove_ms=([0-9.]+) proof_bytes=([0-9]+)",
                output,
            )
            if not match:
                raise RuntimeError(f"missing proof metrics: {output}")
            peak_rss_bytes = (usage.ru_maxrss if platform.system() == "Darwin"
                              else usage.ru_maxrss * 1024)
            return {
                "pass": pass_number,
                "arm": arm,
                "k": 15,
                "rows": 32185,
                "key_load_ms": float(match.group(1)),
                "prove_ms": float(match.group(2)),
                "proof_bytes": int(match.group(3)),
                "peak_keyload_rss_kib_sampled": peak_keyload_rss_kib,
                "key_loaded_rss_kib_sampled": key_loaded_rss_kib,
                "peak_process_rss_bytes": peak_rss_bytes,
                "peak_open_spill_bytes_sampled": peak_open_spill,
                "scans_with_spill": spill_scans,
                "wall_ms": round((time.monotonic() - start) * 1000, 3),
            }


def main():
    passes = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    if passes < 1:
        raise ValueError("passes must be positive")
    binary = build_test("zkir3_mapped_params")
    with tempfile.TemporaryDirectory(prefix="ledger9-hash-chain-") as temp:
        artifact_dir = Path(temp)
        artifacts = export(binary, artifact_dir)
        results = []
        for pass_number in range(1, passes + 1):
            arms = ("heap", "mapped") if pass_number % 2 else ("mapped", "heap")
            for arm in arms:
                result = measure(binary, artifact_dir, pass_number, arm)
                print(json.dumps(result), flush=True)
                results.append(result)
        print(json.dumps({
            "host": platform.platform(),
            "machine": platform.machine(),
            "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "source": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                               cwd=ROOT, text=True).strip(),
            "artifacts": artifacts,
            "results": results,
            "rss_measurement": "wait4 process peak; ps samples through key-load checkpoint",
            "spill_measurement": "sampled open files; zero observed is inconclusive",
        }, indent=2))


if __name__ == "__main__":
    main()
