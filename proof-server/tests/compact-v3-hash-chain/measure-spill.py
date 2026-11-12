#!/usr/bin/env python3
"""Measure one ignored ZKIR v3 hash-chain proof test on macOS.

Build the focused test binary with the desired Cargo patches and features,
then pass its path here. The temporary spill directory and captured test log
are removed when this process exits.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def named_spill_files(output: str, spill_dir: Path) -> dict[str, int]:
    entries: dict[str, int] = {}
    name = ""
    size = 0
    for line in output.splitlines() + ["f"]:
        if line.startswith("f"):
            if str(spill_dir) in name:
                entries[name] = size
            name = ""
            size = 0
        elif line.startswith("n"):
            name = line[1:]
        elif line.startswith("s"):
            try:
                size = int(line[1:])
            except ValueError:
                pass
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_binary", type=Path)
    parser.add_argument(
        "--test-name",
        default="compact_generated_zkir3_hash_chain_proof_timing",
        help="exact ignored test to measure",
    )
    parser.add_argument(
        "--heap-key",
        action="store_true",
        help="use heap key storage in the context-only test",
    )
    parser.add_argument(
        "--no-coset-spill",
        action="store_true",
        help="disable coset spill in the context-only test",
    )
    parser.add_argument(
        "--max-wall-seconds",
        type=float,
        default=1200.0,
        help="kill a proof that exceeds this wall-time bound (default: 1200)",
    )
    args = parser.parse_args()
    if args.max_wall_seconds <= 0:
        parser.error("--max-wall-seconds must be positive")
    binary = args.test_binary.resolve()
    if sys.platform != "darwin":
        parser.error("this probe reports wait4 RSS in macOS bytes")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"not an executable test binary: {binary}")
    if not shutil.which("lsof") or not shutil.which("ps"):
        parser.error("lsof and ps are required")

    with tempfile.TemporaryDirectory(prefix="midnight-zkir3-spill-") as directory:
        spill_dir = Path(directory) / "spill"
        temp_dir = Path(directory) / "tmp"
        phase_file = Path(directory) / "phase"
        spill_dir.mkdir()
        temp_dir.mkdir()
        env = os.environ.copy()
        env.update(
            TMPDIR=str(temp_dir),
            MIDNIGHT_BENCH_PHASE_FILE=str(phase_file),
            MIDNIGHT_SPILL_COSETS="1",
            MIDNIGHT_SPILL_FLOOR_K="0",
            MIDNIGHT_BENCH_REQUIRE_SPILL="1",
            MIDNIGHT_SPILL_DIR=str(spill_dir),
        )
        if args.heap_key:
            env["MIDNIGHT_BENCH_HEAP_KEY"] = "1"
        else:
            env.pop("MIDNIGHT_BENCH_HEAP_KEY", None)
        if args.no_coset_spill:
            env["MIDNIGHT_SPILL_COSETS"] = "0"
            env["MIDNIGHT_BENCH_REQUIRE_SPILL"] = "0"
            env["MIDNIGHT_BENCH_NO_COSET_SPILL"] = "1"
        else:
            env.pop("MIDNIGHT_BENCH_NO_COSET_SPILL", None)
        with tempfile.TemporaryFile(mode="w+t") as log:
            process = subprocess.Popen(
                [
                    str(binary),
                    args.test_name,
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
            start = time.monotonic()
            sampled_peak_rss_kib = 0
            sampled_peak_spill_bytes = 0
            proof_peak_rss_kib = 0
            proof_peak_spill_bytes = 0
            proof_samples = 0
            peak_spill_sizes: list[int] = []
            samples = 0
            timed_out = False
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() - start > args.max_wall_seconds:
                    timed_out = True
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                ps = subprocess.run(
                    ["ps", "-o", "rss=", "-p", str(process.pid)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                try:
                    current_rss_kib = int(ps.stdout.strip())
                    sampled_peak_rss_kib = max(sampled_peak_rss_kib, current_rss_kib)
                except ValueError:
                    current_rss_kib = 0
                files = subprocess.run(
                    ["lsof", "-p", str(process.pid), "-F", "ns"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                entries = named_spill_files(files.stdout, spill_dir)
                spill_bytes = sum(entries.values())
                if spill_bytes > sampled_peak_spill_bytes:
                    sampled_peak_spill_bytes = spill_bytes
                    peak_spill_sizes = sorted(entries.values())
                if phase_file.is_file() and phase_file.read_text() == "prove":
                    proof_samples += 1
                    proof_peak_rss_kib = max(proof_peak_rss_kib, current_rss_kib)
                    proof_peak_spill_bytes = max(proof_peak_spill_bytes, spill_bytes)
                samples += 1
                time.sleep(0.02)

            log.seek(0)
            output = log.read()
            print(output, end="")
            print(
                json.dumps(
                    {
                        "exit_code": process.returncode,
                        "timed_out": timed_out,
                        "wall_seconds": round(time.monotonic() - start, 3),
                        "wait4_peak_rss_bytes": usage.ru_maxrss,
                        "sampled_peak_rss_kib": sampled_peak_rss_kib,
                        "sampled_peak_spill_bytes": sampled_peak_spill_bytes,
                        "proof_peak_rss_kib": proof_peak_rss_kib,
                        "proof_peak_spill_bytes": proof_peak_spill_bytes,
                        "proof_samples": proof_samples,
                        "peak_spill_file_sizes": peak_spill_sizes,
                        "samples": samples,
                    },
                    sort_keys=True,
                )
            )
            return 124 if timed_out else process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
