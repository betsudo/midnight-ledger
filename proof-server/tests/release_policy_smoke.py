#!/usr/bin/env python3
"""Measure the released Ledger9 V2/V3 fixture under separate proof policies.

Run from any directory with Python 3, Cargo, and lsof installed. The script
builds the two existing compatibility tests once, then executes each policy
arm in its own process. The figures are a small-circuit smoke baseline, not a
high-k or mobile memory claim.
"""

import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
TESTS = {
    "v2": ("release_v2_compat", "released_v2_proof_and_key_remain_usable"),
    "v3": ("release_v3_compat", "released_v3_proof_and_key_remain_usable"),
}


def build_test(target):
    command = [
        "cargo", "test", "--locked", "--offline", "-p", "midnight-proof-server",
        "--test", target, "--no-run", "--message-format=json",
    ]
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if process.returncode:
        sys.stderr.write(process.stderr)
        raise RuntimeError(f"build failed for {target}")
    executables = []
    for line in process.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == target:
            if item.get("executable"):
                executables.append(item["executable"])
    if len(executables) != 1:
        raise RuntimeError(f"expected one executable for {target}, found {executables}")
    return executables[0]


def open_spill_bytes(pid, directory):
    output = subprocess.run(
        ["lsof", "-n", "-P", "-p", str(pid), "-F", "sn"],
        capture_output=True, text=True, check=False,
    ).stdout
    names = (str(directory), str(directory.resolve()))
    total = 0
    size = None
    for line in output.splitlines():
        if line.startswith("f"):
            size = None
        elif line.startswith("s"):
            try:
                size = int(line[1:])
            except ValueError:
                size = None
        elif line.startswith("n") and size is not None and any(name in line for name in names):
            total += size
    return total


def measure(version, arm, binary, test_name, repetitions):
    with tempfile.TemporaryDirectory(prefix=f"ledger9-{version}-{arm}-") as temp:
        spill_dir = Path(temp)
        env = os.environ.copy()
        env.update({
            "MIDNIGHT_RELEASE_BENCH_ARM": arm,
            "MIDNIGHT_RELEASE_BENCH_REPETITIONS": str(repetitions),
            "MIDNIGHT_RELEASE_BENCH_SPILL_DIR": str(spill_dir),
            "MIDNIGHT_SPILL_DIR": str(spill_dir),
            "MIDNIGHT_SPILL_PK": "1" if arm == "mapped" else "0",
            "MIDNIGHT_SPILL_COSETS": "1" if arm == "mapped" else "0",
            "MIDNIGHT_SPILL_FLOOR_K": "0",
            "MIDNIGHT_BENCH_REQUIRE_SPILL": "1",
        })
        with tempfile.TemporaryFile(mode="w+t") as log:
            start = time.monotonic()
            process = subprocess.Popen(
                [binary, "--exact", test_name, "--nocapture"],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
            )
            peak_spill = 0
            scans_with_spill = 0
            while True:
                peak = open_spill_bytes(process.pid, spill_dir)
                peak_spill = max(peak_spill, peak)
                scans_with_spill += peak > 0
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.05)
            wall_ms = (time.monotonic() - start) * 1_000
            log.seek(0)
            output = log.read()
            if process.returncode:
                sys.stderr.write(output)
                raise RuntimeError(f"{version}/{arm} fixture failed")
            match = re.search(
                rf"release-{version} k=([0-9]+) arm={arm} repetitions={repetitions} prove_ms=([0-9.]+)",
                output,
            )
            if not match:
                raise RuntimeError(f"{version}/{arm} emitted no proof duration: {output}")
            rss_bytes = usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024
            return {
                "version": version,
                "k": int(match.group(1)),
                "arm": arm,
                "repetitions": repetitions,
                "prove_ms_total": float(match.group(2)),
                "wall_ms": round(wall_ms, 3),
                "peak_rss_bytes": rss_bytes,
                "peak_open_spill_bytes_sampled": peak_spill,
                "scans_with_spill": scans_with_spill,
            }


def main():
    repetitions = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    binaries = {version: build_test(target) for version, (target, _) in TESTS.items()}
    results = []
    for version, (_, test_name) in TESTS.items():
        for arm in ("heap", "mapped"):
            result = measure(version, arm, binaries[version], test_name, repetitions)
            results.append(result)
            print(json.dumps(result), flush=True)
    cpu_model = subprocess.run(
        ["sysctl", "-n", "machdep.cpu.brand_string"],
        capture_output=True, text=True, check=False,
    ).stdout.strip() if platform.system() == "Darwin" else platform.processor()
    print(json.dumps({
        "host": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu_model,
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "results": results,
        "spill_measurement": "sampled open file sizes; zero observed is inconclusive",
    }, indent=2))


if __name__ == "__main__":
    main()
