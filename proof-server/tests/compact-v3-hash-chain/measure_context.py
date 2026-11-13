#!/usr/bin/env python3
"""Sample one ignored ZKIR v3 proof arm on macOS; no external Python packages."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import resource
import subprocess
import sys
import tempfile
import time


def rss_kib(pid: int) -> int | None:
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    value = result.stdout.strip()
    return int(value) if value.isdigit() else None


def spill_bytes(pid: int, spill_dir: Path) -> int | None:
    result = subprocess.run(
        ["lsof", "-w", "-p", str(pid), "-Ffns"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return None
    names = (str(spill_dir), str(spill_dir.resolve()))
    files: set[tuple[str, int]] = set()
    name = ""
    size = 0

    def record() -> None:
        if any(prefix in name for prefix in names):
            files.add((name, size))

    for line in result.stdout.splitlines():
        if line.startswith("f"):
            record()
            name, size = "", 0
        elif line.startswith("n"):
            name = line[1:]
        elif line.startswith("s") and line[1:].isdigit():
            size = int(line[1:])
    record()
    return sum(size for _, size in files)


def physical_footprint_bytes(pid: int) -> tuple[int, int] | None:
    result = subprocess.run(
        ["vmmap", "-summary", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return None

    def read(label: str) -> int | None:
        match = re.search(rf"^{re.escape(label)}:\s+([\d.]+)([KMG])", result.stdout, re.M)
        if not match:
            return None
        return int(float(match.group(1)) * 1024 ** {"K": 1, "M": 2, "G": 3}[match.group(2)])

    current = read("Physical footprint")
    peak = read("Physical footprint (peak)")
    return (current, peak) if current is not None and peak is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="compiled zkir3_mapped_params test binary")
    parser.add_argument("--policy", choices=("heap", "mapped"), required=True)
    parser.add_argument("--no-coset-spill", action="store_true")
    parser.add_argument("--vmmap", action="store_true", help="sample physical footprint; perturbs timing")
    parser.add_argument("--test-name", default="compact_generated_zkir3_hash_chain_context_only")
    parser.add_argument("--output", type=Path, help="optional JSON result file")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("this sampler uses macOS ps RSS and wait4 units")
    if not args.binary.is_file():
        parser.error(f"missing test binary: {args.binary}")

    with tempfile.TemporaryDirectory(prefix="midnight-v3-memory-") as temp:
        temp_dir = Path(temp)
        phase_file = temp_dir / "phase"
        spill_dir = temp_dir / "spill"
        spill_dir.mkdir()
        log_file = temp_dir / "test.log"
        env = os.environ.copy()
        # Keep any process-wide compatibility policy constant during setup;
        # the test selects the measured proof policy through its own context.
        env["MIDNIGHT_MAP_PK"] = "0"
        env["MIDNIGHT_SPILL_COSETS"] = "0"
        env["MIDNIGHT_SPILL_FLOOR_K"] = "18"
        env["MIDNIGHT_BENCH_PHASE_FILE"] = str(phase_file)
        env["MIDNIGHT_SPILL_DIR"] = str(spill_dir)
        env["MIDNIGHT_BENCH_HEAP_KEY"] = "1" if args.policy == "heap" else "0"
        env["MIDNIGHT_BENCH_NO_COSET_SPILL"] = "1" if args.no_coset_spill else "0"
        env["MIDNIGHT_BENCH_SPILL_FLOOR_K"] = "0"
        command = [str(args.binary), args.test_name, "--ignored", "--exact", "--nocapture"]
        peaks: dict[str, int] = {}
        samples: dict[str, int] = {}
        peak_spill_bytes = 0
        spill_samples = 0
        footprint_samples: list[tuple[int, int]] = []
        start = time.monotonic()
        with log_file.open("w") as log:
            proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            next_lsof = start
            next_vmmap = start + 1
            while proc.poll() is None:
                phase = phase_file.read_text().strip() if phase_file.exists() else "setup"
                rss = rss_kib(proc.pid)
                if rss is not None:
                    peaks[phase] = max(peaks.get(phase, 0), rss)
                    samples[phase] = samples.get(phase, 0) + 1
                now = time.monotonic()
                if phase == "prove" and now >= next_lsof:
                    observed = spill_bytes(proc.pid, spill_dir)
                    if observed is not None:
                        peak_spill_bytes = max(peak_spill_bytes, observed)
                        spill_samples += 1
                    next_lsof = now + 0.1
                if phase == "prove" and args.vmmap and now >= next_vmmap:
                    footprint = physical_footprint_bytes(proc.pid)
                    if footprint is not None:
                        footprint_samples.append(footprint)
                    next_vmmap = time.monotonic() + 1
                time.sleep(0.02)
            returncode = proc.wait()
        output = log_file.read_text()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = {
            "host": platform.platform(),
            "policy": args.policy,
            "spill_cosets": not args.no_coset_spill,
            "test": args.test_name,
            "exit_code": returncode,
            "wall_seconds": round(time.monotonic() - start, 3),
            "rusage_children_peak_rss_bytes": usage.ru_maxrss,
            "sampled_peak_rss_kib_by_phase": peaks,
            "rss_samples_by_phase": samples,
            "sampled_peak_spill_bytes_during_prove": peak_spill_bytes,
            "spill_samples_during_prove": spill_samples,
            "vmmap_footprint_samples_bytes": footprint_samples,
            "test_output": output,
        }
        rendered = json.dumps(result, indent=2)
        print(rendered)
        if args.output:
            args.output.write_text(rendered + "\n")
        return (
            0
            if returncode == 0
            and "running 1 test" in output
            and "test result: ok" in output
            and samples.get("prove", 0) > 0
            else 1
        )


if __name__ == "__main__":
    sys.exit(main())
