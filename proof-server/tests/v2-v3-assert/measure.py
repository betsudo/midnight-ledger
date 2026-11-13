#!/usr/bin/env python3
"""Measure one Ledger9 ZKIR v2 or v3 assertion proof on macOS."""

import argparse
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compact-v3-hash-chain"))
from measure_context import rss_kib, spill_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--version", choices=("v2", "v3"), required=True)
    parser.add_argument("--policy", choices=("heap", "mapped-spill"), required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("this sampler uses macOS ps RSS and wait4 units")
    if not args.binary.is_file():
        parser.error(f"missing test binary: {args.binary}")

    with tempfile.TemporaryDirectory(prefix="midnight-v2-v3-assert-") as temp:
        root = Path(temp)
        phase_file = root / "phase"
        spill_dir = root / "spill"
        spill_dir.mkdir()
        log_file = root / "test.log"
        env = os.environ.copy()
        env["MIDNIGHT_BENCH_PHASE_FILE"] = str(phase_file)
        env["MIDNIGHT_BENCH_IR_VERSION"] = args.version
        env["MIDNIGHT_MAP_PK"] = "1" if args.policy == "mapped-spill" else "0"
        env["MIDNIGHT_SPILL_COSETS"] = "1" if args.policy == "mapped-spill" else "0"
        env["MIDNIGHT_SPILL_FLOOR_K"] = "0"
        env["MIDNIGHT_SPILL_DIR"] = str(spill_dir)
        env["MIDNIGHT_BENCH_REQUIRE_SPILL"] = "1" if args.policy == "mapped-spill" else "0"
        command = [str(args.binary), "compare_assert_policy", "--ignored", "--exact", "--nocapture"]
        peaks: dict[str, int] = {}
        samples: dict[str, int] = {}
        spill_peaks: dict[str, int] = {}
        spill_samples: dict[str, int] = {}
        started = time.monotonic()
        with log_file.open("w") as log:
            proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            next_lsof = started
            while proc.poll() is None:
                phase = phase_file.read_text().strip() if phase_file.exists() else "setup"
                rss = rss_kib(proc.pid)
                if rss is not None:
                    peaks[phase] = max(peaks.get(phase, 0), rss)
                    samples[phase] = samples.get(phase, 0) + 1
                now = time.monotonic()
                if phase in ("keygen", "prove") and now >= next_lsof:
                    observed = spill_bytes(proc.pid, spill_dir)
                    if observed is not None:
                        spill_peaks[phase] = max(spill_peaks.get(phase, 0), observed)
                        spill_samples[phase] = spill_samples.get(phase, 0) + 1
                    next_lsof = now + 0.1
                time.sleep(0.02)
            returncode = proc.wait()
        output = log_file.read_text()
        result = {
            "host": platform.platform(),
            "version": args.version,
            "policy": args.policy,
            "assertions": 16384,
            "k": 15,
            "rows": 16386,
            "exit_code": returncode,
            "wall_seconds": round(time.monotonic() - started, 3),
            "rusage_children_peak_rss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            "sampled_peak_rss_kib_by_phase": peaks,
            "rss_samples_by_phase": samples,
            "sampled_peak_live_spill_bytes_by_phase": spill_peaks,
            "spill_samples_by_phase": spill_samples,
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
            and (args.policy != "mapped-spill" or spill_peaks.get("prove", 0) > 0)
            else 1
        )


if __name__ == "__main__":
    sys.exit(main())
