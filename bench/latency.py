#!/usr/bin/env python3
"""Seatbelt latency — time the hook end-to-end via subprocess.

This is the honest number: it includes Python interpreter startup,
because that is what a user waits for on every gated tool call.

Usage: python3 bench/latency.py [rounds]
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "seatbelt_hook.py"


def _pct(values, p):
    values = sorted(values)
    idx = min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1))))
    return values[idx]


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    payloads = {}
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["git", "init", "-q", td], check=False)
        base = {"session_id": "latency", "cwd": td,
                "hook_event_name": "PreToolUse", "tool_name": "Bash"}
        payloads = {
            "allow (git status)": {**base, "tool_input": {"command": "git status"}},
            "deny (rm -rf /)": {**base, "tool_input": {"command": "rm -rf /"}},
            "defer (make build)": {**base, "tool_input": {"command": "make build"}},
        }
        all_times = []
        per = {}
        for label, payload in payloads.items():
            times = []
            for _ in range(rounds):
                start = time.perf_counter()
                subprocess.run([sys.executable, str(HOOK)],
                               input=json.dumps(payload),
                               capture_output=True, text=True)
                times.append((time.perf_counter() - start) * 1000.0)
            per[label] = times
            all_times.extend(times)
        print("Seatbelt hook latency (subprocess end-to-end, includes "
              "Python startup), %d rounds each" % rounds)
        for label, times in per.items():
            print("  %-22s median %6.1f ms   p95 %6.1f ms"
                  % (label, _pct(times, 50), _pct(times, 95)))
        print("  %-22s median %6.1f ms   p95 %6.1f ms"
              % ("ALL", _pct(all_times, 50), _pct(all_times, 95)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
