#!/usr/bin/env python3
"""Restart-proof, segmented runner for bench/robustness.py (SHINE4 V5).

Why this exists: the full battery (10,000 in-process payloads + 300
subprocess checks, seed 20261006) takes ~2.5h in one process on this
VM, and the VM restarts more often than that — the Oct 9 full run was
killed ~2h10m in and, because robustness.py only prints at the end,
left zero evidence.

This runner executes the *identical* deterministic payload pool and
the *identical* per-payload checks (both imported from robustness.py,
not reimplemented), in chunks. After every chunk it flushes a JSON
state file atomically, so a restart loses at most one chunk. Run it
repeatedly (manually or from any scheduler) until it prints the final
verdict:

    python3 bench/robustness_segmented.py            # one chunk per run
    python3 bench/robustness_segmented.py --until-done

Exit codes: 0 = chunk done / final PASS, 1 = final FAIL,
2 = chunks remain (only in single-chunk mode).

Memory: robustness.py materialises the whole pool (~2.1 GB of strings,
measured) before checking anything. This runner instead generates the
pool in slices — repeated gen_payloads() calls on one continuous rng.
gen_payloads draws exclusively from the passed-in rng in order, so
the concatenation of slices is the identical pool; this was proven
empirically on 2026-10-10 by comparing sha256 of all 10,000 payloads
(whole-pool vs 250-slices): identical, in order. Peak memory here is
one slice (~55 MB) plus the payload under test.

One deliberate deviation from the monolithic script, in the direction
of a *complete* tally: a subprocess payload that exceeds the 30s
timeout crashes robustness.py outright (TimeoutExpired propagates).
Here it is recorded as a subprocess failure ("timeout after 30s") —
a hook that never answers is a contract failure, and crashing would
wedge a restart-proof run on that payload forever. All other criteria
are byte-identical: in-process via check_one(); subprocess failure iff
returncode != 0 or "Traceback" in stderr, timeout=30.

State file defaults to ~/workspace/agent-seatbelt/robustness-segmented-state.json
(outside the package tree so a tree sync never clobbers progress).
The final verdict lines match the original script's format exactly:
"ROBUSTNESS: PASS" / "ROBUSTNESS: FAIL (n)" — plus the two phase lines.
Nothing here releases anything; it only produces the missing number.
"""

import importlib.util
import json
import random
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("robustness", HERE / "robustness.py")
rob = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rob)

DEFAULT_STATE = Path.home() / "workspace" / "agent-seatbelt" / "robustness-segmented-state.json"
RUNNER_VERSION = 2
SLICE = 500  # payloads generated per gen_payloads() call while streaming


def load_state(path):
    if path.exists():
        return json.loads(path.read_text())
    return None


def save_state(path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(path)


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iter_payloads(count):
    """Yield the identical pool robustness.py builds, slice by slice."""
    rng = random.Random(20261006)
    remaining = count
    while remaining > 0:
        n = min(SLICE, remaining)
        for raw in rob.gen_payloads(rng, n):
            yield raw
        remaining -= n


def payloads_range(start, end, count):
    """Yield (index, payload) for indices [start, end) of the pool."""
    for i, raw in enumerate(iter_payloads(count)):
        if i >= end:
            break
        if i >= start:
            yield i, raw


def fresh_state(count, sub_count):
    return {"runner_version": RUNNER_VERSION,
            "count": count, "sub_count": sub_count,
            "next": 0, "failures": [],
            "sub_next": 0, "sub_failures": 0, "sub_failure_details": [],
            "chunks_done": 0, "elapsed_secs": 0.0,
            "started": now(), "updated": now()}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    def opt(name, default):
        return int(argv[argv.index(name) + 1]) if name in argv else default

    count = opt("--count", 10000)
    sub_count = opt("--subprocess", 300)
    chunk = opt("--chunk", 250)
    sub_chunk = opt("--sub-chunk", 50)
    state_path = Path(argv[argv.index("--state") + 1]) if "--state" in argv else DEFAULT_STATE
    until_done = "--until-done" in argv
    if "--reset" in argv and state_path.exists():
        state_path.unlink()

    state = load_state(state_path)
    if (state is None or state.get("count") != count
            or state.get("sub_count") != sub_count
            or state.get("runner_version") != RUNNER_VERSION):
        state = fresh_state(count, sub_count)
        save_state(state_path, state)

    while True:
        did_work = False
        t0 = time.time()
        # Phase 1: in-process checks, chunked.
        if state["next"] < count:
            start = state["next"]
            end = min(start + chunk, count)
            for i, raw in payloads_range(start, end, count):
                problem = rob.check_one(raw)
                if problem:
                    state["failures"].append([i, problem, raw[:120]])
            state["next"] = end
            did_work = True
            print("[%s] in-process: %d/%d done, %d failures so far"
                  % (now(), state["next"], count, len(state["failures"])))
        # Phase 2: subprocess sample (payloads[:sub_count]), chunked.
        elif state["sub_next"] < sub_count:
            start = state["sub_next"]
            end = min(start + sub_chunk, sub_count)
            for i, raw in payloads_range(start, end, count):
                try:
                    proc = subprocess.run(
                        [sys.executable, str(rob.HOOK)], input=raw,
                        capture_output=True, text=True, timeout=30)
                    if proc.returncode != 0 or "Traceback" in proc.stderr:
                        state["sub_failures"] += 1
                        state["sub_failure_details"].append(
                            [i, proc.returncode, proc.stderr[:100], raw[:80]])
                except subprocess.TimeoutExpired:
                    state["sub_failures"] += 1
                    state["sub_failure_details"].append(
                        [i, "timeout", "no exit within 30s", raw[:80]])
            state["sub_next"] = end
            did_work = True
            print("[%s] subprocess: %d/%d done, %d failures so far"
                  % (now(), state["sub_next"], sub_count, state["sub_failures"]))

        if did_work:
            state["chunks_done"] += 1
            state["elapsed_secs"] = round(state["elapsed_secs"] + (time.time() - t0), 1)
            state["updated"] = now()
        save_state(state_path, state)
        if not did_work or not until_done:
            break

    if state["next"] < count or state["sub_next"] < sub_count:
        print("SEGMENTED: in progress — re-run to continue (state: %s)" % state_path)
        return 2

    n_fail = len(state["failures"])
    print("Robustness (in-process): %d/%d payloads OK, %d failures"
          % (count - n_fail, count, n_fail))
    for i, problem, raw in state["failures"][:10]:
        print("  FAIL #%d %s :: %r" % (i, problem, raw))
    print("Robustness (subprocess sample): %d/%d OK"
          % (sub_count - state["sub_failures"], sub_count))
    for i, rc, err, raw in state["sub_failure_details"][:5]:
        print("  SUBPROCESS FAIL #%d rc=%s stderr=%r input=%r" % (i, rc, err, raw))
    total_fail = n_fail + state["sub_failures"]
    print("ROBUSTNESS: %s" % ("PASS" if total_fail == 0 else
                              "FAIL (%d)" % total_fail))
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
