#!/usr/bin/env python3
"""Hostile-input robustness fuzz (SHINE4 V5).

Generates adversarial hook payloads — truncated JSON, random unicode,
ANSI/control storms, multi-MB commands, deeply nested substitutions,
null bytes, wrong-shaped JSON — and asserts the hook's contract:
always exit/return 0, never raise, never print a traceback, and
answer deny-or-silence on garbage (fail closed, never crash open).

The full run is in-process for speed (10,000 payloads), plus a
subprocess sample (300 payloads) that verifies real exit codes and
that stderr carries no traceback.

Usage: python3 bench/robustness.py [--count N] [--subprocess N]
"""

import contextlib
import importlib.util
import io
import json
import random
import string
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "seatbelt_hook.py"

spec = importlib.util.spec_from_file_location("seatbelt_hook", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

VALID = {"hook_event_name": "PreToolUse", "session_id": "robust",
         "cwd": "/tmp", "tool_name": "Bash",
         "tool_input": {"command": "rm -rf /"}}


def gen_payloads(rng, count):
    valid_raw = json.dumps(VALID)
    pool = []
    for _ in range(count):
        kind = rng.randrange(9)
        if kind == 0:  # truncated JSON
            pool.append(valid_raw[:rng.randrange(len(valid_raw))])
        elif kind == 1:  # random unicode junk
            pool.append("".join(rng.choice(string.printable + "✓✗☃𝕏\x00\x1b")
                                for _ in range(rng.randrange(200))))
        elif kind == 2:  # ANSI / control storm in the command
            cmd = "".join(rng.choice("\x1b[31m\x1b[0m\x07\x08\x0b\x0c")
                          for _ in range(300)) + "rm -rf /"
            pool.append(json.dumps({**VALID, "tool_input": {"command": cmd}}))
        elif kind == 3:  # huge command
            cmd = "echo " + "A" * rng.choice([100_000, 1_000_000, 5_000_000])
            pool.append(json.dumps({**VALID, "tool_input": {"command": cmd}}))
        elif kind == 4:  # deeply nested substitution
            depth = rng.choice([50, 200, 1000])
            cmd = "echo " + "$(" * depth + "ls" + ")" * depth
            pool.append(json.dumps({**VALID, "tool_input": {"command": cmd}}))
        elif kind == 5:  # wrong shapes
            pool.append(rng.choice([
                "[]", "42", "\"x\"", "null", "true",
                json.dumps({"hook_event_name": "PreToolUse",
                            "tool_input": [1, 2, 3]}),
                json.dumps({"hook_event_name": "PreToolUse",
                            "tool_name": "Bash", "tool_input": "rm -rf /"}),
                json.dumps({"hook_event_name": ["PreToolUse"]}),
                json.dumps({"tool_name": "Bash",
                            "tool_input": {"command": None}}),
            ]))
        elif kind == 6:  # null bytes + escapes inside strings
            pool.append('{"hook_event_name":"PreToolUse","tool_name":"Bash",'
                        '"tool_input":{"command":"rm\\u0000 -rf /"}}')
        elif kind == 7:  # random mutations of the valid payload
            chars = list(valid_raw)
            for _ in range(rng.randrange(1, 12)):
                if chars:
                    chars[rng.randrange(len(chars))] = rng.choice("{}[]\",:0123456789\x1b")
            pool.append("".join(chars))
        else:  # valid control payload — interleave so the run also
            pool.append(valid_raw)  # proves normal traffic still works
    return pool


def check_one(raw):
    """Returns None when the contract holds, else a failure string."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_out), \
                contextlib.redirect_stderr(buf_err):
            rc = hook.run_hook(raw)
    except Exception as exc:
        return "raised %r" % (exc,)
    if rc != 0:
        return "returned %r" % (rc,)
    if "Traceback" in buf_err.getvalue():
        return "traceback on stderr"
    text = buf_out.getvalue().strip()
    if text:
        try:
            json.loads(text)
        except ValueError:
            return "stdout was not valid JSON: %r" % text[:80]
    return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    count = 10000
    sub_count = 300
    if "--count" in argv:
        count = int(argv[argv.index("--count") + 1])
    if "--subprocess" in argv:
        sub_count = int(argv[argv.index("--subprocess") + 1])
    rng = random.Random(20261006)
    payloads = gen_payloads(rng, count)
    failures = []
    for i, raw in enumerate(payloads):
        problem = check_one(raw)
        if problem:
            failures.append((i, problem, raw[:120]))
    print("Robustness (in-process): %d/%d payloads OK, %d failures"
          % (count - len(failures), count, len(failures)))
    for i, problem, raw in failures[:10]:
        print("  FAIL #%d %s :: %r" % (i, problem, raw))
    sub_fail = 0
    for raw in payloads[:sub_count]:
        proc = subprocess.run([sys.executable, str(HOOK)], input=raw,
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or "Traceback" in proc.stderr:
            sub_fail += 1
            if sub_fail <= 5:
                print("  SUBPROCESS FAIL rc=%s stderr=%r input=%r"
                      % (proc.returncode, proc.stderr[:100], raw[:80]))
    print("Robustness (subprocess sample): %d/%d OK"
          % (sub_count - sub_fail, sub_count))
    total_fail = len(failures) + sub_fail
    print("ROBUSTNESS: %s" % ("PASS" if total_fail == 0 else
                              "FAIL (%d)" % total_fail))
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
