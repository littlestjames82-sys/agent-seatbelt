#!/usr/bin/env python3
"""Score an external tool against Seatbelt Bench.

Interface: the tool under test produces a verdicts JSONL file, one
{"name": ..., "decision": ...} object per line, where name matches a
case in cases.jsonl and decision is one of deny/ask/allow/defer (the
decision the tool would emit for that case's input). This scorer
compares against the frozen expectations and prints the same table
format as run_bench.py, listing every miss by name.

    python3 bench/run_external.py verdicts.jsonl

Cases a runner cannot evaluate (sequences, stateful drivers) may be
omitted from the verdicts file; omitted cases are reported as
"unevaluated" and excluded from the score, never silently passed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: run_external.py <verdicts.jsonl>\n")
        return 2
    verdicts = {}
    for line in Path(argv[0]).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            verdicts[row["name"]] = row["decision"]
    cases = [json.loads(l) for l in
             (_HERE / "cases.jsonl").read_text(encoding="utf-8").splitlines()
             if l.strip()]
    cats = {}
    misses = []
    unevaluated = []
    for case in cases:
        got = verdicts.get(case["name"])
        if got is None:
            unevaluated.append(case["name"])
            continue
        ok = got == case["expected"]
        cats.setdefault(case["category"], []).append(ok)
        if not ok:
            misses.append((case["name"], case["expected"], got))
    total = sum(len(v) for v in cats.values())
    passed = sum(sum(v) for v in cats.values())
    print("External runner vs Seatbelt Bench — %d cases evaluated" % total)
    print("%-16s %6s %6s %8s" % ("category", "total", "pass", "score"))
    for cat in sorted(cats):
        rows = cats[cat]
        ok = sum(rows)
        print("%-16s %6d %6d %7.1f%%" % (cat, len(rows), ok,
                                         100.0 * ok / len(rows)))
    print("%-16s %6d %6d %7.1f%%" % ("TOTAL", total, passed,
                                     100.0 * passed / total if total else 0))
    if misses:
        print("Misses:")
        for name, exp, got in misses:
            print("  MISS %-42s expected=%-6s got=%s" % (name, exp, got))
    if unevaluated:
        print("Unevaluated (excluded): %d case(s)" % len(unevaluated))
    return 0 if not misses else 1


if __name__ == "__main__":
    sys.exit(main())
