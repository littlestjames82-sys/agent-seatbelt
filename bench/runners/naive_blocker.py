#!/usr/bin/env python3
"""The naive baseline: a single-regex rm blocker.

This is the thing most people actually ship when they "add a safety
hook": one regex for rm -rf, deny on match, defer everything else.
Seatbelt Bench scores it head-to-head with Seatbelt so the corpus
measures the distance between a regex and a policy engine. It is
deliberately NOT improved — its misses are the argument.

Implements the external-runner interface (see bench/README.md):
writes a verdicts JSONL with {"name", "decision"} per case.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_RM_RF = re.compile(r"\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b")


def decide(case):
    inp = case.get("input", {})
    if case.get("tool") in ("Bash", "PowerShell"):
        return "deny" if _RM_RF.search(inp.get("command", "")) else "defer"
    return "defer"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cases_path = Path(argv[0]) if argv else Path(__file__).parent.parent / "cases.jsonl"
    out = []
    for line in cases_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            case = json.loads(line)
            out.append({"name": case["name"], "decision": decide(case)})
    text = "\n".join(json.dumps(o) for o in out) + "\n"
    if len(argv) > 1:
        Path(argv[1]).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
