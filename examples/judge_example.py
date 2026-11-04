#!/usr/bin/env python3
"""Example Seatbelt judge (round 9, J1) — escalation-only, stdlib only.

A judge is a local command YOU configure. Seatbelt runs the
deterministic rulebook first; only when the verdict is allow or ask
does the hook hand this script a JSON brief on stdin:

    {"tool": "Bash", "action": {"command": "kubectl ..."},
     "verdict": "allow", "rules": ["seatbelt-safe-allow"],
     "cwd": "/path/to/project", "taint": false,
     "session_id": "...", "agent": "claude"}

The judge answers with ONE JSON object on stdout:

    {"escalate": true, "reason": "touches the production cluster"}

escalate=true raises the verdict exactly one tier (allow -> ask,
ask -> deny). That is the only power a judge has. It cannot lower
or clear a verdict, cannot suppress a rule, and a malformed,
verdict-shaped, slow, or crashing reply is ignored (and logged).
See docs/JUDGE.md for the full contract.

This example escalates whenever the action mentions one of a small
keyword list — the sort of thing a team might want a human eye on
even though the deterministic rules allow it. Extend the list, or
replace the whole script with your own (a model call, a ticket
lookup, a team policy service): if it speaks this JSON, it works.

Enable it in .seatbelt/policy.json:

    {"judge": {"command": "python3 /path/to/judge_example.py",
               "timeout_ms": 3000}}

Never crash: any exception answers {"escalate": false}.
"""
import json
import sys

# Actions mentioning any of these get one tier stricter. Deliberately
# boring: deterministic keywords, no model, no network.
KEYWORDS = ("kubectl", "helm", "production", "prod.", "migrate",
            "--force", "terraform plan", "systemctl", "crontab")


def main():
    try:
        brief = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"escalate": False}))
        return 0
    haystack = json.dumps(brief.get("action") or {}).lower()
    tool = str(brief.get("tool") or "")
    for word in KEYWORDS:
        if word in haystack:
            print(json.dumps({
                "escalate": True,
                "reason": "example judge: %s action mentions %r; "
                          "a human should glance at this"
                          % (tool or "tool", word),
            }))
            return 0
    print(json.dumps({"escalate": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
