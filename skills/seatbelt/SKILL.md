---
name: seatbelt
description: How to behave when Agent Seatbelt gates a tool call — denials are final, follow the named safer path.
---

# Living with Agent Seatbelt

Agent Seatbelt is a policy gate between your decision and the tool call.
It classifies each Bash/PowerShell/file/MCP call, decides it against
locked rules plus the project overlay (`.seatbelt/policy.json`), and
writes an audit record BEFORE the call runs.

## When Seatbelt denies

- The denial is FINAL. Do not evade it: no splitting the command into
  pieces, no quoting/obfuscation tricks, no reaching the same effect
  through python/node instead of the shell, no editing Seatbelt's own
  policy, hook, or Claude settings to loosen the gate.
- Read the named rule and the reason — every decision names its rule.
- Follow the remediation in the reason (the "Safer path:") or propose
  an equivalent safer alternative, and tell the user what was stopped
  and why.

## When Seatbelt asks

- The human is being asked because the action is consequential
  (deploy, publish, secret read, persistence change, deletion).
  Present the exact command/target and the blast radius if shown.
  Do not rephrase the command to make it sound smaller than it is.

## When Seatbelt allows or stays silent

- `allow` means the call is on the conservative safe list.
- No output means Seatbelt deferred to the native permission flow —
  that is not an approval; follow the normal permission process.

## Reading a denial (for the user)

Run `/agent-seatbelt:report` for counts and top rules, or
`python3 hooks/seatbelt_hook.py --explain-last` (via the check
command) to read the last record field by field. Records live in
`.seatbelt/audit.jsonl` with secrets redacted to type+length.

## Flight plans

If the user has declared a flight plan for the session
(`.seatbelt/plan.json`, announced at SessionStart), work inside it:
the plan covers specific paths, verbs, and resources for a bounded
time, and ask-tier actions inside it proceed without a prompt.

- A plan NEVER covers denials or locked rules — if Seatbelt denies,
  the plan is irrelevant; follow the denial guidance above.
- If an action you need is off-plan, say so and let the human amend
  the plan (they edit `.seatbelt/plan.json`); do not route around
  the boundary.
- Off-plan consequential actions ask in solo mode and are denied
  under ci/paranoid packs — both are the plan working as intended.
