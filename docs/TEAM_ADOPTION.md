# Team adoption kit

Rolling Seatbelt out to a team, in order. Every number below is
copied exactly from this release's real bench output (docs/BENCH.md).

## Why (the 30-second version)

- Seatbelt Bench v1: **206/206 cases (100.0%)**, false positives 0.
- A naive single-regex `rm -rf` blocker — the thing most teams
  actually have — scores **42/206 (20.4%)** on the same corpus.
- GuardFall mutation fuzz: **1431/1431 mutations caught (100.0%)**,
  4 softened (deny→ask).
- Injection bench: **15/15 positives caught, 0/10 false positives**.
- Robustness: **10,000/10,000** malformed payloads handled without a
  crash, failing closed.

## Step 1 — pilot (one repo, one week)

Install the plugin (README), keep the default `solo` behavior.
Run `/agent-seatbelt:doctor` once; read `/agent-seatbelt:report`
at week's end. Success = zero surprises in the report.

## Step 2 — project policy

Commit `.seatbelt/policy.json` with the team's extra deny/ask
patterns (internal hostnames, prod resource names). Overlay rules
can only add to the locked set, never weaken it. Add a flight plan
template for routine migrations (`commands/plan.md`).

## Step 3 — tighten

Move CI/agents to the `ci` or `paranoid` policy pack
(`policies/`), which denies off-plan consequential actions, escalates
production targets and snapshot failures to deny, and maps asks to
denies on agents without a true ask. Enable the feed overlay
(`"feed": true`) so incident-driven rules arrive with releases.

## Step 4 — evidence

`--report --evidence` produces the JSON bundle (audit counts by
decision + ASI, hash-chain verification) for your security review;
`docs/COMPLIANCE.md` maps it to SOC 2 CC6.1/CC7.2/CC8.1 talking
points. Plant canaries (`install.py --canaries`) on shared agent
machines for the highest-signal tripwire available.

## Ground rules for the rollout

- Denials are final for the agent; humans change policy, agents
  don't negotiate. The skill file teaches the agent to propose the
  safer path named in every denial.
- False positive in the wild? File the false-positive template with
  the exact command — that's the project's most-valued report.

---

From Ghost Developer Studio, the makers of GhostGuard — the
governance layer for autonomous systems.
