# The judge seam

Seatbelt's verdicts are deterministic: the same action in the same
project always gets the same answer, and you can read the rulebook.
But some calls are judgment calls — "this deploy is fine, *that* one
touches the production cluster" — and no static rulebook knows your
context. The judge seam lets you plug in your own judgment **without
handing it the keys**.

**The judge is off by default.** Nothing in this document happens
until you configure a judge command.

## The one rule

A judge can only ever make a verdict **stricter**:

```
allow ──judge──▶ ask ──judge──▶ deny
deny  ──judge──▶ (never consulted — a deny is final)
```

- `escalate: true` raises the verdict exactly **one tier**.
- The judge can **never** produce an allow from an ask or a deny,
  never suppress or soften a rule, and never delay the hook beyond
  its timeout.
- A malicious or broken judge can cause extra asks and denies — an
  availability nuisance — but it **cannot weaken a single verdict**.
  That asymmetry is the whole design.

## How it works

1. The deterministic engine runs first, exactly as it always does.
   Its verdict is the floor; it cannot be negotiated down.
2. If a judge is configured **and** the verdict is allow or ask,
   the hook runs the judge command once, with a timeout.
3. `escalate: true` rewrites the envelope one tier up. The judge's
   reason is appended to the verdict reason, sanitized and capped
   at 200 characters, and marked as judge-raised.
4. Every invocation — escalated, no-raise, timeout, crash,
   malformed, or a reply that tried to speak in verdicts — is
   written to the hash-chained audit log under rule id
   `seatbelt-judge`, with the outcome and the from/to verdicts.

The judge never runs:

- on a deny (final is final),
- in `audit` or `shadow` mode (those modes observe only; there is
  no emitted verdict to raise),
- on tools the deterministic layer did not actually evaluate
  (ungated tools pass silently, as always),
- on a call a flight plan deliberately de-escalated (the human's
  filed plan governs; the judge does not fight it),
- for Cline payloads (the Cline adapter keeps its own contract).

## Configuring a judge

In the project policy, `.seatbelt/policy.json`:

```json
{"judge": {"command": "python3 /path/to/my_judge.py",
           "timeout_ms": 3000}}
```

Environment overrides (they win over the file):

- `SEATBELT_JUDGE_COMMAND`
- `SEATBELT_JUDGE_TIMEOUT_MS`

Set `"enabled": false` in the policy to switch a configured judge
off without deleting it. The timeout defaults to 3000 ms and is
clamped to 100–30000 ms. Keep judge timeout + normal hook time
inside your agent host's hook timeout (5 s in the shipped Claude
Code config) — a judge that eats the whole budget gets cut off by
the host, and the deterministic verdict stands anyway.

`--doctor` reports whether a judge is configured.

## The contract

The hook sends one JSON object on the judge's **stdin**:

```json
{"tool": "Bash",
 "action": {"command": "kubectl rollout status deploy/api"},
 "verdict": "allow",
 "rules": ["seatbelt-safe-allow"],
 "cwd": "/path/to/project",
 "taint": false,
 "session_id": "...",
 "agent": "claude"}
```

- `action` is the same redacted summary the audit log keeps
  (commands are secret-redacted before the judge ever sees them).
- `verdict` is the deterministic verdict: `"allow"` or `"ask"`.
- `taint` is true while the session is under an injection taint.

The judge replies with one JSON object on **stdout**:

```json
{"escalate": true, "reason": "touches the production cluster"}
```

Rules of the reply, enforced by the hook no matter what the judge
sends:

- Only `escalate` (a boolean) and `reason` (a string) are read.
- A reply containing verdict-shaped keys (`decision`, `verdict`,
  `allow`, `clear`, `suppress`, `override`,
  `permissionDecision`) is ignored **in full** and logged as a
  `clear-attempt` anomaly — even if it also said `escalate: true`.
  Verdicts are not the judge's to give.
- Unparseable output, a non-zero exit, or a timeout: the reply is
  ignored, the deterministic verdict stands, and the outcome is
  logged (`malformed` / `crash` / `timeout`).
- The hook never waits past the timeout. A hung judge costs at
  most `timeout_ms`, once per tool call, and changes nothing.

## A working example

`examples/judge_example.py` is a complete judge in ~60 lines of
stdlib Python: it escalates when the action mentions a keyword list
(`kubectl`, `helm`, `production`, migrations, `--force`, …).
Point the config at it, or replace its keyword check with anything
you like — a model call, an internal policy service, a lookup
against your deploy calendar. If it speaks this JSON within the
timeout, it works.

## Scope, plainly

- The seam applies to the **hook**. The Python library Governor is
  unchanged: if you embed the library, your own code is the judge.
- A judge runs with **your** user's permissions, as a command **you**
  configured. Seatbelt treats it as trusted configuration, the same
  way it treats your policy file — the escalation-only contract
  bounds what it can do to *verdicts*, not what your own command
  does on your own machine. Don't point the config at code you
  wouldn't run yourself.
- Judge latency is real latency: every gated allow/ask call waits
  for the judge (up to the timeout). With no judge configured, the
  seam costs one small policy-file read and nothing else.
