# Threat model

## What Seatbelt is

A local, stdlib-only gate on the tool-call path of AI coding agents
(Claude Code first; Codex/Gemini/Cursor envelopes simulated-tested).
It denies or asks before destructive, exfiltrating, or self-tampering
actions run; snapshots enumerable targets before approved destructive
actions; flags instruction-like content the agent reads; and keeps a
hash-chained, redacted audit of every gated call.

## What it stops (and how well)

| Threat | Mechanism | Strength |
|---|---|---|
| Accidental destructive commands (`rm -rf`, force push, `terraform destroy`, cloud/DB deletes) | Locked detectors over the *normalized* command (quotes, `$IFS`, substitutions, wrappers, aliases resolved) | Bench: see docs/BENCH.md for the measured catch rate and the misses by name |
| Evasion spelling of the same commands | Shell normalization + GuardFall mutation fuzz | Measured, published with misses |
| Secret reads and one-step exfiltration (secret + network in one command) | Secret-path gating; exfil shape detector | Strong on the gated path |
| Agent tampering with its own gate | Self-protection denies on the plugin, policy, audit log, and enforcement env | Deny in all modes |
| Wrong-folder / wrong-target deletes that a human approved | Pre-action snapshots (bounded, manifest-verified) + additive restore | Recovers enumerable in-project targets; caps are recorded in the manifest |
| Planted instructions in read content (tickets, pages, MCP rows) | Scored injection flag + 30-min taint escalation | Heuristic flag, NOT proof of malice — see docs/INJECTION.md |
| Runaway loops | Identical-command repetition guard | Session-scoped |
| Audit tampering after the fact | SHA-256 hash chain + `--verify-log` | Tamper-evident, not tamper-proof (an attacker who can rewrite the whole log can re-chain it) |

## What it cannot stop — stated plainly

- **API calls outside the agent's tools.** If a program the agent
  launches makes raw HTTP calls with a harvested credential, the hook
  sees the launch, not the calls. (The PocketOS incident shape; see
  docs/INCIDENTS.md #4.)
- **A determined human** with shell access, or an agent running under
  a bypass mode the host itself granted. Seatbelt denies *launching*
  bypass modes from inside a gated session; it cannot remove the
  host's own switches.
- **Paraphrased social engineering.** Injection flagging is scored
  string/heuristic signals. Novel phrasing evades it; the protection
  is the taint *escalation* of destructive verdicts while flagged
  content is recent, not a guarantee of detection.
- **Script-internal deletions beyond enumerated targets.** Snapshots
  cover targets the hook can enumerate at PreToolUse time; a script
  that computes its targets at runtime can outrun the list.
- **Disk loss.** Snapshots and the audit log live on the same disk.
- **Host compromise.** If the machine or the Python interpreter is
  compromised, a userspace hook is not a boundary.

## Design commitments that follow from this model

1. Fail closed on malformed input and internal errors.
2. Locked rules cannot be weakened by project policy; overlays can
   only add.
3. Every detector ships with bench cases (destructive AND benign
   near-miss) and a remediation string — see CONTRIBUTING.md.
4. Numbers in the docs come from runs, not aspirations; misses are
   listed by name.

## OWASP Agentic Top 10 (ASI) mapping

Every rule carries an ASI id (also on bench cases, feed rules, and
audit records; `--report` groups by ASI):

| ASI | Threat | Seatbelt coverage |
|---|---|---|
| ASI01 | Agent goal hijack | Injection flagging + taint escalation; flight plans bounding scope |
| ASI02 | Tool misuse & exploitation | The core deny/ask rule pack; blast radius; loop guard |
| ASI03 | Identity & privilege abuse | Secret-read/exfil gating, sudo asks, canary honeytokens, MCP config drift |
| ASI04 | Agentic supply chain | Pipe-to-shell and global-install gating; MCP tool-surface baseline |
| ASI05 | Unexpected code execution | Inline `-c` / script-content scanning; write-then-run closure |
| ASI06 | Memory & context poisoning | Brain drift watch; persistence/tamper asks; governance-file protection |
| ASI08 | Cascading failures | Loop/cost guard on identical repeats |
| ASI10 | Rogue agents | Agent-bypass launch denies; bare agent-launch asks in strict mode |

## A note on Claude Mods (and other in-process layers)

Claude Code Mods run **unsandboxed, in-process**, with the user's
permissions, and per Anthropic's documentation a mod that approves
tool calls **can approve one that a PreToolUse hook blocked**. Read
that sentence twice before installing any mod: mods are trusted
code, not sandboxed plugins. Seatbelt's position:

- The **hook is the deterministic floor** — a separate process,
  fail-closed, stdlib-only, no network.
- A mod can sit *above* that floor ( UX, extra checks — Seatbelt's
  own experimental mod is block-only for exactly this reason), but
  nothing in-process should be mistaken for a boundary.
- On Team/Enterprise/managed setups Anthropic ships a built-in
  `sec-default` mod that loads first; `allowManagedModsOnly` exists
  for organizations that want to control the layer deliberately.

The same logic applies to classifier-based layers elsewhere: Cursor's
own documentation describes its Auto-review classifier as "steering,
not enforcement" and "not a security boundary". Classifiers advise;
deterministic gates decide. Seatbelt is the gate.
