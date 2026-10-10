# Changelog

## Unreleased

(Disaster-feed entries land here first — see docs/FEED_RUNBOOK.md.)

## 0.3.0 — 2026-10-07

The judgment release — two opt-in layers on top of the unchanged
deterministic rulebook:

- **Judge escalation seam (J1, off by default).** A local command
  you configure in `.seatbelt/policy.json` (`"judge": {"command":
  …, "timeout_ms": …}`, env overrides `SEATBELT_JUDGE_COMMAND` /
  `SEATBELT_JUDGE_TIMEOUT_MS`) is consulted on allow/ask verdicts
  and may raise a verdict exactly one tier (allow → ask, ask →
  deny). It can never lower, clear, or suppress a verdict: replies
  that try are ignored and audit-logged as `clear-attempt`
  anomalies, as are malformed, crashing, and timed-out replies.
  The judge never runs on a deny, in audit/shadow mode, on ungated
  tools, or against a flight plan's deliberate de-escalation.
  Every invocation lands in the hash-chained audit log under rule
  id `seatbelt-judge`. Ships with a stdlib keyword example
  (`examples/judge_example.py`) and the full contract in
  `docs/JUDGE.md`.
- **Skill & plugin drift watch (J2).** `--skills-baseline` files a
  human baseline of sha256+size fingerprints (names and hashes
  only, never contents) for the installed skill/plugin surface —
  SKILL.md files, commands, hooks, plugin manifests, project +
  user scope. SessionStart surfaces new drift; `--skills` prints
  the full report; drift is audit-logged under
  `seatbelt-skill-drift` once per distinct drift set. In solo mode
  drift never blocks anything; in strict/CI mode the first
  escalatable call after a drift is raised one tier, once.
  Re-baselining is explicit (`--accept`) and audit-logged; drift
  never auto-updates the baseline. Limits are stated plainly in
  `docs/SKILL_DRIFT.md`: this detects change, not malice.
- Bench grows to 221 cases (15 new: judge escalation semantics +
  skill drift), still 100% with 0 false positives. New test
  battery `tests/test_round9.py` (26 tests). A pre-existing flaky
  test in `tests/test_round5.py` was fixed in the test helper only
  (newest snapshot chosen by directory creation time, not name —
  same-second snapshot ids made the old name-sort pick random);
  no product code changed for it.

## 0.2.0 — 2026-10-07

The plugin release. Agent Seatbelt becomes a Claude Code plugin with
a self-contained, stdlib-only hook, and the safety net gets much
deeper:

- **Plugin packaging**: `.claude-plugin` manifests, slash commands
  (`/agent-seatbelt:status|report|selftest|check|doctor|restore|plan`),
  a seatbelt skill, `install.py` (settings merge, `--dry-run`,
  `--harden` native-permissions layer, `--canaries`), policy packs
  (solo/team-strict/ci/paranoid) with a JSON Schema.
- **Shell normalization & deobfuscation** before matching: quote
  fragments, `$IFS`, backslash escapes, segment splitting,
  command-substitution recursion, base64 decode checks, interpreter
  `-c` code scanning, alias resolution for npm/make/just/deno/
  composer (what the alias *actually* runs is what's judged).
- **Blast radius** in ask/deny reasons; **write-then-run closure**
  (scripts are scanned at write time and again at run time).
- **Cross-agent envelopes** from one file: Claude Code, Codex,
  Cursor, Cline (documented contracts), Gemini (LEGACY — retired CLI),
  OpenCode via an experimental JS shim. Per-agent ask semantics are
  documented in `docs/AGENTS.md`; all simulated-tested.
- **Self-protection + tamper-evident audit**: the agent cannot edit
  Seatbelt's own enforcement files; the JSONL audit log is
  hash-chained (`--verify-log`), sanitized, and secret-redacting.
- **Pre-action snapshots + restore** (bounded, manifest-verified,
  additive restore), **injection flagging** with a 30-minute taint
  window, **rehearsal previews** (dry-run twins on ask-tier infra
  commands), **flight plans** (`.seatbelt/plan.json` — friction
  reduction only, never over a deny), **memory drift watch** for
  brain files, **MCP rug-pull watch** (config + tool-surface
  baselines, env key names only), **canary honeytokens**,
  **shadow mode**, **loop/cost guard**, **disaster feed** format.
- **Seatbelt Bench v1**: 206 labeled cases + GuardFall mutation fuzz
  (1,431), injection bench, 10k robustness fuzz, latency harness,
  and a naive single-regex baseline scored head-to-head (20.4%).
- OWASP ASI tagging on every rule/case/audit record; compliance
  evidence bundle (`--report --evidence`).

## 0.1.0 — 2026-10-06

Initial Python library: policy kernel (strictest-wins tiers, locked
rules, named decisions, human handoff, redacted audit trail),
governor, and CLI. 34 tests.
