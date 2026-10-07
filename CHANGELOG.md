# Changelog

## Unreleased

(Disaster-feed entries land here first — see docs/FEED_RUNBOOK.md.)

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
