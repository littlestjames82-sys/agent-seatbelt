# Launch playbook — Agent Seatbelt 0.2.0

Status: **DRAFT — nothing here has been submitted or posted.** All
copy is ready-to-paste; the taps are Ryan's.

## The 48-hour sequence

1. **Hour 0** — Tag + release `v0.2.0` on GitHub with `SHA256SUMS`
   attached (`scripts/make_checksums.sh`). Repo topics:
   `claude-code`, `claude-plugin`, `claude-code-marketplace`,
   `ai-agents`, `agent-security`, `guardrails`, `hooks`, `mcp`.
2. **Hour 1** — Marketplace submissions (texts below): official
   marketplace form + clau.de listing (50–100 words, below).
3. **Hour 2** — Show HN (text in LAUNCH_POSTS_DRAFT.md). Post early
   US morning; Ryan answers comments for the first 3 hours.
4. **Hour 4** — X thread (text in LAUNCH_POSTS_DRAFT.md) with the
   45-second film (`docs/LAUNCH_FILM.md`) and social preview image
   (`docs/social-preview.png`).
5. **Hour 24** — Reddit r/AI_Agents + r/ClaudeCode (drafts marked
   DRAFT in LAUNCH_POSTS_DRAFT.md).
6. **Hour 48** — awesome-claude-code **web form** submission (their
   PRs are auto-closed; do not open a PR). Build-in-Public Episode
   covering the launch numbers.

Known state (Oct 6): the HN and Reddit accounts are blocked on
Ryan's 10-second taps (HN create-account password field, Reddit
email verification). Drafts stay ready; don't improvise new ones.

## Marketplace submission (official form)

Name: Agent Seatbelt. One-liner: "A seatbelt for AI coding agents:
deterministic pre-tool gating with shell deobfuscation, snapshots,
and a tamper-evident audit log." Category: security / developer
tools. Install: two commands (README). License: MIT.

## clau.de listing (86 words)

> Agent Seatbelt is a Claude Code plugin that gates every tool call
> before it runs: destructive shell commands, secret reads,
> exfiltration shapes, deploys, and prompt-injection fallout are
> denied or escalated with the safer path named. It deobfuscates
> shell tricks (quote fragments, $IFS, base64, aliases), snapshots
> files before destructive actions, keeps a hash-chained audit log,
> and scores 206/206 on its public bench — where a naive rm -rf
> regex scores 20.4%. Free, MIT, stdlib-only, no network, no
> telemetry.

## Disaster-feed SLA commitment line

> *[RYAN'S CALL TO PUBLISH]* "When a public agent incident lands,
> a Seatbelt feed entry — bench cases first, detector second —
> ships within 24 hours." (Operational checklist:
> docs/FEED_RUNBOOK.md. Publish this line only on Ryan's word.)

## Numbers sheet (copy exactly; all from real runs)

- Bench v1: 206/206 = 100.0%, false positives 0
- GuardFall fuzz: 1431/1431 = 100.0%, 4 softened
- Injection: 15/15 caught, 0/10 false positives
- Naive regex blocker on the same bench: 42/206 = 20.4%
- Selftest: 68/68
- Latency: see docs/BENCH.md (final table)
