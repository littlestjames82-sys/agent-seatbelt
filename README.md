# Agent Seatbelt

**A seatbelt for AI coding agents.** One self-contained Python file
that reads every tool call *before* it runs — shell commands, file
writes, MCP calls — and denies or escalates the ones that end
careers: recursive deletes, secret exfiltration, production deploys,
agent-bypass launches, memory poisoning. Every verdict names its
rule, its blast radius, and the safer path.

```text
Seatbelt Bench v1   206/206 cases   ·   GuardFall fuzz 1431/1431
Naive rm-rf regex    42/206         ·   Injection 15/15, 0 FP
```

No network. No telemetry. No dependencies. The hook never phones
home — check `tests/test_no_network.py`, it AST-scans the source.

## Install (verify, then run)

Read `install.py` before you run it — it's short, and installing a
security tool you haven't read is how the incidents in
`docs/INCIDENTS.md` happen.

```bash
# 1. Verify the download against the release's SHA256SUMS
sha256sum -c SHA256SUMS

# 2. Install as a Claude Code plugin
claude plugin marketplace add littlestjames82-sys/agent-seatbelt
claude plugin install agent-seatbelt@agent-seatbelt
```

Or wire the hook directly into `~/.claude/settings.json`:

```bash
python3 install.py --dry-run   # shows the diff first
python3 install.py
```

Optional extras: `--harden` adds a native permissions deny/ask
layer alongside the hook; `--canaries` plants decoy credentials
(see below). Team rollout: `docs/TEAM_ADOPTION.md`.

## See it work

```
$ python3 hooks/seatbelt_hook.py --check "rm -rf ~/project"
DENY  rule=seatbelt-locked-rm-rf
  reason: recursive forced deletion (rm with -r and -f) is irreversible
  Safer path: List the targets first (ls), move them to a
  quarantine/trash directory, and delete only after checking.
```

Full captured demo — selftest, an ask with a rehearsal preview, an
off-plan stop, a brain-drift report: **`docs/DEMO.md`**. Try the
policy in your browser: **`docs/playground.html`** (open from disk).

## What it does

- **Deobfuscation before judgment.** Quote fragments (`r"m" -rf`),
  `$IFS`, backslash escapes, command substitution, base64 blobs,
  interpreter `-c` code, and **aliases** — `npm run deploy` is
  judged by what the script actually runs. The 2026 GuardFall
  bypass shapes are the test corpus, not a surprise.
- **Locked rules, strictest wins.** Bash + PowerShell destruction,
  git destruction, cloud/DB deletion, deploys/publishes,
  pipe-to-shell, secret reads, secret+network exfiltration, sudo,
  persistence, reverse shells, tunnels, TLS bypass, crypto mining,
  agent-bypass launches. Project overlays and policy packs
  (`solo` / `team-strict` / `ci` / `paranoid`) can only add.
- **Blast radius in every serious reason** — git status counts, rm
  target counts, symlink/junction escapes out of the target tree.
- **Snapshots before destruction.** Ask-tier destructive actions
  first copy their enumerable targets (bounded: 2,000 files /
  256 MB, caps recorded honestly in the manifest). One command
  restores — additively, hash-verified (`docs/SNAPSHOTS.md`).
- **Injection flagging.** Tool output and pasted text are scored
  for agent-directed instructions; a flag taints the session for
  30 minutes and escalates the next destructive/exfil verdict,
  naming the source (`docs/INJECTION.md`).
- **Memory drift watch.** Your `CLAUDE.md`/`AGENTS.md`/settings are
  baselined; SessionStart reports drift only when it exists,
  quoting instruction-shaped added lines verbatim. The baseline
  moves only by a human running `--baseline --accept`
  (`docs/BRAIN.md`).
- **MCP rug-pull watch.** Server configs (env **key names only —
  never values**) and tool surfaces are fingerprinted at baseline;
  drift escalates MCP verdicts until a human re-baselines.
- **Judge escalation seam (opt-in, off by default).** Point
  Seatbelt at a local judge command *you* configure: on allow/ask
  verdicts it may raise the verdict exactly one tier — and it can
  never lower, clear, or suppress anything. Malformed, slow, or
  verdict-shaped replies are ignored and audit-logged; the
  deterministic verdict is always the floor (`docs/JUDGE.md`).
- **Skill & plugin drift watch.** A human-filed baseline of
  sha256+size fingerprints (never file contents) for installed
  skills, commands, hooks, and plugin manifests. Drift is reported
  at SessionStart and via `--skills`, audit-logged, and — in
  strict/CI mode only — escalates the first call after the change
  one tier. Detection, not prevention (`docs/SKILL_DRIFT.md`).
- **Flight plans.** Declare the session's scope
  (`.seatbelt/plan.json`): ask-tier actions inside it stop
  prompting; denials and locked rules are never covered; off-plan
  consequential actions ask (solo) or deny (ci/paranoid).
- **Rehearsal previews.** Ask-tier infra commands run their honest
  dry-run twin (terraform plan, git push --dry-run, kubectl
  --dry-run=client…) and the ask carries a `Preview:` line.
  Previews never change verdicts.
- **Canary honeytokens.** Opt-in decoy credentials
  (`install.py --canaries`); any read of one, or any command
  carrying one's value, denies in every mode. Registry stores
  hashes only.
- **Tamper-evident audit.** Every decision is written first to
  `.seatbelt/audit.jsonl` — hash-chained, sanitized,
  secret-redacting (type+length, never values). `--verify-log`
  walks the chain; `--report --evidence` emits the compliance
  bundle (`docs/COMPLIANCE.md`).
- **Self-protection.** The agent cannot edit the hook, the
  policies, the audit log, the baselines, or its own governance
  files without a human. Reads of them stay open — transparency
  cuts both ways.

Snapshots and injection flags are seatbelts, not roll cages:
bounded, local, and honest about what they can't catch.

## Agents

One core, per-agent envelopes (full matrix: `docs/AGENTS.md`).
**All non-Claude surfaces are simulated-tested, not live-tested.**

| Agent | Ask semantics | Notes |
|---|---|---|
| Claude Code | True ask | Reference surface (plugin) |
| Codex | ask→deny under strict/CI | Hooks can fail open on ask |
| Cursor | True ask | `preToolUse` contract |
| Cline | Ask delivered as block for review | Documented hooks; host fails open on errors |
| Gemini | LEGACY | Consumer CLI retired 2026-06-18 → Antigravity (`agy`); support pending Google's documented contract |
| OpenCode | Ask delivered as block | Experimental JS plugin shim |

## Built from real disasters

Each incident below is written up in `docs/INCIDENTS.md` and
reproduced as bench cases (sources cited there):

| Incident | Seatbelt answer | Bench case |
|---|---|---|
| Home-directory wipe (Claude Code, Dec 2025) | rm -rf deny + blast radius | `incident-home-wipe` |
| Wrong-folder photo deletion (Cowork, Feb 2026) | Delete asks + snapshots | `incident-cowork-photos-rm` |
| Alias pushed a DB change to prod (Replit, Jul 2025) | Alias resolution + prod signals | `incident-replit-dbpush-alias` |
| Over-scoped token deleted a prod volume (PocketOS, Apr 2026) | MCP gating + flight plans | `incident-pocketos-mcp-volume` |
| Junction cleanup ate a live tree (Sep 2026) | Link-aware blast radius | `incident-junction-rm` |
| Terraform applied to production (DataTalks, Feb 2026) | Prod-target escalation | `incident-terraform-prod` |
| Supply-chain payload hired an agent (Nx, Aug 2025) | Agent-bypass deny | `incident-nx-agent-bypass` |
| 4.6-hour retry loop (Dec 2025) | Loop guard | `incident-loop-sequence` |

Scope honesty: Seatbelt gates the **tool-call path** only. The
PocketOS deletion, for instance, arrived through an MCP tool call —
which is why MCP calls are gated — but no hook can govern what a
separately-credentialed service does on its own.

## How it compares (honestly)

- **Single-regex rm blockers** are the common baseline; the bench
  scores one at 20.4%. They're better than nothing and blind to
  everything else.
- **Shellter** covers PowerShell/cmd and persistence well; Seatbelt
  matches that ground and adds deobfuscation, snapshots, and the
  memory/injection layers.
- **Anthropic's security-guidance plugin** reviews code patterns;
  Seatbelt gates *actions at runtime* — different layer, composable.
- **Classifier layers** (e.g. Cursor's Auto-review) are, in Cursor's
  own documentation's words, "steering, not enforcement" and "not
  a security boundary". Classifiers advise; Seatbelt is the
  deterministic gate underneath.
- **AgentGuards and similar policy tools** overlap on policy
  gating; Seatbelt's distinguishing bets are the public bench,
  the snapshot/restore pair, and the memory-drift watch.

No "first" or "only" claims: the field is active and good. The
bench is the argument — run your current tool through
`bench/run_external.py` and compare.

## Known limits

- Deterministic pattern policy, not a sandbox: a determined
  adversary with arbitrary code execution can route around any
  hook. Seatbelt raises the cost of accidents and common attack
  shapes; it is not a kernel boundary (see `docs/THREAT_MODEL.md`).
- Snapshots cover enumerable local files only — not databases,
  remote state, or shell-expanded globs.
- Injection flagging is a heuristic scorer with a measured
  false-positive budget, not a proof.
- Claude Mods (and the experimental `experimental/` editions) run
  unsandboxed in-process and can approve what a hook blocked —
  treat mods as trusted code; the hook is the floor.

## The Python library

The original 0.1 library remains: `agent_seatbelt` (policy kernel
with strictest-wins tiers, locked rules, named decisions, human
handoff, redacted audit), the governor, and a CLI.

```bash
pip install ghost-seatbelt
python3 -m agent_seatbelt --help
```

## Docs map

`docs/BENCH.md` (all the numbers) · `docs/DEMO.md` ·
`docs/INCIDENTS.md` · `docs/THREAT_MODEL.md` · `docs/AGENTS.md` ·
`docs/SNAPSHOTS.md` · `docs/INJECTION.md` · `docs/BRAIN.md` ·
`docs/JUDGE.md` · `docs/SKILL_DRIFT.md` ·
`docs/COMPLIANCE.md` · `docs/TEAM_ADOPTION.md` ·
`docs/FEED_RUNBOOK.md` · `docs/VERIFICATION.md` ·
`docs/CLAIMS_AUDIT.md` · `bench/README.md` (score anything)

Slash commands: `/agent-seatbelt:status`, `:report`, `:selftest`,
`:check`, `:doctor`, `:restore`, `:plan`, `:skills`.

MIT licensed. Contributions follow one law — no detector without
bench cases (destructive AND benign near-miss) and a remediation
string (`CONTRIBUTING.md`).

---

From Ghost Developer Studio, the makers of GhostGuard — the
governance layer for autonomous systems.
