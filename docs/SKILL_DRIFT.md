# Skill & plugin drift watch

Skills and plugins are executable instructions your agent trusts:
a `SKILL.md` tells the agent what to do, a plugin ships hooks and
commands that run inside your sessions. They are also files that
other software can rewrite — an auto-update, a marketplace sync, or
something worse. The rug-pull shape is always the same: the skill
you reviewed last month is not byte-for-byte the skill that loads
today.

Drift watch is Seatbelt's tripwire for that. It is **detection, not
prevention** — read the limits section before relying on it.

## How it works

A human files a baseline: sha256 + size fingerprints of the
installed skill/plugin surface. From then on, Seatbelt compares the
live files against that baseline:

- **At SessionStart**, new drift is added to the session summary
  (`🧩 Skill drift: …`) and written to the audit log under rule id
  `seatbelt-skill-drift` — once per distinct drift set, not on
  every session.
- **On demand**, `--skills` prints the full report: every changed,
  new, and removed file with its scope.
- **In strict or CI mode**, the first escalatable tool call after a
  drift is raised one tier (allow → ask, ask → deny), once per
  distinct drift set. In solo/enforce mode drift never escalates
  anything by itself: report + audit only.

## What is watched

Project scope:

- `./.claude/skills/**/SKILL.md`, `./.claude/commands/**/*.md`,
  `./.claude/hooks/*`
- `./skills/**/SKILL.md`, `./commands/**/*.md`, `./hooks/*`,
  `./.claude-plugin/*.json` (the plugin-repo layout)

User scope:

- `~/.claude/skills/**/SKILL.md`, `~/.claude/commands/**/*.md`,
  `~/.claude/hooks/*`
- `~/.claude/plugins/**/SKILL.md` and plugin manifests
  (`*/.claude-plugin/*.json`)

The baseline lives at `.seatbelt/skills-baseline.json` and stores
**names, hashes, and sizes only — never file contents**.

Bounds, so SessionStart stays fast: discovery stops at 2000 files,
`.git` / `node_modules` / `__pycache__` are skipped, and files over
16 MiB are fingerprinted from size + head + tail instead of a full
hash (those entries are marked `"partial": true` in the baseline).

## Commands

```bash
# Create the baseline (first time)
python3 hooks/seatbelt_hook.py --skills-baseline

# Review drift
python3 hooks/seatbelt_hook.py --skills
# (or: ... skills check)

# Accept current files as the new normal (human only)
python3 hooks/seatbelt_hook.py --skills-baseline --accept
# (or: ... skills baseline --accept)
```

The baseline moves **only** by a human running the accept command —
the same rule as Seatbelt's brain and MCP baselines. Running
`--skills-baseline` when one exists refuses and says so. Accepts are
audit-logged under rule id `seatbelt-skill-baseline`. Drift never
auto-updates the baseline, and nothing in the hook path ever
rewrites it.

`--doctor` reports the baseline size and current drift count.

## Limits, plainly

- **It detects change, not malice.** A legitimate skill update and
  a rug-pulled skill look identical: bytes differ from the baseline.
  Deciding which one you're looking at is a human's job — review
  the diff (`--skills` names the files; your editor shows the
  change) and re-baseline only when the change was yours.
- **No baseline, no watch.** Until a human files one, SessionStart
  stays silent about skills. The watch also can't see a compromise
  that happened *before* the first baseline: the baseline blesses
  whatever was on disk when it was created.
- **It watches files, not behavior.** A skill that was always
  malicious, or one that fetches its real instructions from the
  network at runtime, produces no drift. (Runtime instruction
  fetching is what the injection flagging and taint are for.)
- **Scope is the discovered surface above.** Skills installed in
  other locations (another agent's directories, a custom
  `CLAUDE_CONFIG_DIR`) are not fingerprinted.
- **Strict/CI escalation is a speed bump, not a wall.** It buys one
  human glance at the first call after a change. It does not block
  the drifted skill from loading.
