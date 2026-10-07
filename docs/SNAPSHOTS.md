# Pre-action snapshots

Before a destructive-but-allowed action runs, Seatbelt copies what it
is about to lose. If the action turns out to be wrong, the work is
recoverable — that changes a catastrophe into an inconvenience.

## What gets snapshotted

At PreToolUse time, when the verdict is **ask-tier or stricter** (and
not an outright denial — denied actions never run), Seatbelt
enumerates the concrete targets:

- **Write/Edit/MultiEdit** — the file's current content.
- **Bash/PowerShell deletes** (`rm`, `del`, `Remove-Item`, `find
  -delete`) — the literal target paths, when they resolve inside the
  project.
- **git discards** (`reset --hard`, `clean`, `checkout --`) — the
  files `git status` says would be affected.

Snapshots land in `.seatbelt/snapshots/<timestamp>-<id>/` with a
`manifest.json` (path, size, sha256 per file).

## The caps, stated plainly

- At most **2,000 files**, **256 MB total**, **64 MB per file**.
- When a cap is hit, the snapshot is partial and **the manifest says
  so** (`caps_hit`, `skipped` entries with reasons) — a partial
  snapshot never pretends to be complete.
- `.git` and `node_modules` are skipped by policy (recorded in the
  manifest).
- **Symlinks are stored as links, never followed.** A link's target is
  not copied.
- Targets that can't be enumerated (globs the shell would expand,
  computed paths) aren't snapshotted — the manifest only ever lists
  what was actually copied.

## Failure behavior

If a snapshot fails (disk, permissions): in solo mode the ask goes
through with a warning appended; in strict/ci/paranoid the ask
escalates to a **deny** naming the failure — proceeding blind is
worse than stopping.

Pruning keeps the newest 20 snapshots and at most 1 GB; prunes are
counted in the audit log.

## Restore

```bash
python3 hooks/seatbelt_hook.py --snapshots        # list
python3 hooks/seatbelt_hook.py --restore <id>     # restore
```

Restore is **additive over the manifest's paths only: it never
deletes files created after the snapshot, and never touches paths
not in the manifest.** Before restoring, the current state is itself
snapshotted, so a restore can be undone by restoring the
pre-restore snapshot. Copies are hash-verified against the manifest
and the restore is audit-logged.

## Limits

Snapshots are a seatbelt, not a roll cage: bounded, local, and
honest about what they can't catch. They do not cover remote state,
databases, or anything the tool call mutates outside the enumerated
files. Commits and off-site backups are still your job.
