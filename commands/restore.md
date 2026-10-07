---
description: Restore files from a Seatbelt pre-action snapshot (additive — never deletes newer files)
argument-hint: "<snapshot-id>"
allowed-tools: Bash(python3 *)
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --restore $ARGUMENTS` and show the output. If no id was given, first run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --snapshots` to list them. Restores are additive over the snapshot manifest's paths only, hash-verified, and the pre-restore state is itself snapshotted so a restore can be undone.
