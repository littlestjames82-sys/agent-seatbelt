---
description: Check a command with Seatbelt
argument-hint: "<command>"
allowed-tools: Bash(python3 *)
---

Ask Seatbelt what it would decide for a command, without running the command.

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --check "$ARGUMENTS"` and report the verdict, rule, and safer path. NEVER run the checked command itself.
