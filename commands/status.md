---
description: Seatbelt status
allowed-tools: Bash(python3 *)
---

Show whether the Seatbelt hook is alive, its mode, audit location, and today's verdict counts.

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --doctor` and also read `.seatbelt/audit.jsonl` (fallback `~/.claude/seatbelt/audit.jsonl`) if it exists: report the SEATBELT_MODE in effect (default enforce), the number of gated calls today, and counts by verdict. Summarize in at most 6 lines.
