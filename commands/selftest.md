---
description: Run the Seatbelt self-test battery
allowed-tools: Bash(python3 *)
---

Run Seatbelt's built-in battery against its own rules and report the pass count.

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --selftest` and report the final SELFTEST line verbatim, plus any FAIL lines. The battery is the proof the rules are live.
