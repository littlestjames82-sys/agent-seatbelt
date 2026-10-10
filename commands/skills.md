---
description: Review skill/plugin drift against the human baseline (or create the baseline)
argument-hint: "[baseline]"
allowed-tools: Bash(python3 *)
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --skills` and show the output. If the argument is `baseline`, run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --skills-baseline --accept` instead — that is the explicit human act that accepts the current skill/plugin files as the new normal, and it is audit-logged. Never re-baseline on the agent's own initiative: drift means *something changed*, and only the human decides whether the change was theirs.
