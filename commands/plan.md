---
description: Show or validate this project's Seatbelt flight plan (declared intent scope)
allowed-tools: Bash(python3 *)
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --plan` and show the output. A flight plan lives at `.seatbelt/plan.json`: `{id, created, task, ttl_hours (≤4), allow: {paths: [globs], verbs: [read|write|delete|network|publish|deploy|pay|test|build], resources: [globs]}}`. File one BEFORE consequential work: a plan only reduces friction on ask-tier actions inside its scope — it never converts a deny and never covers locked rules (self-protection, secrets, exfiltration, persistence). Off-plan consequential calls are asked about in solo mode and denied under CI/paranoid packs.
