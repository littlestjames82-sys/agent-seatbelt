---
description: Seatbelt doctor — prove the gate is alive
allowed-tools: Bash(python3 *)
---

Run Seatbelt's doctor checks (hook file, manifests, synthetic deny/allow, audit writability).

Run `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/seatbelt_hook.py" --doctor` and present every PASS/FAIL line. If any check fails, say plainly that the seatbelt may not be protecting this session (hooks fail open) and name the failing check.
