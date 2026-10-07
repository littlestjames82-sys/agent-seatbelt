# Per-agent semantics matrix

One policy core, six agent surfaces. The honest differences matter
more than the similarities: what a "decision" means, whether a true
**ask** exists, and what happens when the hook itself errors.

Every row is **simulated-tested** (payloads constructed from each
agent's documented contract, driven through the hook in tests) and
**not live-tested** against the real agent. Cells say what they're
based on.

| Agent | Decision shape Seatbelt emits | True ask? | On hook error | Basis |
|---|---|---|---|---|
| Claude Code | `hookSpecificOutput.permissionDecision` = allow/deny/ask (+reason) | **Yes** — native prompt | Docs treat hook failure as non-blocking for the tool call; Seatbelt fails closed *internally* (malformed input → deny) | Documented hook contract |
| Codex | Same JSON envelope as Claude | **No reliable ask** — hooks can fail open on ask, so strict/CI map ask→deny (doctor warns) | Fail-open risk is the host's; that's why the mapping exists | Documented + Agent Night Watch findings |
| Gemini (LEGACY) | `{"decision": "deny", "reason"}` / `{"decision": "allow"}` | No — ask is surfaced as a deny for human review | Host-defined | Community/AGET contract write-ups. **LEGACY**: the consumer Gemini CLI was switched off 2026-06-18 and replaced by Antigravity CLI (`agy`, `.agents/hooks.json`). Antigravity support is pending a documented hook contract from Google. |
| Cursor | `{"permission": "deny"/"ask"/"allow", "user_message", "agent_message"}` | Yes (permission ask) | Host-defined | Documented preToolUse contract |
| Cline | `{"cancel": bool, "errorMessage"}` | No — ask maps to cancel + "blocked for human review" note | **Fail-open** (documented: script errors allow execution) | Documented hooks contract (PreToolUse, `.clinerules/hooks/`) |
| OpenCode | JS plugin (`tool.execute.before`) — throw to block | No ask in that hook — ask maps to a throw with the safer path named | Plugin exceptions block that call | Documented plugin API; experimental shim, simulated tests only |

Notes:

- "Ask→deny mapping" (Codex under strict/CI; Gemini and Cline
  always) exists because an ask that nobody sees is an allow with
  extra steps. The reason text says when a mapping happened.
- Shadow mode (`SEATBELT_MODE=shadow`) is agent-independent: verdicts
  are audited, nothing is emitted, on every surface.
- Canary trips deny on every surface in every mode — including
  shadow and audit — because a decoy credential has no legitimate
  reader (Cline/OpenCode deliver it through their own block shapes).
