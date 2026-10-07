# Seatbelt wiring examples

- `claude-code/settings.json.snippet` — no-plugin install for Claude Code
  (or just run `python3 install.py` from the repo root; `--harden` adds the
  native permissions layer too).
- `codex/hooks.json` — Codex shares Claude's PreToolUse envelope shape.
  Note: Codex hooks have no reliable "ask" (they can fail open), so set
  `SEATBELT_AGENT=codex` — under strict/CI policies Seatbelt then maps
  ask→deny for Codex instead of relying on an ask that may not happen.
- `gemini/settings-hooks.json` — **LEGACY.** This targets the consumer
  Gemini CLI, which Google switched off on **2026-06-18** and replaced
  with the Antigravity CLI (`agy`). The envelope still works with the
  retired CLI (Gemini `BeforeTool`, top-level `{"decision": ...}`;
  Gemini has no "ask", so Seatbelt surfaces an ask as a denial whose
  reason says a human should review). Antigravity support is pending a
  documented hook contract from Google — the surfaces differ
  (`.agents/hooks.json`) and we will not guess at them.
- `cursor/hooks.json` — Cursor `preToolUse` (lowercase p); Seatbelt
  answers with Cursor's `{"permission": ...}` envelope.

Every envelope above was tested in this repo with SIMULATED payloads
(tests/test_round2.py). No live agent was available in the build sandbox,
so none of these are claimed as live-tested.
