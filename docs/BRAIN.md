# Memory drift watch

An agent's instruction files — `CLAUDE.md`, `AGENTS.md`,
`GEMINI.md`, `.cursor/rules`, `.claude/settings.json` — are its
long-term memory and its standing orders. Whoever edits them
steers every future session. That makes them the quietest attack
surface in the stack: poison the memory once and the agent
re-infects itself forever, no exploit required.

The research agrees. AgentPoison showed that poisoning an agent's
long-term memory or knowledge base compromises later behavior with
very few injected samples. MINJA demonstrated memory injection
against agents that learn from interaction history, using only
queries a normal user could make. MemGhost (described in July 2026
write-ups of memory-ghosting attacks) showed persistent instructions
surviving inside agent memory stores. OWASP's Agentic Top 10 files
this under **ASI06: Memory & Context Poisoning**.

## What Seatbelt does

- A **baseline** of the brain files (project + user level) — sha256
  plus full text — lives in `~/.claude/seatbelt/brain/`, itself
  inside Seatbelt's self-protection zone (the agent cannot edit it).
- At SessionStart, drift is reported **only when it exists**: which
  files changed, how many lines were added/removed, and any
  *instruction-shaped* added lines ("always…", "never…", "allow…",
  "run…") quoted **verbatim**, so the human sees the actual words
  someone tried to teach their agent. The same drift is reported
  once per drift version (deduped by drift hash), never as nagging.
- The baseline moves **only** when a human runs
  `python3 hooks/seatbelt_hook.py --baseline --accept` in their own
  shell — and that move is audit-logged. Repeated malicious edits
  cannot launder themselves into the baseline.
- A brain-file edit requested **while the session is tainted** by
  flagged injected content (see `docs/INJECTION.md`) escalates:
  deny in strict/ci modes, a warned ask in solo. The edit isn't
  presumed malicious — but that sequence (read poison → edit
  memory) is exactly the poisoning shape, so a human looks first.

Inspect any time: `python3 hooks/seatbelt_hook.py --brain`.

## Limits

Drift watch detects *change*, not *intent* — legitimate edits trip
it too, by design, and the human glances and re-baselines. It
covers the enumerated brain files, not every place an agent can
store state (vector stores, provider-side memory, chat history).
Pair it with version control on your instruction files for a real
history.
