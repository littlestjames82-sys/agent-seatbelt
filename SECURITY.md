# Security policy

## Reporting a vulnerability

Please report security issues privately — do not open a public issue
for a bypass or a flaw in the gate itself.

- Preferred: GitHub private vulnerability reporting on this repository
  ("Security" tab → "Report a vulnerability").
- Or email the studio: gdev6145@gmail.com with subject
  `[agent-seatbelt security]`.

We aim to acknowledge within 3 business days. Bypasses are taken
seriously and, with your permission, credited — a published bypass
corpus makes every user safer, which is why the bench lists its own
misses by name.

## Scope notes

- The hook is a single Python file using only the standard library and
  makes **no network calls** (there is a test that proves the import
  surface). It runs with the user's own privileges, at the user's
  request, on the user's machine.
- The audit log is hash-chained for tamper evidence (`--verify-log`),
  and records are redacted (secret type + length, never values) and
  sanitized (ANSI/control stripped) before they are written.
- Snapshots under `.seatbelt/snapshots/` are local pre-action copies,
  not backups: they share fate with the disk they sit on.
- Known limits are documented in `docs/THREAT_MODEL.md`. The honest
  one-line version: Seatbelt gates the tool-call path of supported
  agents; it cannot see API calls made outside the agent's tools, and
  a determined paraphrase can evade any string-based detector — the
  defenses are layered (normalization, gating, snapshots, taint
  escalation) precisely because no single layer is a proof.

## Supported versions

Only the latest release receives fixes. The hook targets Python 3.8+
syntax (verified by test) and the plugin targets Claude Code's
documented hook contract.
