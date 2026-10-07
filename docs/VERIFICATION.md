# Verification battery — Agent Seatbelt 0.2.0 (Round 8, Z5)

Run on the final tree, 2026-10-07. Every item below was executed
against the files in this repository as they stand. Anything that
failed is named, with what was done about it.

## 1. Full pytest suite

**275 tests, all passing.** Breakdown: library 34 (unchanged from
0.1.0), hook battery + rounds 2–8 suites + no-network 241.

Correction (independent verification, 2026-10-07): an earlier draft of
this section said 389. That figure could not be reproduced — a clean
collection on the final tree yields 275 tests, and a full independent
re-run passed 275/275. The document now carries the reproducible
number; the discrepancy is recorded here rather than silently fixed.

Honest footnote: in one full-suite run, two tests failed —
`test_standalone_copy_in_empty_dir` and `test_robustness_sample` —
during a window when the build sandbox itself restarted mid-run
while a 10,000-payload robustness job was executing concurrently.
Both were re-run in isolation on a quiet machine and pass. They are
recorded here rather than silently absorbed.

A real bug was found and fixed by this battery (§6): the loop guard
could soften a deny to an ask on the third identical repeat. A
regression test (`test_loop_guard_never_softens_a_deny`) now guards
the strictest-wins invariant.

## 2. Standalone-copy test

`hooks/seatbelt_hook.py` + `experimental/mods/policy.js` copied
alone into an empty directory:

- `SELFTEST: 68/68 passed, 0 failed (seatbelt v0.2.0)`
- Simulated `rm -rf /` payload → deny envelope with blast radius.
- JS policy evaluates the same command → deny.

## 3. Clean-venv wheel install

```
Successfully built agent_seatbelt-0.2.0-py3-none-any.whl
installed version: 0.2.0
34 passed (library tests against the installed wheel)
```

## 4. Bench, fuzz, robustness, head-to-head (bench v1)

- Curated bench: **206/206 = 100.0%, false positives 0**
  (full category table in `docs/BENCH.md`).
- GuardFall fuzz: **1431/1431 = 100.0%, 4 softened** (deny→ask).
- Injection bench: **15/15 caught, 0/10 FP — PASS**.
- Robustness: **10,000/10,000 in-process clean** (0 errors, 0 bad
  JSON); **subprocess sample 300/300 clean** (0 crashes, 0 bad
  stdout). Contract: always exit 0, stdout empty-or-valid-JSON,
  fail closed.
- Naive single-regex blocker, same corpus: **42/206 = 20.4%**.

## 5. Per-agent simulated payload decisions

Simulated payloads per documented contract, `rm -rf /`:

| Agent | Output |
|---|---|
| Claude Code | `permissionDecision: deny` |
| Codex | `permissionDecision: deny` |
| Gemini (LEGACY) | deny envelope (after fresh-session check — see note) |
| Cursor | deny/ask envelope per contract |
| Cline | `{"cancel": true, "errorMessage": "Seatbelt: recursive forced deletion…"}` |
| OpenCode | shim throws on deny/ask (node tests, simulated args) |

Note: an early spot-check appeared to show ask-tier results on two
surfaces for a repeated payload — that was the §6 loop-guard bug
surfacing through shared session state, now fixed and re-verified
(deny ×4 on repeat). All surfaces remain **simulated-tested, not
live-tested**.

## 6. Round acceptance fixtures

- **Snapshots/restore**: round-trips green (delete, edit, symlink
  restored as link, caps honesty in manifest, restore-of-restore,
  no snapshot for denied actions) — `tests/test_round5.py`.
- **Canaries**: plant → registry hashes-only → read trip denies and
  logs without the value → value-in-curl denies **even in audit
  mode** → innocent `.env` unaffected → `--remove` cleans up —
  `tests/test_round8.py` + bench canary 4/4.
- **Brain drift**: quiet when clean; drift quotes poison lines;
  dedupe by drift hash; `--baseline --accept` clears; tainted edit
  escalates; store self-protected — `tests/test_round6.py`.
- **MCP drift**: baseline stores no secret values (grep-verified);
  new tool surface + config change drift; verdicts escalate;
  human re-baseline absorbs — `tests/test_round7.py`.
- **Shadow mode**: emits nothing, audits would-be verdicts, report
  carries the shadow section — `tests/test_round7.py`.
- **Flight plan PocketOS fixture**: staging plan vs production
  volume delete passes both directions (on-plan defer, off-plan
  ask solo / deny ci) — bench plan 8/8 + `tests/test_round6.py`.
- **Hash chain**: verifies clean; tamper detected at the correct
  line; ANSI-laced payload produces a clean chained record —
  `tests/test_round3.py`, `tests/test_round4.py`.
- **`--check-file`**: deny line reported with rule id; exit 1 on
  deny, 0 when clean (the GitHub Action treats any non-zero as
  failure — fixed in this round to match).
- **Doctor**: `DOCTOR: 15/15 checks passed` on a clean project,
  including audit chain, snapshots, taint, brain, MCP, canaries.
- **Evidence bundle**: `--report --evidence` parses as JSON;
  `chain_verified: true` on a live log.
- **Feed scaffolder**: refuses (exit 2, project-law message) an
  entry without bench cases.
- **Loop guard**: benign repeat asks at #3; **deny never softens**
  (regression test added this round).

## 7. No-network proof

`tests/test_no_network.py` passes over the final tree (AST scan for
network imports and dynamic network calls across the hook, library,
bench, and feed code paths).

## 8. Latency (final, clean sequential runs)

```
ALL (30 rounds)        median 153.5 ms   p95 180.6 ms
snapshot path          median 149.1 ms   p95 237.6 ms
rehearsal path (stub)  median 156.6 ms   p95 171.4 ms
```

## Cuts and non-goals (unchanged)

Nothing was cut in Round 8. Standing non-goals from earlier rounds
remain: kernel/eBPF layers, phone approvals, live-agent testing
(all envelopes simulated), Antigravity envelope (no documented
contract to build against — recorded in `docs/AGENTS.md`).

## Gate

Everything on this page is local. Nothing has been pushed,
published, submitted, or posted. The tree is left built and green
for the parent agent's release step, on Ryan's explicit word.
