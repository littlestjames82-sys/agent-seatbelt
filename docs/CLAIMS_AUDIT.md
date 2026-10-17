> **Status (October 14, 2026): the refresh below audits the
> current public copy and the 0.3.2 candidate tree.** The original
> audit (0.2.0 claims) follows it, unedited, as history.

# Claims audit refresh — October 14, 2026

Scope: README headline and capability copy, docs/BENCH.md,
docs/SECURITY_AUDIT_0.3.2.md, docs/VERIFICATION_0.3.2.md, the
GitHub repo description, and the Pages site. Evidence runs are
the October 14, 2026 isolated-tree verification
(docs/VERIFICATION_0.3.2.md) and the Phase 2 audit.

| # | Claim (where) | Evidence | Verdict |
|---|---|---|---|
| R1 | "Seatbelt Bench (0.3.1) 221/221 · GuardFall fuzz 1431/1431 · Naive 46/221 · Injection 15/15, 0 FP" (README banner, repo description, Pages site) | Phase 1 re-run on the isolated 0.3.1 tree, October 14, 2026: 221/221, fuzz 1431/1431 with 4 softened, naive 46/221, injection PASS | kept — describes the released 0.3.1 exactly |
| R2 | Candidate-tree figures: bench 272/272, fuzz 1853/1853, naive 56/272 (BENCH.md top section, VERIFICATION_0.3.2.md, SECURITY_AUDIT_0.3.2.md) | Executed October 14, 2026 on the isolated 6b5d84a tree (118/118 blobs verified) | kept — labelled candidate tree everywhere it appears; the README banner does NOT carry these numbers until 0.3.2 is actually released |
| R3 | "379 tests" (VERIFICATION_0.3.2.md) | Full pytest on the isolated tree: 379 passed (363 at 0.3.1 + 16 Phase 2 tests) | kept |
| R4 | "Robustness 10,000/10,000 + 300/300" (SECURITY_AUDIT_0.3.2.md, VERIFICATION_0.3.2.md) | Segmented battery, October 14, 2026; the audit's run covers the shipped 0.3.1 code, the verification run covers the candidate tree | kept, with the per-tree scoping stated in both documents |
| R5 | "Hash-chained audit log detects tampering" (README) | Phase 2 integrity exercise: mid-log verdict flip detected at the altered line; silent TAIL truncation is NOT detectable — copy that implies more than tamper-evident is wrong | kept as tamper-evident only; the limit is stated in SECURITY_AUDIT_0.3.2.md and the threat model |
| R6 | "One self-contained Python file, stdlib only" (README) | Standalone copy in an empty directory: selftest 68/68, live deny; wheel declares zero Requires-Dist | kept |
| R7 | Per-agent support rows (README, docs/AGENTS.md) | Simulated-payload batteries only; no host was live-tested in this cycle | kept with the simulated-tested label; no row was upgraded |
| R8 | Snapshot caps "2,000 files / 256 MB / 64 MB per file" (README, SNAPSHOTS.md) | Unchanged code path; cap tests in the 379 | kept |
| R9 | Latency "~163 ms median" (0.3.1 BENCH section) | Candidate tree measures 174.3 ms median, same method; the 0.3.1 figure stays attached to the 0.3.1 section | kept, dated per section; no blended figure anywhere |
| R10 | "First / only / sandbox" style claims (anywhere) | Sweep of README, docs, site copy for this refresh | removed (class) — none present; Seatbelt is described as a policy gate, not a sandbox, in every current surface |

Process note: this refresh exists because the 0.2.0 audit's
numbers kept presenting as current after two releases. The rule
it establishes: a number may headline only the tree it was
measured on, and every headline carries its version.

# Claims audit (Round 8, Z3)

Every capability sentence in the public copy (README, docs,
playground, launch drafts) mapped to the evidence that proves it.
Verdicts: **kept** (proven as written), **reworded** (claim adjusted
to match evidence), **removed**.

| # | Claim (where) | Evidence | Verdict |
|---|---|---|---|
| 1 | "Bench v1 206/206, false positives 0" (README, playbook, film) | `bench/run_bench.py` full run 2026-10-07: 206/206, FP 0 | kept |
| 2 | "GuardFall fuzz 1431/1431" (README, playbook) | `bench/fuzz.py`: 1431/1431, 4 softened — softened count printed next to the score in BENCH.md | kept (with the softened disclosure) |
| 3 | "Naive regex scores 42/206 (20.4%)" (README, bench/README, playbook, film, social image) | `bench/runners/naive_blocker.py` + `run_external.py`: 42/206 = 20.4%, 164 misses | kept |
| 4 | "Injection 15/15, 0 FP" (README, INJECTION.md) | `bench/run_injection.py`: 15/15 caught, 0/10 FP, PASS | kept |
| 5 | "Robustness 10,000 payloads, 0 crashes" (BENCH.md, TEAM_ADOPTION) | `bench/robustness.py 10000`: 10000/10000 in-process, 300/300 subprocess sample | kept |
| 6 | "No network / never phones home" (README, FEED_RUNBOOK) | `tests/test_no_network.py` AST scan over the whole tree incl. feed paths | kept |
| 7 | "One self-contained Python file, stdlib only" (README) | Standalone-copy battery: hook alone in an empty dir passes selftest 68/68 + live deny (VERIFICATION.md) | kept |
| 8 | "Snapshots: 2,000 files / 256 MB caps, recorded in manifest" (README, SNAPSHOTS.md) | `tests/test_round5.py` cap tests assert manifest `caps_hit`/`skipped` honesty | kept |
| 9 | "Restore never deletes newer files" (SNAPSHOTS.md, hook output) | Round-trip tests incl. restore-of-restore; the sentence is printed by `--restore` itself | kept |
| 10 | "Hash-chained audit; --verify-log detects tampering" (README) | `test_round3.py` chain test: tamper detected at the right line; ANSI sanitization test (round 4) | kept |
| 11 | "MCP baseline stores env key names only, never values" (README, COMPLIANCE) | `test_round7.py` greps the written baseline for a planted secret value — absent | kept |
| 12 | "Canary registry stores hashes only" (README) | `test_round8.py`: planted token value asserted absent from registry AND from audit log | kept |
| 13 | "Canaries deny in every mode" (README, AGENTS.md) | Round-8 test: trip denied with SEATBELT_MODE=audit; code path runs before mode dispatch | kept |
| 14 | "Per-agent envelopes for Codex/Cursor/Cline; Gemini LEGACY" (README, AGENTS.md) | Simulated-payload batteries (rounds 2, 7, 8). NOT live-tested — every surface says so | kept (with the simulated label) |
| 15 | "OpenCode support" (README table, experimental README) | Documented plugin API + simulated node tests of the shim's mapping | reworded → "Experimental JS plugin shim", ask described as block-delivered |
| 16 | "Antigravity support" (examples/README) | Google has not published a hook contract we could verify | reworded → "pending a documented hook contract"; no envelope shipped |
| 17 | "Mods edition" (experimental/README) | JS logic unit-tested incl. bench parity spot-check (32 node tests); Mods runtime not live-testable here | kept as EXPERIMENTAL with the unsandboxed warning verbatim |
| 18 | "Rehearsal previews never change verdicts" (README) | `test_round6.py` stub-binary tests incl. timeout + composite-skip; preview string asserted absent from decision logic | kept |
| 19 | "Flight plans never cover denials/locked rules" (README, SKILL.md) | `test_round6.py` never-cover tests + bench plan cases 8/8 incl. PocketOS both directions | kept |
| 20 | "Brain baseline moves only via human --baseline --accept" (README, BRAIN.md) | `test_round6.py`: baseline refuses overwrite without --accept; accept clears drift; store is self-protected | kept |
| 21 | "Latency median ~153 ms" (BENCH.md) | `bench/latency.py 30` clean sequential run 2026-10-07 + itemized snapshot/rehearsal timings | kept (dated, method stated) |
| 22 | "SOC 2 / EU AI Act compliance" (COMPLIANCE.md) | The doc maps evidence artifacts to criteria and carries "not a certification, not legal advice"; EU dates double-checked against the Round-7 research report (Annex III deferred to 2027-12-02) | kept (as evidence mapping, never as certification) |
| 23 | "24-hour disaster-feed SLA" (FEED_RUNBOOK, playbook) | Runbook is operational fact; the public commitment line is flagged "Ryan's call to publish" and is NOT in public copy | kept (internal) / not published |
| 24 | "First / only" style claims (anywhere) | Z3 sweep: none survive; comparison section rewritten to verifiable, competitor-respecting statements | removed (class) |
| 25 | Playground copy: "the full rule set lives in the Python hook; this port covers the Bash core" (playground.html) | policy.js header + parity spot-check limited to Bash cases | kept |

Process note: this audit ran over README.md, docs/*.md,
LAUNCH_POSTS_DRAFT.md, the launch playbook/film, playground copy,
and the social preview. Anything that couldn't be pointed at a
test, a bench run, or a cited source was reworded or deleted —
notably the Antigravity and "first/only" classes above.
