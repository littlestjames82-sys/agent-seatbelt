# Verification — Agent Seatbelt, 0.3.2 candidate tree

Run October 14, 2026, against an isolated copy of repository main
at commit 6b5d84a105785a51b627439611e26c3b4f071ebf (the 0.3.1
release plus the Phase 1 documentation reconciliation, the CI
executable-mode fix, and the Phase 2 audit remediation). The copy
was verified file-for-file against the remote before anything ran:
118 of 118 blobs matched by hash, no extras, no missing files, and
no `.git`, caches, or `.seatbelt` state inside it. Interpreter:
Python 3.12.3. Every item below was executed against that copy.
Anything that failed is named, with what was done about it.

Version strings in this tree still read 0.3.1 (pyproject, library
`__init__`, hook VERSION). This document verifies the tree proposed
to carry the 0.3.2 tag; the version bump, tag, and PyPI release are
separate steps and have not happened yet.

## 1. Full pytest suite

**379 tests, all passing** on the isolated tree (292 s). That is
the 363 tests of the 0.3.1 release plus 16 new tests
(tests/test_round11_phase2.py) covering the Phase 2 audit's
config-plane and envelope-shape fixes, which the bench cannot
express. An earlier run of the same suite during remediation
passed 378 of 379; the single failure was a missing remediation
text for a new rule, fixed and re-verified before this run.

## 2. Curated bench

**272 of 272 cases, 0 false positives** (bench/run_bench.py). The
corpus is the 221-case 0.3.1 corpus plus 51 cases added by the
Phase 2 audit (42 in the main remediation, 9 in the residual
batch), each with a benign near-miss. The benign category, the
false-positive guard, is 51 of 51. Full category table:
docs/BENCH.md, top section.

## 3. GuardFall fuzz

**1,853 of 1,853 mutations caught, 0 misses, 4 softened**
(deny-to-ask under mutation, the same count as the 0.3.1
baseline). The mutation space grew with the corpus (1,431
mutations at 0.3.1). bench/fuzz.py.

## 4. Injection bench

**PASS: 15 of 15 positives caught, 0 of 10 benign false
positives** (bar: at least 13 of 15 caught, at most 1 of 10 FP).
bench/run_injection.py.

## 5. Selftest

**68 of 68** (hooks/seatbelt_hook.py --selftest).

## 6. Latency

Subprocess end-to-end, including Python startup, 25 rounds each,
sequential, on a quiet machine (sandbox VM):

```
allow (git status)     median  179.3 ms   p95  200.0 ms
deny (rm -rf /)        median  171.4 ms   p95  204.4 ms
defer (make build)     median  176.1 ms   p95  224.1 ms
ALL                    median  174.3 ms   p95  204.4 ms
```

The 0.3.1 tree measured 163.5 ms median under the same method. The
difference is the Phase 2 decoded-forms and DNS-substitution
passes; it is recorded, not rounded away. A run of the same
harness while the test suite executed concurrently read a 447 ms
median and is not the recorded figure; load is the whole story
there, and the quiet figure is the comparable one.

## 7. Naive baseline head-to-head

The single-regex rm -rf blocker (bench/runners/naive_blocker.py)
scored through the 272-case corpus (bench/run_external.py):
**56 of 272 (20.6%)**, 216 misses, every miss printed by name in
the scorer output. On the 221-case corpus it scored 46 of 221
(20.8%); the baseline did not get better, the corpus got wider.

## 8. Standalone copy

hooks/seatbelt_hook.py copied alone into an empty directory:

- --selftest: 68 of 68.
- A live PreToolUse envelope for `rm -rf /` returns deny.
- --doctor: 14 of 16 in the bare directory. The two failures are
  the companion-file checks (hooks/hooks.json and
  .claude-plugin/plugin.json), which do not exist in a bare
  directory by construction; on the built tree --doctor is 16 of
  16. The standalone claim is about the hook file itself, and it
  holds.

## 9. Build and clean-venv install

Built from the isolated tree (python -m build):

- sdist: 119 files, **zero** `.seatbelt` state files (the Phase 2
  supply-chain fix verified on this tree's build, not just on the
  tree where the fix was written).
- wheel: zero Requires-Dist entries (stdlib only).
- twine check: PASSED for both artifacts.
- A fresh venv installed the wheel with `pip install --no-index`
  (no network, no index) and `import agent_seatbelt` succeeds.

## 10. Robustness battery

**10,000 of 10,000 in-process payloads processed, 0 failures,
and 300 of 300 subprocess samples, 0 failures** (the checkpointed
segmented driver bench/robustness_segmented.py, running the
bench/robustness.py generator against this tree). The run started
October 14, 2026 and completed October 15, 2026; its final
checkpoint state records an empty failure list and zero subprocess
failures. Verdict: PASS.

## 11. Continuous integration

The remediation commit's GitHub Actions run completed with all
five jobs green (Python 3.9, 3.10, 3.11, 3.12, 3.13) — the second
consecutive fully green run after the executable-mode fix that
closed the pre-existing CI failure.

## What this verification does not cover

- Live host behaviour. Every non-Claude-Code surface remains
  simulated-tested only (docs/AGENTS.md); live testing is Phase 3
  of the work plan and needs real host installs.
- Independent or held-out evaluation. Every corpus above is ours.
  The held-out bench is Phase 5.
- The 0.3.2 release itself: version bump, tag, PyPI publish, and
  release-asset attachment are gated steps that follow this
  document, not part of it.
