# Agent Seatbelt v0.3.0 — full-scale robustness battery result

The last unmet v0.3.0 gate item: the SHINE4 V5 hostile-input robustness
battery at full scale — 10,000 in-process payloads + 300 subprocess
payloads (seed 20261006), run via `bench/robustness_segmented.py`
(imports the identical payload generator and per-payload checks from
`bench/robustness.py`).

## FINAL VERDICT: ROBUSTNESS: PASS

| Phase | Result |
|---|---|
| In-process | **10,000/10,000 payloads OK, 0 failures** |
| Subprocess sample | **300/300 OK, 0 failures** |
| **Overall** | **PASS — total failures: 0** |

Runner output (verbatim, from `robustness-segmented-run.log`,
2026-10-10T23:31:53Z):

```
Robustness (in-process): 10000/10000 payloads OK, 0 failures
Robustness (subprocess sample): 300/300 OK
ROBUSTNESS: PASS
```

Run facts: started 2026-10-10T20:33Z, finished 23:31:53Z; 46 chunks;
10,473s (~2h55m) of runner time. One VM/service restart (~22:15Z)
killed the driver loop mid-run; it resumed from the on-disk checkpoint
at 5,500/10,000 having lost only the chunk in flight — the
restart-proofing live-tested. No isolated re-checks were needed: the
subprocess phase recorded zero failures in the main run (see below
for why a re-check rule existed).

## How the runner works / equivalence evidence

- Checkpoint: `~/workspace/agent-seatbelt/robustness-segmented-state.json`
  (atomic write after every 250-payload in-process chunk and every
  50-payload subprocess chunk; re-running resumes where it stopped).
  Final state: next=10000, sub_next=300, failures=[], sub_failures=0,
  chunks_done=46. Run log: `~/workspace/agent-seatbelt/robustness-segmented-run.log`
- Payload equivalence: sha256 of all 10,000 payloads from the
  monolithic whole-pool generation vs the runner's slice generation —
  identical, in order. Same payloads, same `check_one()` assertions,
  same subprocess criteria (rc != 0 or "Traceback" in stderr, 30s
  timeout), same scale. Segmentation changes scheduling only.
- Runner mechanics were validated at reduced scale first (count=200,
  subprocess=2, chunk=64): state advanced 64 → 128 → 192 → 200 across
  separate processes, final verdict lines matched the monolithic
  script's format exactly, exit 0.
- One deliberate deviation from the monolithic script, toward a
  complete tally: a subprocess timeout is recorded as a failure
  ("timeout after 30s") instead of crashing the run
  (`robustness.py` lets TimeoutExpired propagate — a timeout there
  means no verdict at all, which is what happened to the monolithic
  validation run described below).

## Subprocess timeouts and the re-check rule (pre-registered)

Before the run, this rule was written down: any subprocess failure
would get ONE isolated re-check under the identical criterion (fresh
subprocess, same payload, 30s limit), with both outcomes reported;
a payload failing its re-check would be a genuine battery failure.

Why: payload #2 is a 5,000,129-byte `echo AAAA…` command. The hook
answers it correctly every time (exit 0, well-formed decision JSON,
no stderr) but needs ~21s of CPU. During early testing this VM
(2 vCPUs) ran at load average ~5.5–10.7 from other tenants, inflating
that payload's wall-clock to 43–57s: the monolithic `robustness.py`
validation run (--count 200 --subprocess 60) crashed outright with
`subprocess.TimeoutExpired` on it, while on Oct 9 the same sample
passed in a 71s total run on a quieter box.

Outcome: **the rule never had to be used.** By the time the battery's
subprocess phase ran (23:24–23:31Z, load ~1.3–2.6), all 300 payloads —
including #2 — passed within the 30s limit in the main run. The
battery is a clean PASS on its own terms, with no environmental
asterisk on the final tally.

Progress milestones (all 0 failures): 250 @20:41Z · 1,000 @20:51Z ·
2,000 @21:10Z · 4,250 @21:51Z · 5,000 @22:04Z · restart/resume from
5,500 ~22:17Z · 7,750 @22:50Z · 9,000 @23:12Z · 10,000 + subprocess
300/300 @23:31Z.

## Gate status

With this PASS, every v0.3.0 verification item is green:
pytest 301/301, Seatbelt Bench 221/221, selftest 68/68,
injection 15/15 + 0/10 false positives, GuardFall fuzz 1431/1431,
build + twine check, and now the full-scale robustness battery
10,000 + 300 with 0 failures. **The v0.3.0 "go if green" condition is
met.** (Release/tag/PyPI remain separate steps for the main agent —
nothing was released by this run.)
