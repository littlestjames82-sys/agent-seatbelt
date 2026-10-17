# Bench results — Agent Seatbelt

## 0.3.2 — run October 14, 2026 (current)

All numbers in this section come from real runs on October 14, 2026
against an isolated copy of repository main at commit 6b5d84a (the
0.3.1 release plus the Phase 2 audit remediation), verified
file-for-file against the remote (118 files, blob hashes matched;
Python 3.12.3). At measurement time this tree's version strings
still read 0.3.1; it was released as v0.3.2 on October 17, 2026.
The audit behind the new cases is
docs/SECURITY_AUDIT_0.3.2.md; the consolidated verification record
is docs/VERIFICATION_0.3.2.md.

### Curated bench — 272/272 (100.0%), false positives 0

```
category          total   pass    score
alias                 7      7   100.0%
anti-forensics        1      1   100.0%
benign               51     51   100.0%
brain                 6      6   100.0%
canary                4      4   100.0%
cloud-db             15     15   100.0%
cloud-delete          2      2   100.0%
deploy                8      8   100.0%
destructive          33     33   100.0%
evasion              28     28   100.0%
exfil                 5      5   100.0%
exfiltration          2      2   100.0%
exposure              5      5   100.0%
file-gating           5      5   100.0%
git                   8      8   100.0%
git-destructive       1      1   100.0%
interpreter           6      6   100.0%
judge                 8      8   100.0%
loop                  1      1   100.0%
mcp                   1      1   100.0%
obfuscation           5      5   100.0%
permissions           1      1   100.0%
persistence          14     14   100.0%
pipe-to-shell         5      5   100.0%
plan                  8      8   100.0%
powershell           15     15   100.0%
script-content        8      8   100.0%
secrets              11     11   100.0%
skills                7      7   100.0%
system-control        1      1   100.0%
TOTAL               272    272   100.0%
False positives (benign cases not matching): 0
```

The 272-case corpus is the 221-case 0.3.1 corpus (next section)
plus 51 cases added by the Phase 2 audit, every fix shipping with
a benign near-miss. The benign category is the false-positive
guard: 51 legitimate lookalikes that must NOT be blocked. It
scores 51/51.

### GuardFall fuzz — 1853/1853 (100.0%), 4 softened

```
GuardFall score: 1853/1853 mutations caught = 100.0%
Softened (deny -> ask under mutation): 4
Mutations generated: 1853 (from 146 dangerous cases)
```

### Injection bench — 15/15 caught, 0/10 false positives

```
Positives caught (taint written): 15/15
Benign false positives: 0/10
INJECTION BENCH: PASS (bar: >=13/15 caught, <=1/10 FP)
```

### Selftest — 68/68

```
SELFTEST: 68/68 passed, 0 failed (seatbelt v0.3.1)
```

### Latency — subprocess end-to-end (includes Python startup)

Measured October 14, 2026, 25 rounds each, sequential, quiet
sandbox VM:

```
allow (git status)     median  179.3 ms   p95  200.0 ms
deny (rm -rf /)        median  171.4 ms   p95  204.4 ms
defer (make build)     median  176.1 ms   p95  224.1 ms
ALL                    median  174.3 ms   p95  204.4 ms
```

Slightly above the 0.3.1 figure (163.5 ms) — the Phase 2
decoded-forms and DNS-substitution passes cost measurable time,
recorded here rather than rounded away.

### Head-to-head: the naive baseline on the 272-case corpus

```
External runner vs Seatbelt Bench — 272 cases evaluated
TOTAL               272     56    20.6%
```

216 misses, every one printed by name in the scorer output.

### Robustness

10,000 of 10,000 in-process payloads, 0 failures, and 300 of 300
subprocess samples, 0 failures, on this tree
(bench/robustness_segmented.py; run completed October 15, 2026).
Verdict: PASS. Full record: docs/VERIFICATION_0.3.2.md, section 10.

---

## 0.3.1 — run October 14, 2026

All numbers in this section come from real runs on October 14, 2026
against an isolated copy of the shipped 0.3.1 tree (109 files, no
`.git`, caches, or `.seatbelt` state; `sha256sum -c SHA256SUMS`
passed, 74 files; Python 3.12.3). Reproduce any of them:
`bench/README.md` has the commands. Misses, when they exist, are
printed by name by every runner — none are hidden here either.

### Curated bench — 221/221 (100.0%), false positives 0

```
category          total   pass    score
alias                 7      7   100.0%
benign               39     39   100.0%
brain                 6      6   100.0%
canary                4      4   100.0%
cloud-db             15     15   100.0%
deploy                8      8   100.0%
destructive          19     19   100.0%
evasion              28     28   100.0%
exfil                 5      5   100.0%
exposure              5      5   100.0%
file-gating           5      5   100.0%
git                   8      8   100.0%
judge                 8      8   100.0%
loop                  1      1   100.0%
mcp                   1      1   100.0%
persistence          13     13   100.0%
pipe-to-shell         4      4   100.0%
plan                  8      8   100.0%
powershell           12     12   100.0%
script-content        7      7   100.0%
secrets              11     11   100.0%
skills                7      7   100.0%
TOTAL               221    221   100.0%
False positives (benign cases not matching): 0
```

The 221-case corpus is the 0.2.0 Bench v1 corpus (206 cases, next
section) plus the 15 cases added in 0.3.0 (judge 8, skills 7). The
`benign` category is the false-positive guard: 39 legitimate
lookalikes that must NOT be blocked. It scores 39/39.

### GuardFall fuzz — 1431/1431 (100.0%), 4 softened

```
GuardFall score: 1431/1431 mutations caught = 100.0%
Softened (deny -> ask under mutation): 4
Mutations generated: 1431 (from 113 dangerous cases)
```

"Softened" means the mutation still stopped for a human but at ask
tier instead of deny — counted honestly, with the same disclosure
as the 0.2.0 report.

### Injection bench — 15/15 caught, 0/10 false positives

```
Positives caught (taint written): 15/15
Benign false positives: 0/10
INJECTION BENCH: PASS (bar: >=13/15 caught, <=1/10 FP)
```

### Selftest — 68/68

```
SELFTEST: 68/68 passed, 0 failed (seatbelt v0.3.1)
```

### Latency — subprocess end-to-end (includes Python startup)

Measured October 14, 2026, 30 rounds each, sequential, sandbox VM
(a different machine from the 0.2.0 run; compare with care):

```
allow (git status)     median  163.5 ms   p95  178.8 ms
deny (rm -rf /)        median  165.6 ms   p95  209.2 ms
defer (make build)     median  161.4 ms   p95  189.2 ms
ALL                    median  163.5 ms   p95  189.2 ms
```

### Head-to-head: the naive baseline on the 221-case corpus

`bench/runners/naive_blocker.py` scored through the current corpus
(`bench/run_external.py`):

```
External runner vs Seatbelt Bench — 221 cases evaluated
TOTAL               221     46    20.8%
```

175 misses, every one printed by name in the scorer output.

### Not re-run for 0.3.1 in this pass

The 10,000-payload robustness battery was not re-run for 0.3.1.
The last full robustness run is the 0.3.0 segmented run
(10,000/10,000 in-process, 300/300 subprocess — see
ROBUSTNESS_FULL_RESULT.md). No number in this section should be
read as a 0.3.1 robustness result.

---

## 0.2.0 — run October 7, 2026 (Bench v1 baseline, historical)

All numbers on this page come from real runs of the shipped tree on
2026-10-07. Reproduce any of them: `bench/README.md` has the
commands. Misses, when they exist, are printed by name by every
runner — none are hidden here either.

## Curated bench — 206/206 (100.0%), false positives 0

```
category          total   pass    score
alias                 7      7   100.0%
benign               39     39   100.0%
brain                 6      6   100.0%
canary                4      4   100.0%
cloud-db             15     15   100.0%
deploy                8      8   100.0%
destructive          19     19   100.0%
evasion              28     28   100.0%
exfil                 5      5   100.0%
exposure              5      5   100.0%
file-gating           5      5   100.0%
git                   8      8   100.0%
loop                  1      1   100.0%
mcp                   1      1   100.0%
persistence          13     13   100.0%
pipe-to-shell         4      4   100.0%
plan                  8      8   100.0%
powershell           12     12   100.0%
script-content        7      7   100.0%
secrets              11     11   100.0%
TOTAL               206    206   100.0%
False positives (benign cases not matching): 0
```

The `benign` category is the false-positive guard: 39 legitimate
lookalikes (one named file's `rm`, staging deploys, security writing
that quotes attacks) that must NOT be blocked. It scores 39/39.

## GuardFall fuzz — 1431/1431 (100.0%), 4 softened

Programmatic mutations of every dangerous case (quote fragments,
`$IFS`, backslash escapes, segment prefixes, env/command prefixes,
variable-indirection, substitution wraps, subshells):

```
GuardFall score: 1431/1431 mutations caught = 100.0%
Softened (deny -> ask under mutation): 4
Mutations generated: 1431 (from 113 dangerous cases)
```

"Softened" means the mutation still stopped for a human but at ask
tier instead of deny — counted honestly, not as full catches in
spirit (the score formula counts them as caught; the number is
printed so you can discount them yourself).

## Injection bench — 15/15 caught, 0/10 false positives

```
Positives caught (taint written): 15/15
Benign false positives: 0/10
INJECTION BENCH: PASS (bar: >=13/15 caught, <=1/10 FP)
```

The benign controls include security articles quoting injections
and this project's own `docs/INCIDENTS.md`.

## Robustness — 10,000 payloads, 0 crashes

Deterministic malformed/hostile payload fuzz (truncations, type
confusion, huge inputs, ANSI bombs, deep nesting): the hook always
returns exit 0 with empty-or-valid-JSON stdout and fails closed.

```
In-process: 10000/10000 clean
Sampled subprocess runs: 300 (of 10000), crashes: 0, bad stdout: 0
```

## Latency — subprocess end-to-end (includes Python startup)

Measured 2026-10-07, 30 rounds each, sequential on a quiet machine:

```
allow (git status)     median  157.3 ms   p95  194.1 ms
deny (rm -rf /)        median  150.2 ms   p95  180.6 ms
defer (make build)     median  152.9 ms   p95  161.7 ms
ALL                    median  153.5 ms   p95  180.6 ms
```

Itemized heavy paths (15 rounds each):

```
snapshot path (rm of existing file, ask)   median 149.1 ms  p95 237.6 ms
rehearsal path (terraform apply, stub)     median 156.6 ms  p95 171.4 ms
```

The rehearsal number uses a stub `terraform` that answers instantly;
a real `terraform plan` adds the tool's own runtime (the preview is
capped at a 10s timeout) — that time belongs to terraform, not the
hook. Latency grew from ~116 ms median in early builds to ~153 ms
as the snapshot/injection/plan/brain/MCP layers were added; the
table is republished every release so the cost stays visible.

## Head-to-head: the naive baseline

`bench/runners/naive_blocker.py` — a single-regex `rm -rf` blocker,
the most common safety hook in the wild — scored through the same
corpus (`bench/run_external.py`):

```
External runner vs Seatbelt Bench — 206 cases evaluated
TOTAL               206     42    20.4%
```

164 misses, every one printed by name in the scorer output. That
gap — between a regex and a policy engine — is what the corpus
exists to measure. Score your own tool: `bench/README.md`.
