# Bench results — Agent Seatbelt 0.2.0, Seatbelt Bench v1

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
