# Contributing to Agent Seatbelt

Thanks for helping make agent tool-calls safer. This project has one
law, learned from watching safety tools fail in the wild:

## The project law

**No detector without bench cases — one destructive case AND one
benign near-miss case — and a remediation string.**

Every rule must arrive with:

1. A bench case in `bench/cases.jsonl` where the dangerous input gets
   the intended verdict.
2. A bench case where the closest *legitimate* lookalike does **not**
   get blocked (false positives are bugs with the same severity as
   misses).
3. A remediation: the safer alternative, written into the rule's
   reason text. A denial that doesn't teach is just friction.

Pull requests that add a detector without all three will be asked to
add them. This is not bureaucracy — it is the entire quality bar.

## Hard constraints

- **Stdlib only.** The hook (`hooks/seatbelt_hook.py`) is a single
  self-contained Python file, standard library only, no network, no
  imports of the `agent_seatbelt` package. It must keep passing the
  standalone-copy test (the battery runs it alone in an empty dir).
- **Python 3.8+ syntax** in the hook (it is grammar-checked in tests).
- **Rule ids are stable** and never reused (see
  `docs/RULE_LIFECYCLE.md`). New rules get new ids.
- **Locked rules stay locked**: project overlays and policy packs can
  add asks/denies but can never weaken a locked rule.
- Every number in docs must come from a real run of the bench/tests
  on the tree you're submitting. We don't ship invented figures.

## Workflow

```bash
python3 -m pytest tests/ -q        # full suite must be green
python3 bench/run_bench.py         # bench table must not regress
node --test experimental/mods/policy.test.mjs   # if you touched JS
```

## Reporting

- False positive in the wild? Use the false-positive issue template —
  the exact command matters more than anything else in the report.
- Security vulnerability? See `SECURITY.md` (private disclosure, not
  a public issue).
