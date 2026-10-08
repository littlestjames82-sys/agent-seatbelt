## What

<!-- What does this change? Name the layer: rules / policy packs /
detectors / surfaces (hooks, mods, plugin) / audit / library / docs. -->

## Why

<!-- The incident shape, gap, or false positive this addresses. Link
the issue if there is one. -->

## Bench & verification

<!-- Receipts, not adjectives: paste the commands and the numbers. -->

- [ ] `python -m pytest tests/ -q` — green (report the count)
- [ ] `python bench/run_bench.py` — green (report the score)
- [ ] `python bench/run_injection.py` — green, if detectors/scoring touched
- [ ] New or changed detector ships bench cases: the destructive shape
      AND the benign near-miss, plus a remediation string
- [ ] Verdicts still name their rule, blast radius, and safer path

## Rules check

- [ ] No network, no telemetry — the hook still never phones home
      (`tests/test_no_network.py` semantics intact)
- [ ] No secrets in code, tests, fixtures, or audit output (type+length
      redaction preserved — never values)
- [ ] Locked rules and overlays can still only get stricter, never weaker
- [ ] Honest-status language intact — simulated surfaces are still
      called simulated, unproven things still called unproven
