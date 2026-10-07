# Disaster feed runbook

The disaster feed turns a public agent incident into new Seatbelt
coverage: a feed entry (overlay rules + bench cases) that ships in
the next release.

## Distribution, plainly

**The feed is release-based. The hook never phones home.** There is
no update server, no telemetry, no background fetch — `feed/` is
data bundled with releases, applied only when a project opts in
(`SEATBELT_FEED=1` or `"feed": true` in the project overlay), layered
*below* the project overlay, and locked rules always win over it.
`test_no_network` covers the feed code paths.

## The 24-hour SLA

From a credible public incident report (agent deleted data,
exfiltrated secrets, bypassed approvals, poisoned memory) to a
shipped feed entry:

- **Hour 0–2 — triage.** Confirm the incident from a primary source
  (vendor postmortem, maintainer report). Write the one-paragraph
  summary in our own words for `docs/INCIDENTS.md`.
- **Hour 2–8 — cases first.** Add bench cases reproducing the
  tool-call shape: the destructive case AND the benign near-miss.
  If the current hook already catches it, the entry is
  documentation-only — say so.
- **Hour 8–16 — detector.** If it doesn't catch it, build the
  smallest detector that does, with a remediation string (project
  law: no detector without cases + remediation). Scaffold the entry:

  ```bash
  python3 scripts/feed_entry.py --id <slug> --title "..." \
      --rule <rule-id> --bench-case <case-name> [...]
  ```

  The scaffolder **refuses** entries without bench cases that exist
  in `bench/cases.jsonl`.
- **Hour 16–24 — verify + ship.** Full suite + bench green, feed
  files validate against `policies/schema.json`, CHANGELOG line
  under `## Unreleased`, entry ships with the next release.

## The commitment

Whether to publish the 24-hour SLA as a public commitment is
**Ryan's call** — it's marked in the launch playbook as such. This
runbook is the operational checklist either way; the SLA above is
the internal target the checklist is built to hit.
