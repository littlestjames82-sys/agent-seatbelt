# Rule lifecycle

Seatbelt's rule ids are a public contract: audit logs, bench cases,
flight plans, and user muscle memory all refer to them.

- **Ids are stable.** A rule id, once shipped, never changes meaning.
- **Ids are never reused.** A retired rule's id stays retired; a
  replacement gets a new id.
- **Tiers can only move stricter by default.** If a rule's verdict
  changes (ask → deny), the CHANGELOG says so explicitly, with the
  bench case that justified it.
- **Every rule carries a remediation** — the safer path printed with
  the verdict (the project law in CONTRIBUTING.md).
- **Deprecation**: a rule is deprecated in one release (still firing,
  CHANGELOG notes it) before removal in the next, unless it is itself
  causing harm (blocking legitimate work counts as harm; the
  false-positive template is the fastest route to a fix).
- **Feed rules** (`feed/rules/`) follow the same lifecycle; a feed
  entry's rule ids must resolve to real rules or overlay patterns in
  the release that ships the entry.
