---
name: Feature request
about: A rule, policy pack, surface, or capability Seatbelt should have
title: "[feature] "
labels: enhancement
---

**The situation**
What was the agent about to do (or what did you have to allow) that
Seatbelt didn't cover the way you needed? A real command transcript
beats an abstraction — redact secrets as type+length, never values.

**Proposed shape**
Which layer: a locked rule, a project overlay / policy pack
(`solo` / `team-strict` / `ci` / `paranoid`), a detector, a new agent
surface, the audit/report tooling, or the library API? Sketch it.

**The bench cases this needs**
House law: no detector without bench cases — the destructive shape AND
the benign near-miss — plus a remediation ("safer path") string. List
the cases you'd expect:

- Blocks/escalates:
- Allows (near-miss):

**Alternatives you tried**
Overlays, allowlists, flight plans, rehearsal previews — what wasn't enough?
