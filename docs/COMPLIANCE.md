# Compliance evidence — what Seatbelt produces, and what it isn't

Seatbelt produces **evidence artifacts**: a tamper-evident record of
what an agent tried to do, what the policy decided, and why. Auditors
like records. This document maps those artifacts to the frameworks
teams ask about.

**This document is not a compliance certification, and nothing here
is legal advice.** Seatbelt doesn't make you SOC 2 compliant or
EU-AI-Act compliant; it gives your auditor better evidence for the
controls you operate.

## The evidence bundle

```bash
python3 hooks/seatbelt_hook.py --report --evidence
```

emits a JSON bundle: audit record counts by decision and by OWASP
ASI category, the hash-chain verification result, snapshot/taint/
brain/MCP-baseline/flight-plan state, the build version, and a
generated timestamp.

## SOC 2 (Trust Services Criteria) mapping

How Seatbelt's artifacts support criteria your auditor may test
(mapping is our interpretation, offered as a starting point for the
conversation — the AICPA criteria text governs):

- **CC6.1 (logical access / authorized actors).** Every audit record
  names the agent surface and the deploying principal's environment
  (mode, policy pack, flight plan) under which an action was
  evaluated — who tried to do what, under whose policy.
- **CC7.2 (system monitoring).** The hash-chained audit log records
  every evaluated action, its decision, and any detected anomaly
  (canary trips, injection flags, MCP drift, brain drift). The chain
  makes silent edits to history detectable (`--verify-log`).
- **CC8.1 (change management).** Policy changes leave records:
  baseline moves (`--baseline --accept`, brain + MCP together) are
  audit-logged human acts; policy-pack and feed changes ship as
  versioned files in releases.

Practical note: auditors in 2026 commonly expect on the order of
twelve months of retained, tamper-evident, queryable logs. The
audit log is a local JSONL file — retention and shipping it to your
SIEM of choice are yours to operate.

## OWASP Agentic Top 10 (ASI) mapping

Every rule, bench case, feed rule, and audit record carries an ASI
id; `--report` groups counts by ASI. The mapping table lives in
`docs/THREAT_MODEL.md`. Headline coverage: ASI01 (goal hijack —
injection flags, flight plans), ASI03 (identity & privilege — secret
gating, canary trips, MCP drift), ASI06 (memory poisoning — brain
drift watch), ASI10 (rogue agents — bypass-launch denies).

## EU AI Act — dates, stated carefully

- GPAI (general-purpose AI) obligations have applied since
  **August 2025**.
- Commission enforcement powers (Art. 91–93) and the Art. 50
  transparency obligations apply from **2026-08-02**. Art. 101 fines
  reach up to 3% of worldwide turnover or €15M.
- The Digital Omnibus (Council approval 29 Jun 2026) **deferred**
  Annex III high-risk obligations to **2027-12-02**, and Annex I
  embedded-product obligations to 2028-08-02. **August 2026 is not
  the high-risk deadline** — any source telling you otherwise is
  out of date.

Seatbelt's relevance is narrow and real: agent tool-call governance
and its audit trail are the kind of technical evidence that supports
transparency and human-oversight claims. The obligations themselves
belong to deployers and providers, and they need counsel, not a
hook.
