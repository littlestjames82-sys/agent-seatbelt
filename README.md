# Agent Seatbelt

**A seatbelt for browser agents: record-first, fail-closed policy gating for agent actions — before they happen.**

Your browser agent can click "Pay now," submit the form, send the message.
Nothing in most agent loops asks *should it?* — or writes down that it was
about to — before the click lands. Agent Seatbelt is the small gate that
sits between the agent's decision and the browser:

1. **Classify** — every action is classified read-only or consequential.
   Only provably harmless shapes (scrolls, waits, link clicks, view
   switches) are read-only; unknown shapes are consequential.
2. **Evaluate** — an executable policy decides: `allow`, `pre_approved`,
   `ask`, `hand_off`, or `deny`. Strictest verdict wins, the deciding
   rule is named, and everything fails **closed**: no matching rule →
   deny; a broken restrictive rule denies everything and names itself;
   a broken permissive rule is inert.
3. **Record** — the decision is written to your record sink *first*,
   with the intent, the exact payload, the verdict, and the rule. If
   the record can't be written, the action does not run. **An action
   that is not recorded does not happen.**
4. **Act** — your loop executes only on `allow` / `pre_approved`.
   `ask` and `hand_off` halt the action and hand you the record as the
   pending item for a human decision made outside the loop. `deny`
   stops it, with the rule named.

By **Ghost Developer Studio**. MIT licensed. Zero dependencies.

## Quickstart (60 seconds)

```bash
pip install agent-seatbelt   # or: PYTHONPATH=src, it's one small package
```

```python
from agent_seatbelt import Governor

governor = Governor()  # default policy: reads flow, consequential asks

# In your agent loop, after the agent picks an action and BEFORE it runs:
record = governor.gate(action, page, operation="CLICK")

if Governor.may_execute(record):
    browser.act(action)          # the record already exists
elif record["verdict"] in {"ask", "hand_off"}:
    surface_for_human(record)    # your approval flow; the record is the item
else:
    stop(record["reason"])       # denied — the reason names the rule
```

`action` and `page` are plain dicts in the vocabulary browser agents
already produce:

```python
action = {"id": "e3", "kind": "click", "label": "Pay now",
          "role": "button", "value": "", "node": 20}
page   = {"url": "https://shop.example.test/checkout",
          "actions": [ ...all observed actions... ],
          "fingerprint": "any-observation-id"}
```

Records accumulate in `governor.records`; or pass a sink —
`JsonlSink("seatbelt.jsonl")` for an append-only audit log, any
callable, or any object with `write(record)`. Runnable demo:
[`examples/quickstart.py`](examples/quickstart.py).

## Policy

Policies are small JSON documents — the same shape the Ghost Kernel
and GhostGuard use, so a policy written for one decides identically
in all three:

```json
{"rules": [
  {"id": "never-pay", "effect": "deny",
   "when": "payload.label == 'Pay now'"},
  {"id": "reads", "effect": "allow",
   "when": "classification == 'read_only'"},
  {"id": "rest-ask", "effect": "ask",
   "when": "classification == 'consequential'"},
  {"id": "route-purchases", "effect": "hand_off", "handoff_to": "owner",
   "when": "permission_class == 'NETWORK_WRITE' && initiator == 'routine'"}
]}
```

Rules see `kind` (`browser.click`, `browser.fill`, …), `permission_class`
(`READ` / `WRITE_LOCAL` / `NETWORK_WRITE`), `actor`, `project_id`,
`approved`, `initiator`, `payload.<field>`, plus the native roots
`classification`, `operation`, `role`, `label`, `host`. Expressions
support `== != < <= > >= in && || !`, list literals, and
`startsWith / endsWith / contains / matches`. Effects rank
`deny > hand_off > ask > pre_approved > allow` — by tier, never by
document order, so an allow appended later can never outrank a deny.
Rules marked `"locked": true` survive policy merges verbatim.

`Governor(policy)` accepts a document dict, a path to a JSON policy
file, a compiled policy, or nothing (the default above's shipped
analogue: read-only allow, consequential ask).

## What it is not

- **Not an approval UI.** `ask` / `hand_off` halt the action and give
  you the record; collecting the human's answer is deliberately your
  loop's business. A fake approve button would misrepresent the
  guarantee.
- **Not a sandbox.** It gates the actions your loop sends through
  `gate()`. Code that drives a browser around the gate is outside it.
- **Not a classifier you must trust blindly.** Classification is
  heuristic by action *shape*, not site knowledge: a pagination
  button is a button, and asks under the default policy until your
  policy allows it by label or host. That friction is the
  conservative stance working; the policy file is the release valve.
- **Not the whole governance stack.** No dashboard, no multi-agent
  audit store, no secret-redacting records, no approval surfaces.
  That's the full version:

## The full version: GhostGuard

Agent Seatbelt is the browser-agent extraction of **GhostGuard** —
record-first gateway, fail-closed policy, approvals, and audit for
*any* agent (browser bots, coding agents, workflow runners), with
initiator-vs-actor stamping, locked team rules, secret hygiene in
records, and an approvals flow. Same policy language; records here
are shaped to feed it.

→ GhostGuard, by Ghost Developer Studio: the full TypeScript
governance package this is extracted from — same policy language,
and records here are shaped to feed it.

## Provenance

The governor was first built into [Jev](https://github.com/browser-use/jev-ultrafast),
an ultrafast browser agent, where it runs the same
classify → evaluate → record → act contract inside the loop (suite:
85 checks, including the engine and classification tests carried over
here). The policy engine is a faithful Python port of the Ghost
Kernel's `policy.ts`; `matches()` uses Python's `re` where the
original uses JS RegExp — the common subset behaves the same.

## License

MIT — see [LICENSE](LICENSE). © 2026 Ghost Developer Studio.
