"""The policy engine: a faithful port of the Ghost Kernel's engine.

Carried over from the Jev governor's offline test suite (the engine
there was the same port), with Jev's `jev.*` action kinds renamed to
this package's `browser.*` default prefix. The semantics under test
are the Kernel's: strictest tier wins, no match denies, broken
restrictive rules deny by name, broken permissive rules are inert,
locked rules survive merging.
"""

from agent_seatbelt import policy


def ctx(**overrides):
    base = {
        "kind": "browser.click",
        "permission_class": "NETWORK_WRITE",
        "actor": "browser-agent",
        "project_id": "",
        "approved": False,
        "payload": {"label": "Go"},
        "classification": "consequential",
    }
    base.update(overrides)
    return base


def evaluate(doc, context):
    return policy.evaluate_policy(policy.compile_policy(doc), context)


def test_policy_strictest_tier_wins_regardless_of_order():
    rules = [
        {"id": "allow-all", "effect": "allow", "when": "true"},
        {"id": "no-spend", "effect": "deny", "when": "permission_class == 'SPEND'"},
    ]
    for ordered in (rules, list(reversed(rules))):
        decision = evaluate({"rules": ordered}, ctx(permission_class="SPEND"))
        assert decision["verdict"] == "deny" and decision["rule_id"] == "no-spend"
    ladder = [
        {"id": "allow-all", "effect": "allow", "when": "true"},
        {"id": "pre", "effect": "pre_approved", "when": "true"},
        {"id": "ask", "effect": "ask", "when": "true"},
        {"id": "route", "effect": "hand_off", "handoff_to": "ryan", "when": "true"},
    ]
    assert evaluate({"rules": ladder}, ctx())["verdict"] == "hand_off"
    assert evaluate({"rules": ladder[:-1]}, ctx())["verdict"] == "ask"
    assert evaluate({"rules": ladder[:-2]}, ctx())["verdict"] == "pre_approved"


def test_policy_no_match_denies_fail_closed():
    decision = evaluate({"rules": [{"id": "reads", "effect": "allow", "when": "kind == 'browser.scroll'"}]}, ctx())
    assert decision["verdict"] == "deny" and decision["rule_id"] is None
    assert evaluate({"rules": []}, ctx())["verdict"] == "deny"


def test_policy_broken_restrictive_rule_denies_everything_by_name():
    doc = {"rules": [
        {"id": "broken-deny", "effect": "deny", "when": "permission_class =="},
        {"id": "allow-all", "effect": "allow", "when": "true"},
    ]}
    decision = evaluate(doc, ctx())
    assert decision["verdict"] == "deny" and decision["rule_id"] == "broken-deny"
    doc["rules"][0] = {"id": "broken-ask", "effect": "ask", "when": "&& true"}
    decision = evaluate(doc, ctx())
    assert decision["verdict"] == "deny" and decision["rule_id"] == "broken-ask"
    targetless = {"rules": [
        {"id": "route-nowhere", "effect": "hand_off", "when": "true"},
        {"id": "allow-all", "effect": "allow", "when": "true"},
    ]}
    decision = evaluate(targetless, ctx())
    assert decision["verdict"] == "deny" and decision["rule_id"] == "route-nowhere"


def test_policy_broken_permissive_rule_is_inert():
    doc = {"rules": [
        {"id": "broken-allow", "effect": "allow", "when": "kind =="},
        {"id": "real-allow", "effect": "allow", "when": "kind == 'browser.click'"},
    ]}
    decision = evaluate(doc, ctx())
    assert decision["verdict"] == "allow" and decision["rule_id"] == "real-allow"


def test_policy_expressions_match_the_kernel_subset():
    doc = {"rules": [
        {"id": "routine-ask", "effect": "ask", "when": "initiator == 'routine'"},
        {"id": "clicks", "effect": "allow",
         "when": "kind in ['browser.click', 'browser.fill'] && startsWith(payload.label, 'G')"},
    ]}
    assert evaluate(doc, ctx())["rule_id"] == "clicks"
    assert evaluate(doc, ctx(initiator="routine"))["verdict"] == "ask"
    # An absent initiator evaluates as null, like any missing field.
    assert evaluate(doc, ctx())["verdict"] == "allow"
    null_doc = {"rules": [{"id": "unstamped", "effect": "allow", "when": "initiator == null"}]}
    assert evaluate(null_doc, ctx())["rule_id"] == "unstamped"
    host_doc = {"rules": [{"id": "host", "effect": "allow", "when": "matches(host, 'example')"}]}
    assert evaluate(host_doc, ctx(host="example.test"))["rule_id"] == "host"


def test_policy_locked_rules_survive_merging():
    base = {"rules": [
        {"id": "no-spend", "effect": "deny", "locked": True, "when": "permission_class == 'SPEND'"},
        {"id": "scratch", "effect": "allow", "when": "kind == 'browser.click'"},
    ]}
    overlay = {"rules": [
        {"id": "no-spend", "effect": "allow", "when": "true"},
        {"id": "scratch", "effect": "deny", "when": "kind == 'browser.click'"},
        {"id": "allow-all", "effect": "allow", "when": "true"},
    ]}
    merged = policy.merge_policy_docs(base, overlay)
    decision = evaluate(merged, ctx(permission_class="SPEND"))
    assert decision["verdict"] == "deny" and decision["rule_id"] == "no-spend"
    edited = evaluate(merged, ctx())
    assert edited["verdict"] == "deny" and edited["rule_id"] == "scratch"  # non-locked edit took effect
