"""The gate harness: record-first, verdicts surface, sinks are honest.

These rewrite the Jev governor's in-the-loop tests at the harness
level: a minimal fake loop that follows the documented caller
contract — gate() first, execute only when Governor.may_execute()
says so — stands in for any real agent loop. No browser, no network.
"""

import json

import pytest

from agent_seatbelt import Governor, JsonlSink, compile_policy


def page():
    return {
        "url": "https://example.test/",
        "fingerprint": "fp-1",
        "actions": [
            {"id": "e1", "kind": "fill", "label": "Search", "role": "textbox", "value": "", "node": 10},
            {"id": "e2", "kind": "click", "label": "Open Search", "role": "textbox", "value": "", "node": 10},
            {"id": "e3", "kind": "click", "label": "Go", "role": "button", "value": "", "node": 20},
            {"id": "wait", "kind": "wait", "label": "Wait"},
        ],
    }


def action(page_state, action_id):
    return next(a for a in page_state["actions"] if a["id"] == action_id)


class FakeLoop:
    """The caller contract, in miniature: gate, then maybe execute."""

    def __init__(self, governor):
        self.governor = governor
        self.executed = []

    def run(self, act, page_state, *, operation=None):
        record = self.governor.gate(act, page_state, operation=operation)
        if Governor.may_execute(record):
            self.executed.append(act["id"])
        return record


def test_record_is_written_before_any_effect():
    order = []
    governor = Governor(sink=lambda record: order.append(("record", record["verdict"])))
    record = governor.gate(action(page(), "e2"), page(), operation="CLICK")
    order.append(("effect", record["action_id"]))
    assert order == [("record", "allow"), ("effect", "e2")]  # record existed first


def test_read_only_action_executes_under_the_default_policy():
    governor = Governor()
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e2"), page(), operation="CLICK")
    assert loop.executed == ["e2"]
    assert record["verdict"] == "allow" and record["rule_id"] == "seatbelt-read-only"
    assert record["classification"] == "read_only" and record["permission_class"] == "READ"
    assert record["target"]["element"] == "e2" and record["snapshot_id"] == "fp-1"
    json.dumps(record)  # records stay JSON-safe for logs and inspectors


def test_consequential_action_asks_by_default_and_does_not_execute():
    governor = Governor()
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page(), operation="CLICK")  # the "Go" button
    assert loop.executed == []
    assert record["verdict"] == "ask" and record["rule_id"] == "seatbelt-consequential-ask"
    assert record["classification"] == "consequential" and record["permission_class"] == "NETWORK_WRITE"
    assert governor.records == [record]


def test_allow_policy_executes_a_consequential_action():
    governor = Governor({"rules": [
        {"id": "allow-clicks", "effect": "allow", "when": "kind == 'browser.click'"},
    ]})
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page())
    assert loop.executed == ["e3"]
    assert record["verdict"] == "allow" and record["rule_id"] == "allow-clicks"


def test_pre_approved_executes_and_is_recorded_as_such():
    governor = Governor({"rules": [
        {"id": "standing", "effect": "pre_approved", "when": "kind == 'browser.click'"},
    ]})
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page())
    assert loop.executed == ["e3"]
    assert record["verdict"] == "pre_approved"


def test_deny_blocks_and_names_its_rule():
    governor = Governor({"rules": [
        {"id": "never-go", "effect": "deny", "when": "payload.label == 'Go'"},
        {"id": "allow-rest", "effect": "allow", "when": "true"},
    ]})
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page())
    assert loop.executed == []
    assert record["verdict"] == "deny" and record["rule_id"] == "never-go"
    assert "never-go" in record["reason"]


def test_hand_off_record_carries_its_target():
    governor = Governor({"rules": [
        {"id": "route-clicks", "effect": "hand_off", "handoff_to": "ryan", "when": "kind == 'browser.click'"},
        {"id": "allow-rest", "effect": "allow", "when": "true"},
    ]})
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page())
    assert loop.executed == []
    assert record["verdict"] == "hand_off" and record["handoff_to"] == "ryan"


def test_dry_run_records_the_verdict_without_executing():
    governor = Governor(
        {"rules": [{"id": "allow-clicks", "effect": "allow", "when": "kind == 'browser.click'"}]},
        dry_run=True,
    )
    loop = FakeLoop(governor)
    record = loop.run(action(page(), "e3"), page())
    assert loop.executed == []
    assert record["verdict"] == "allow" and record["dry_run"] is True


def test_jsonl_sink_receives_each_record(tmp_path):
    log = tmp_path / "seatbelt.jsonl"
    governor = Governor(sink=JsonlSink(log))
    loop = FakeLoop(governor)
    loop.run(action(page(), "e2"), page())
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["verdict"] == "allow"


def test_unwritable_sink_means_no_action(tmp_path):
    governor = Governor(sink=JsonlSink(tmp_path / "missing-dir" / "seatbelt.jsonl"))
    loop = FakeLoop(governor)
    with pytest.raises(RuntimeError, match="no action executed"):
        loop.run(action(page(), "e2"), page())
    assert loop.executed == []


def test_policy_loads_from_a_json_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": [
        {"id": "allow-clicks", "effect": "allow", "when": "kind == 'browser.click'"},
    ]}))
    governor = Governor(path)
    record = governor.gate(action(page(), "e3"), page())
    assert record["verdict"] == "allow" and record["rule_id"] == "allow-clicks"


def test_missing_policy_file_fails_closed_at_construction(tmp_path):
    with pytest.raises(ValueError, match="no action executed"):
        Governor(tmp_path / "absent.json")


def test_malformed_policy_file_fails_closed_at_construction(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"not": "a policy"}')
    with pytest.raises(ValueError, match="not a policy document"):
        Governor(path)


def test_compiled_policy_is_accepted_directly():
    compiled = compile_policy({"rules": [
        {"id": "allow-clicks", "effect": "allow", "when": "kind == 'browser.click'"},
    ]})
    governor = Governor(compiled)
    record = governor.gate(action(page(), "e3"), page())
    assert record["verdict"] == "allow" and record["rule_id"] == "allow-clicks"


def test_identity_fields_are_stamped_from_the_integrator_not_the_action():
    governor = Governor(actor="checkout-bot", initiator="routine", project_id="shop")
    record = governor.gate(action(page(), "e2"), page())
    assert record["actor"] == "checkout-bot"
    assert record["initiator"] == "routine"
    assert record["project_id"] == "shop"
    assert record["kind"] == "browser.click"


def test_policy_can_branch_on_initiator():
    doc = {"rules": [
        {"id": "routine-ask", "effect": "ask", "when": "initiator == 'routine'"},
        {"id": "reads", "effect": "allow", "when": "classification == 'read_only'"},
    ]}
    attended = Governor(doc, initiator="person")
    unattended = Governor(doc, initiator="routine")
    assert attended.gate(action(page(), "e2"), page())["verdict"] == "allow"
    assert unattended.gate(action(page(), "e2"), page())["verdict"] == "ask"
