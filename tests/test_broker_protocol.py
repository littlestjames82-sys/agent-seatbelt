"""Broker protocol v1 (0.4.0, B1): validation + the authorization
state machine. Pure-code tests — malformed input must never
advance state, and every illegal transition must raise.
"""

from __future__ import annotations

import pytest

from agent_seatbelt.broker.protocol import (
    ProtocolError,
    RequestMachine,
    ValidationError,
    request_hash,
    validate_request,
)


def valid_doc(**overrides):
    doc = {
        "protocol_version": "1",
        "request_id": "req-00000001",
        "session_id": "sess-1",
        "agent_id": "tester",
        "operation": "execute",
        "argv": ["/bin/echo", "hi"],
        "working_directory": "/tmp",
        "requested_permissions": {"filesystem": ["workspace-read"],
                                  "network": "none",
                                  "process": "restricted"},
        "timeout_seconds": 30,
    }
    doc.update(overrides)
    return doc


# ── validation ───────────────────────────────────────────────────────

def test_validate_argv_form():
    req = validate_request(valid_doc())
    assert req["argv"] == ["/bin/echo", "hi"]
    assert req["command"] == "/bin/echo hi"
    assert req["command_was_string"] is False
    assert req["timeout_seconds"] == 30


def test_validate_command_string_is_shlex_parsed():
    doc = valid_doc()
    del doc["argv"]
    doc["command"] = "echo 'a b' && ls"
    req = validate_request(doc)
    assert req["argv"] == ["echo", "a b", "&&", "ls"]
    assert req["command_was_string"] is True


def test_validate_defaults():
    doc = valid_doc()
    del doc["requested_permissions"]
    del doc["timeout_seconds"]
    req = validate_request(doc)
    assert req["requested_permissions"]["network"] == "none"
    assert req["requested_permissions"]["filesystem"] == ["workspace-read"]
    assert req["timeout_seconds"] == 120


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(protocol_version="2"),
    lambda d: d.update(request_id="short"),
    lambda d: d.update(request_id=42),
    lambda d: d.update(agent_id=""),
    lambda d: d.update(operation="delete"),
    lambda d: d.update(argv=[]),
    lambda d: d.update(argv=["/bin/echo", 7]),
    lambda d: d.update(argv=["x" * 9000]),
    lambda d: d.update(working_directory="relative/path"),
    lambda d: d.update(working_directory=""),
    lambda d: d.update(timeout_seconds=0),
    lambda d: d.update(timeout_seconds=99999),
    lambda d: d.update(timeout_seconds="30"),
    lambda d: d.update(seq=-1),
    lambda d: d.update(surprise_field=True),
    lambda d: d.update(requested_permissions={"filesystem": ["root"]}),
    lambda d: d.update(requested_permissions={"network": "tor"}),
    lambda d: d.update(requested_permissions={"process": "godmode"}),
    lambda d: d.update(requested_permissions={"shell": True}),
])
def test_validate_rejects_malformed(mutate):
    doc = valid_doc()
    mutate(doc)
    with pytest.raises(ValidationError):
        validate_request(doc)


def test_validate_requires_argv_or_command():
    doc = valid_doc()
    del doc["argv"]
    with pytest.raises(ValidationError):
        validate_request(doc)


def test_validate_unparseable_command_string():
    doc = valid_doc()
    del doc["argv"]
    doc["command"] = "echo 'unterminated"
    with pytest.raises(ValidationError):
        validate_request(doc)


def test_validate_rejects_non_object():
    with pytest.raises(ValidationError):
        validate_request(["not", "a", "dict"])


# ── request hash (approval binding) ──────────────────────────────────

def test_request_hash_stable_and_sensitive():
    base = validate_request(valid_doc())
    same = validate_request(valid_doc())
    assert request_hash(base) == request_hash(same)
    for change in ({"argv": ["/bin/echo", "bye"]},
                   {"working_directory": "/var"},
                   {"timeout_seconds": 31}):
        other = validate_request(valid_doc(**change))
        assert request_hash(other) != request_hash(base)
    doc = valid_doc()
    doc["requested_permissions"] = {"filesystem": ["workspace-write"],
                                    "network": "none",
                                    "process": "restricted"}
    assert request_hash(validate_request(doc)) != request_hash(base)


# ── state machine ────────────────────────────────────────────────────

def machine():
    return RequestMachine(validate_request(valid_doc()))


def test_full_legal_path():
    m = machine()
    for state in ("VALIDATING", "AUTHORIZED", "PREPARING_SANDBOX",
                  "EXECUTING", "VERIFYING", "COMPLETED"):
        m.transition(state)
    assert m.state == "COMPLETED"
    assert m.terminal
    assert m.history[0] == ("RECEIVED", "VALIDATING")
    assert m.history[-1] == ("VERIFYING", "COMPLETED")


def test_approval_path():
    m = machine()
    m.transition("VALIDATING")
    m.transition("AWAITING_APPROVAL")
    m.transition("AUTHORIZED")
    assert m.state == "AUTHORIZED"


def test_deny_is_terminal_and_final():
    m = machine()
    m.transition("VALIDATING")
    m.transition("DENIED")
    assert m.terminal
    with pytest.raises(ProtocolError):
        m.transition("AUTHORIZED")


@pytest.mark.parametrize("frm,to", [
    ("RECEIVED", "EXECUTING"),
    ("RECEIVED", "COMPLETED"),
    ("RECEIVED", "AUTHORIZED"),
    ("VALIDATING", "EXECUTING"),
    ("VALIDATING", "COMPLETED"),
    ("AWAITING_APPROVAL", "EXECUTING"),
    ("AWAITING_APPROVAL", "COMPLETED"),
    ("EXECUTING", "COMPLETED"),
    ("EXECUTING", "AUTHORIZED"),
    ("VERIFYING", "EXECUTING"),
])
def test_illegal_transitions_raise(frm, to):
    m = machine()
    path = {
        "RECEIVED": [],
        "VALIDATING": ["VALIDATING"],
        "AWAITING_APPROVAL": ["VALIDATING", "AWAITING_APPROVAL"],
        "EXECUTING": ["VALIDATING", "AUTHORIZED",
                      "PREPARING_SANDBOX", "EXECUTING"],
        "VERIFYING": ["VALIDATING", "AUTHORIZED",
                      "PREPARING_SANDBOX", "EXECUTING", "VERIFYING"],
    }[frm]
    for state in path:
        m.transition(state)
    with pytest.raises(ProtocolError):
        m.transition(to)
    assert m.state == frm  # a refused transition changes nothing


def test_failure_reachable_from_active_states():
    m = machine()
    m.transition("VALIDATING")
    m.transition("AUTHORIZED")
    m.transition("FAILED")
    assert m.terminal
    with pytest.raises(ProtocolError):
        m.transition("EXECUTING")


def test_snapshot_shape():
    m = machine()
    snap = m.snapshot()
    assert snap["request_id"] == "req-00000001"
    assert snap["state"] == "RECEIVED"
    assert "result" not in snap and "error" not in snap
