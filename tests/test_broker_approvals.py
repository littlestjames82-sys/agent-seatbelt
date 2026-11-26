"""Broker approvals (0.4.0, B3): an ask verdict parks the request
until the USER decides with the approval capability token. Agent
sessions can never approve their own requests; approvals are
single-use and bound to the exact request hash.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG / "src"))

from agent_seatbelt.broker.approvals import read_approval_token  # noqa: E402
from agent_seatbelt.broker.client import (  # noqa: E402
    BrokerClient,
    BrokerError,
)
from test_broker_server import BASE_CONFIG, start_broker, stop_broker  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "old.log").write_text("log", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SEATBELT_HOME", str(home / ".seatbelt"))
    monkeypatch.setenv("SEATBELT_BROKER_SOCK",
                       str(tmp_path / "broker.sock"))
    monkeypatch.delenv("SEATBELT_JUDGE_COMMAND", raising=False)
    monkeypatch.delenv("SEATBELT_MODE", raising=False)
    return {"home": home, "ws": ws, "sock": tmp_path / "broker.sock"}


@pytest.fixture()
def broker(env):
    start_broker()
    yield
    stop_broker()


def execute_async(client, **kwargs):
    """Run client.execute on a thread (it blocks awaiting approval);
    returns (thread, box) where box gets 'snap' or 'error'."""
    box = {}

    def _run():
        try:
            box["snap"] = client.execute(**kwargs)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread, box


def wait_pending(client, token, want=1, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = client.pending(token)["pending"]
        if len(pending) >= want:
            return pending
        time.sleep(0.1)
    raise AssertionError("no pending approval appeared")


ASK_CMD = {"command": "rm old.log"}  # the engine asks on plain rm


def test_approve_lets_ask_execute(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    thread, box = execute_async(
        client, cwd=str(env["ws"]), request_id="req-appr-001",
        **ASK_CMD)
    token = read_approval_token()
    pending = wait_pending(client, token)
    assert pending[0]["request_id"] == "req-appr-001"
    client.approve("req-appr-001", token)
    thread.join(timeout=15)
    assert box["snap"]["state"] == "COMPLETED"
    assert not (env["ws"] / "old.log").exists()  # the rm ran


def test_deny_blocks_ask_and_is_final(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    thread, box = execute_async(
        client, cwd=str(env["ws"]), request_id="req-deny-001",
        **ASK_CMD)
    token = read_approval_token()
    wait_pending(client, token)
    client.deny("req-deny-001", token)
    thread.join(timeout=15)
    assert box["snap"]["state"] == "DENIED"
    assert (env["ws"] / "old.log").exists()  # never ran
    # A deny is final: a later approve is refused.
    with pytest.raises(BrokerError):
        client.approve("req-deny-001", token)


def test_agent_session_cannot_approve_own_request(broker, env):
    client = BrokerClient()
    session = client.open("agent-a")
    thread, box = execute_async(
        client, cwd=str(env["ws"]), request_id="req-self-001",
        **ASK_CMD)
    token = read_approval_token()
    wait_pending(client, token)
    # The session token is NOT the approval capability.
    with pytest.raises(BrokerError):
        client.approve("req-self-001", session["session_token"])
    with pytest.raises(BrokerError):
        client.approve("req-self-001", "guessed-token")
    # Still parked; the user can still decide.
    assert len(client.pending(token)["pending"]) == 1
    client.deny("req-self-001", token)
    thread.join(timeout=15)
    assert box["snap"]["state"] == "DENIED"


def test_approval_is_single_use(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    thread, box = execute_async(
        client, cwd=str(env["ws"]), request_id="req-once-001",
        **ASK_CMD)
    token = read_approval_token()
    wait_pending(client, token)
    client.approve("req-once-001", token)
    thread.join(timeout=15)
    assert box["snap"]["state"] == "COMPLETED"
    with pytest.raises(BrokerError) as excinfo:
        client.approve("req-once-001", token)
    assert "single-use" in str(excinfo.value)


def test_changed_request_under_same_id_refused_while_pending(broker,
                                                             env):
    client = BrokerClient()
    client.open("agent-a")
    thread, box = execute_async(
        client, cwd=str(env["ws"]), request_id="req-chg-0002",
        **ASK_CMD)
    token = read_approval_token()
    wait_pending(client, token)
    # Same request_id, different command: not the request the user
    # is being asked about — refused outright.
    with pytest.raises(BrokerError) as excinfo:
        client.execute(argv=["/bin/true"], cwd=str(env["ws"]),
                       request_id="req-chg-0002")
    assert "different content" in str(excinfo.value)
    client.deny("req-chg-0002", token)
    thread.join(timeout=15)
    assert box["snap"]["state"] == "DENIED"
    assert (env["ws"] / "old.log").exists()


def test_approval_timeout_terminates(env, monkeypatch):
    # Own broker on its own socket with a 2s approval timeout.
    monkeypatch.setenv("SEATBELT_BROKER_SOCK",
                       str(env["sock"]) + ".short")
    config = dict(BASE_CONFIG, approval_timeout_seconds=2)
    start_broker(config)
    try:
        _approval_timeout_body(env)
    finally:
        stop_broker()


def _approval_timeout_body(env):
    client = BrokerClient()
    client.open("agent-a")
    started = time.monotonic()
    snap = client.execute(cwd=str(env["ws"]),
                          request_id="req-timeout1", **ASK_CMD)
    elapsed = time.monotonic() - started
    assert snap["state"] == "TERMINATED"
    assert "approval timed out" in (snap.get("error") or "")
    assert elapsed < 15
    assert (env["ws"] / "old.log").exists()
