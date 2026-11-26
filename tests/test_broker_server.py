"""Broker daemon (0.4.0, B2/B4): sessions, peer/session auth,
replay refusal, session isolation, and end-to-end execution in
policy-only mode (labeled as such — isolation mode has its own
battery in test_broker_sandbox.py). The broker runs in-process on
a thread with an isolated HOME and socket.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
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
    BrokerUnavailable,
)
from agent_seatbelt.broker.server import Broker  # noqa: E402

BASE_CONFIG = {
    "isolation": "none",
    "allow_network_host": False,
    "filesystem_max": "workspace-write",
    "extended_dirs": [],
    "session_idle_timeout_seconds": 3600,
    "approval_timeout_seconds": 10,
    "output_cap_bytes": 262144,
    "limits": {"cpu_seconds": 60, "address_space_mb": 1024,
               "memory_mb": 1024, "file_size_mb": 64,
               "open_files": 512, "processes": 64},
}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SEATBELT_HOME", str(home / ".seatbelt"))
    monkeypatch.setenv("SEATBELT_BROKER_SOCK",
                       str(tmp_path / "broker.sock"))
    monkeypatch.delenv("SEATBELT_JUDGE_COMMAND", raising=False)
    monkeypatch.delenv("SEATBELT_MODE", raising=False)
    return {"home": home, "ws": ws, "sock": tmp_path / "broker.sock"}


def start_broker(config=None):
    broker = Broker(config=config or dict(BASE_CONFIG))
    thread = threading.Thread(target=broker.serve, daemon=True)
    thread.start()
    for _ in range(200):
        if Path(broker.sock_path).exists():
            break
        time.sleep(0.05)
    return broker


def stop_broker():
    try:
        BrokerClient(timeout=5).shutdown(read_approval_token())
    except Exception:
        pass


@pytest.fixture()
def broker(env):
    start_broker()
    yield
    stop_broker()


def rpc(sock_path, doc):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(10)
    conn.connect(str(sock_path))
    try:
        conn.sendall((json.dumps(doc) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        conn.close()
    return json.loads(buf.decode("utf-8"))


# ── sessions & auth ──────────────────────────────────────────────────

def test_status_reports_policy_only_mode(broker, env):
    resp = BrokerClient().status()
    assert resp["running"] is True
    assert resp["mode"] == "policy-only"  # honestly labeled


def test_session_open_close(broker, env):
    client = BrokerClient()
    resp = client.open("agent-a", client_label="test")
    assert resp["session_id"] and resp["session_token"]
    client.close_session()
    with pytest.raises(BrokerError):
        client.poll("whatever")


def test_execute_requires_valid_session_token(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    resp = rpc(env["sock"], {
        "op": "execute", "session_id": client.session_id,
        "session_token": "forged-token",
        "request": {"protocol_version": "1",
                    "request_id": "req-forged01",
                    "session_id": client.session_id,
                    "agent_id": "agent-a", "operation": "execute",
                    "argv": ["/bin/true"],
                    "working_directory": str(env["ws"])}})
    assert resp["ok"] is False
    assert "token" in resp["error"]


def test_unknown_session_refused(broker, env):
    resp = rpc(env["sock"], {"op": "poll", "session_id": "nope",
                             "session_token": "x",
                             "request_id": "r"})
    assert resp["ok"] is False


def test_malformed_message_gets_error_not_crash(broker, env):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(10)
    conn.connect(str(env["sock"]))
    try:
        conn.sendall(b"this is not json\n")
        data = conn.recv(4096)
    finally:
        conn.close()
    assert json.loads(data.decode("utf-8"))["ok"] is False
    assert BrokerClient().status()["running"] is True


# ── replay & session isolation ───────────────────────────────────────

def test_duplicate_request_id_refused(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    snap = client.execute(argv=["/bin/true"], cwd=str(env["ws"]),
                          request_id="req-dup-0001")
    assert snap["state"] == "COMPLETED"
    with pytest.raises(BrokerError) as excinfo:
        client.execute(argv=["/bin/true"], cwd=str(env["ws"]),
                       request_id="req-dup-0001")
    assert "replay refused" in str(excinfo.value)


def test_changed_request_same_id_refused(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    client.execute(argv=["/bin/true"], cwd=str(env["ws"]),
                   request_id="req-chg-0001")
    with pytest.raises(BrokerError) as excinfo:
        client.execute(argv=["/bin/false"], cwd=str(env["ws"]),
                       request_id="req-chg-0001")
    assert "different content" in str(excinfo.value)


def test_non_monotonic_seq_refused(broker, env):
    client = BrokerClient()
    session = client.open("agent-a")

    def raw_execute(request_id, seq):
        return rpc(env["sock"], {
            "op": "execute", "session_id": session["session_id"],
            "session_token": session["session_token"],
            "request": {"protocol_version": "1",
                        "request_id": request_id,
                        "session_id": session["session_id"],
                        "agent_id": "agent-a", "operation": "execute",
                        "argv": ["/bin/true"],
                        "working_directory": str(env["ws"]),
                        "seq": seq}})

    assert raw_execute("req-seq-0001", 5)["state"] == "COMPLETED"
    resp = raw_execute("req-seq-0002", 5)
    assert resp["ok"] is False
    assert "not monotonic" in resp["error"]


def test_sessions_cannot_see_each_others_requests(broker, env):
    alice = BrokerClient()
    alice.open("alice")
    snap = alice.execute(argv=["/bin/true"], cwd=str(env["ws"]),
                         request_id="req-alice-01")
    assert snap["state"] == "COMPLETED"
    bob = BrokerClient()
    bob.open("bob")
    with pytest.raises(BrokerError):
        bob.poll("req-alice-01")


# ── policy-only execution ────────────────────────────────────────────

def test_policy_only_exec_runs_and_propagates_exit_code(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    snap = client.execute(argv=["/bin/sh", "-c", "echo out; exit 7"],
                          cwd=str(env["ws"]))
    assert snap["state"] == "COMPLETED"
    assert snap["result"]["exit_code"] == 7
    assert "out" in snap["result"]["stdout_tail"]
    assert snap["result"]["mode"] == "policy-only"


def test_policy_only_exec_output_is_capped_and_tailed(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    snap = client.execute(
        argv=[sys.executable, "-c",
              "import sys; sys.stdout.write('A' * 300000 + 'END')"],
        cwd=str(env["ws"]))
    result = snap["result"]
    assert result["truncated"] is True
    assert len(result["stdout_tail"]) <= 262144
    assert result["stdout_tail"].endswith("END")


def test_policy_only_exec_output_is_secret_redacted(broker, env):
    client = BrokerClient()
    client.open("agent-a")
    snap = client.execute(
        argv=[sys.executable, "-c",
              "print('key is AKIAIOSFODNN7EXAMPLE ok')"],
        cwd=str(env["ws"]))
    tail = snap["result"]["stdout_tail"]
    assert "AKIAIOSFODNN7EXAMPLE" not in tail
    assert "[redacted:" in tail


def test_denied_command_never_executes(broker, env):
    target = env["ws"] / "victim"
    target.mkdir()
    (target / "keep.txt").write_text("keep", encoding="utf-8")
    client = BrokerClient()
    client.open("agent-a")
    snap = client.execute(argv=["/bin/rm", "-rf", str(target)],
                          cwd=str(env["ws"]))
    assert snap["state"] == "DENIED"
    assert snap["verdict"] == "deny"
    assert (target / "keep.txt").exists()  # untouched


def test_broker_down_client_fails_closed(env):
    client = BrokerClient()  # nothing is listening on the socket
    with pytest.raises(BrokerUnavailable):
        client.open("agent-a")
    with pytest.raises(BrokerUnavailable):
        client.status()
