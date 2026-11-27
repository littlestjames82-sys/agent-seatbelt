"""Broker crash safety (0.4.0, B2/B5): kill -9 the broker
mid-execution. The client must fail closed, the orphaned sandbox
must be reaped by the next broker start, and the ledger must gain
a FAILED event for the request that never completed. Runs the
broker as a real subprocess — an in-process broker cannot be
SIGKILLed.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG / "src"))

from agent_seatbelt.broker import sandbox_linux  # noqa: E402
from agent_seatbelt.broker.client import (  # noqa: E402
    BrokerClient,
    BrokerUnavailable,
)

PY = sys.executable


@pytest.fixture()
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    # The in-process client must look at the same socket, so the
    # test process env gets the same values as the subprocess env.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SEATBELT_HOME", str(home / ".seatbelt"))
    monkeypatch.setenv("SEATBELT_BROKER_SOCK",
                       str(tmp_path / "broker.sock"))
    environ = dict(os.environ)
    environ.update({
        "HOME": str(home),
        "SEATBELT_HOME": str(home / ".seatbelt"),
        "SEATBELT_BROKER_SOCK": str(tmp_path / "broker.sock"),
        "PYTHONPATH": str(_PKG / "src"),
    })
    environ.pop("SEATBELT_JUDGE_COMMAND", None)
    environ.pop("SEATBELT_MODE", None)
    return {"home": home, "ws": ws, "sock": tmp_path / "broker.sock",
            "environ": environ, "tmp": tmp_path}


def start_broker(env):
    proc = subprocess.Popen(
        [PY, "-m", "agent_seatbelt.broker.server"],
        env=env["environ"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True)
    for _ in range(200):
        if env["sock"].exists():
            return proc
        if proc.poll() is not None:
            raise AssertionError("broker exited early: %s"
                                 % proc.stdout.read())
        time.sleep(0.05)
    raise AssertionError("broker socket never appeared")


def ledger_rows(env):
    path = env["home"] / ".seatbelt" / "ledger.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in
            path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def manifest_sandboxes(env):
    mdir = env["home"] / ".seatbelt" / "broker-runs"
    boxes = []
    if mdir.is_dir():
        for entry in mdir.glob("*.json"):
            doc = json.loads(entry.read_text(encoding="utf-8"))
            boxes.extend(doc.get("sandboxes", []))
    return boxes


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


@pytest.mark.skipif(
    not (sys.platform.startswith("linux") and sandbox_linux.probe()),
    reason="broker crash test needs a working namespace sandbox — "
           "the real-launcher probe says this environment cannot "
           "run one (e.g. hosted CI runners that restrict the "
           "namespace operations), so it skips loudly instead of "
           "failing on a sandbox that can never register")
def test_broker_kill_mid_execution(env):
    broker = start_broker(env)
    client = BrokerClient()
    client.open("crash-tester")
    box = {}

    def _run():
        try:
            box["snap"] = client.execute(
                argv=["/bin/sleep", "60"], cwd=str(env["ws"]),
                timeout_seconds=55, request_id="req-crash-001")
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    # Wait until the sandbox is registered in the run manifest.
    init_pid = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        for sb in manifest_sandboxes(env):
            if sb.get("init_pid"):
                init_pid = sb["init_pid"]
                break
        if init_pid:
            break
        time.sleep(0.1)
    assert init_pid, "sandbox never registered in the manifest"
    assert pid_alive(init_pid)

    broker.send_signal(signal.SIGKILL)
    broker.wait(timeout=10)
    thread.join(timeout=15)
    # The client failed closed — no result, an error.
    assert "snap" not in box
    assert isinstance(box.get("error"), Exception)

    # The orphaned sleep is still alive until a broker reaps it...
    assert pid_alive(init_pid)
    # ...and the next broker start reaps it and closes the request
    # out as FAILED in the ledger.
    broker2 = start_broker(env)
    try:
        deadline = time.monotonic() + 15
        failed = False
        while time.monotonic() < deadline:
            if not pid_alive(init_pid):
                rows = ledger_rows(env)
                failed = any(
                    r.get("event") == "transition"
                    and r.get("request_id") == "req-crash-001"
                    and r.get("to") == "FAILED"
                    for r in rows)
                if failed:
                    break
            time.sleep(0.2)
        assert not pid_alive(init_pid), "orphan sandbox not reaped"
        assert failed, "no FAILED ledger event for the crashed " \
                       "request"
    finally:
        broker2.terminate()
        broker2.wait(timeout=10)


def test_daemonize_on_fresh_home(env):
    # Regression: --daemonize opens ~/.seatbelt/broker.log before
    # anything creates the directory; on a fresh home that crashed
    # the daemon before it ever bound the socket.
    assert not (env["home"] / ".seatbelt").exists()
    proc = subprocess.run(
        [PY, "-m", "agent_seatbelt.broker.server", "--daemonize"],
        env=env["environ"], capture_output=True, text=True,
        timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "daemonized" in proc.stdout
    try:
        client = BrokerClient()
        deadline = time.monotonic() + 15
        status = None
        while time.monotonic() < deadline:
            try:
                status = client.status()
                break
            except BrokerUnavailable:
                time.sleep(0.2)
        assert status and status["running"] is True
        from agent_seatbelt.broker.approvals import \
            read_approval_token
        client.shutdown(read_approval_token())
    finally:
        # Make sure no daemon outlives the test.
        subprocess.run(["pkill", "-f",
                        "agent_seatbelt.broker.server"],
                       capture_output=True)


def test_no_broker_no_execution(env):
    # With nothing listening, the client refuses — it never falls
    # back to running the command itself.
    client = BrokerClient()
    with pytest.raises(BrokerUnavailable):
        client.open("nobody")
