"""Broker isolation (0.4.0, B5): the escape battery. A broker in
isolation mode runs every execution inside unprivileged Linux
namespaces; these tests attack that boundary for real: secret
reads, writes outside the workspace, network access on profile
none, fork bombs, detached children, timeouts, symlink escapes.

If unprivileged namespaces are unavailable in the environment,
the whole module skips — loudly, via the skip reason — rather
than passing vacuously.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG / "src"))

from agent_seatbelt.broker import sandbox_linux  # noqa: E402
from agent_seatbelt.broker.client import BrokerClient  # noqa: E402
from test_broker_server import BASE_CONFIG, start_broker, stop_broker  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and sandbox_linux.probe()),
    reason="unprivileged user namespaces unavailable in this "
           "environment — isolation battery cannot run here")

CONFIG = dict(BASE_CONFIG, isolation="namespace")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text("HOST-SECRET-KEY",
                                          encoding="utf-8")
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text("HOST-AWS-SECRET",
                                               encoding="utf-8")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "note.txt").write_text("workspace file", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SEATBELT_HOME", str(home / ".seatbelt"))
    monkeypatch.setenv("SEATBELT_BROKER_SOCK",
                       str(tmp_path / "broker.sock"))
    monkeypatch.delenv("SEATBELT_JUDGE_COMMAND", raising=False)
    monkeypatch.delenv("SEATBELT_MODE", raising=False)
    return {"home": home, "ws": ws, "sock": tmp_path / "broker.sock"}


@pytest.fixture()
def broker(env):
    start_broker(dict(CONFIG))
    yield
    stop_broker()


@pytest.fixture()
def client(broker):
    c = BrokerClient()
    c.open("escape-artist")
    return c


def run(client, env, argv, **kwargs):
    kwargs.setdefault("cwd", str(env["ws"]))
    kwargs.setdefault("filesystem", ["workspace-write"])
    kwargs.setdefault("timeout_seconds", 30)
    return client.execute(argv=argv, **kwargs)


# Inside the sandbox only the bound system tree exists, so the
# interpreter must be addressed by its system path, not by the
# test runner's venv path (which lives under an unbound $HOME).
PY = "/usr/bin/python3"


# ── filesystem escapes ───────────────────────────────────────────────

def test_cannot_read_ssh_key(client, env):
    secret = env["home"] / ".ssh" / "id_rsa"
    snap = run(client, env, [PY, "-c",
                             "print(open(%r).read())" % str(secret)])
    result = snap["result"]
    assert "HOST-SECRET-KEY" not in result["stdout_tail"]
    assert result["exit_code"] != 0  # the file does not exist inside


def test_cannot_read_aws_credentials(client, env):
    creds = env["home"] / ".aws" / "credentials"
    snap = run(client, env, [PY, "-c",
                             "print(open(%r).read())" % str(creds)])
    assert "HOST-AWS-SECRET" not in snap["result"]["stdout_tail"]
    assert snap["result"]["exit_code"] != 0


def test_cannot_read_broker_ledger(client, env):
    ledger = env["home"] / ".seatbelt" / "ledger.jsonl"
    assert ledger.exists()  # it exists on the host
    snap = run(client, env, [PY, "-c",
                             "print(open(%r).read())" % str(ledger)])
    assert snap["result"]["exit_code"] != 0


def test_write_inside_workspace_works(client, env):
    snap = run(client, env, [PY, "-c",
                             "open('made.txt','w').write('ok')"])
    assert snap["result"]["exit_code"] == 0
    assert (env["ws"] / "made.txt").read_text(
        encoding="utf-8") == "ok"


def test_write_outside_workspace_does_not_reach_host(client, env):
    outside = env["home"] / "evil.txt"
    snap = run(client, env, [PY, "-c",
                             "open(%r,'w').write('pwned')"
                             % str(outside)])
    # The write lands in the sandbox's empty home shadow (or fails
    # outright); either way it must NEVER reach the host home.
    assert not outside.exists()
    host_tmp = Path("/tmp/seatbelt-escape-marker")
    snap = run(client, env, ["/bin/sh", "-c",
                             "echo pwned > %s" % host_tmp])
    assert snap["result"]["exit_code"] == 0  # succeeds in ITS /tmp
    assert not host_tmp.exists()  # which is not the host's /tmp


def test_read_only_profile_blocks_workspace_writes(client, env):
    snap = run(client, env, [PY, "-c",
                             "open('nope.txt','w').write('x')"],
               filesystem=["workspace-read"])
    assert snap["result"]["exit_code"] != 0
    assert not (env["ws"] / "nope.txt").exists()
    # ...while reads still work.
    snap = run(client, env, [PY, "-c",
                             "print(open('note.txt').read())"],
               filesystem=["workspace-read"])
    assert "workspace file" in snap["result"]["stdout_tail"]


def test_symlink_escape_fails(client, env):
    link = env["ws"] / "escape"
    link.symlink_to(env["home"] / ".ssh")
    snap = run(client, env, [PY, "-c",
                             "print(open('escape/id_rsa').read())"])
    assert "HOST-SECRET-KEY" not in snap["result"]["stdout_tail"]
    assert snap["result"]["exit_code"] != 0


# ── network ──────────────────────────────────────────────────────────

def test_network_none_blocks_direct_ip_and_dns(client, env):
    code = (
        "import socket, sys\n"
        "fails = 0\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "except OSError:\n"
        "    fails += 1\n"
        "try:\n"
        "    socket.gethostbyname('example.com')\n"
        "except OSError:\n"
        "    fails += 1\n"
        "print('blocked', fails)\n"
        "sys.exit(0 if fails == 2 else 1)\n")
    snap = run(client, env, [PY, "-c", code], network="none")
    assert snap["result"]["exit_code"] == 0
    assert "blocked 2" in snap["result"]["stdout_tail"]


def test_network_host_not_granted_by_default(client, env):
    # Config does not grant host networking: the request is capped
    # to none, and the response records the effective set.
    snap = run(client, env, ["/bin/true"], network="host")
    assert snap["effective_permissions"]["network"] == "none"


# ── process limits, timeouts, namespace teardown ─────────────────────

def test_fork_bomb_is_contained(client, env):
    code = (
        "import os, time\n"
        "kids = []\n"
        "try:\n"
        "    for _ in range(500):\n"
        "        pid = os.fork()\n"
        "        if pid == 0:\n"
        "            time.sleep(30)\n"
        "            os._exit(0)\n"
        "        kids.append(pid)\n"
        "except OSError:\n"
        "    pass\n"
        "print('spawned', len(kids))\n")
    config_note = client.execute(
        argv=[PY, "-c", code], cwd=str(env["ws"]),
        filesystem=["workspace-write"], timeout_seconds=25)
    result = config_note["result"]
    assert config_note["state"] == "COMPLETED"
    if result.get("limit_exceeded") == "processes":
        # The watchdog killed the tree mid-loop, before the child
        # could print its spawn count (which mechanism fires first
        # is timing-dependent: cgroup-v2 tends to land before the
        # print, rlimit+watchdog after it). The recorded limit is
        # the containment evidence; stdout was never produced.
        assert result["exit_code"] == -9
    else:
        spawned = int(result["stdout_tail"].split("spawned")[1].split()[0])
        # The processes cap (64 in the test config) must bite long
        # before 500.
        assert spawned <= 80


def test_timeout_kills_the_whole_tree(client, env):
    heartbeat = env["ws"] / "heartbeat.txt"
    script = (
        "setsid sh -c 'while true; do date +%%s%%N >> %s; "
        "sleep 0.2; done' & sleep 30" % heartbeat)
    started = time.monotonic()
    snap = run(client, env, ["/bin/sh", "-c", script],
               timeout_seconds=2)
    elapsed = time.monotonic() - started
    assert snap["state"] == "TERMINATED"
    assert snap["result"]["timed_out"] is True
    assert elapsed < 15
    # The detached heartbeat writer died with the namespace.
    lines = heartbeat.read_text(encoding="utf-8").splitlines()
    time.sleep(0.8)
    assert heartbeat.read_text(
        encoding="utf-8").splitlines() == lines


def test_detached_children_die_with_namespace(client, env):
    heartbeat = env["ws"] / "hb2.txt"
    script = (
        "setsid sh -c 'while true; do date +%%s%%N >> %s; "
        "sleep 0.2; done' & sleep 1" % heartbeat)
    snap = run(client, env, ["/bin/sh", "-c", script])
    assert snap["state"] == "COMPLETED"
    lines = heartbeat.read_text(encoding="utf-8").splitlines()
    assert lines  # the detached writer did run during execution
    time.sleep(0.8)
    assert heartbeat.read_text(
        encoding="utf-8").splitlines() == lines  # and then died


def test_sandbox_reports_honest_mechanism(client, env):
    snap = run(client, env, ["/bin/true"])
    result = snap["result"]
    assert result["mode"] == "isolation"
    # cgroup v2 only when a delegated writable subtree exists;
    # otherwise the rlimit+watchdog floor — either way the ledger
    # names what actually applied.
    assert result["limits_mechanism"] in ("cgroup-v2",
                                          "rlimit+watchdog")
    assert snap["effective_permissions"]["filesystem"] == \
        "workspace-write"
