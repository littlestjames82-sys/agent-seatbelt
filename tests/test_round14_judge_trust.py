"""Round 14 battery (v0.3.5): the judge trust boundary (finding
F-14-01). Before 0.3.5 the judge command was read from the PROJECT
file .seatbelt/policy.json and executed via a shell with the user's
permissions — a cloned repo could run code on the back of a harmless
allow verdict. Now a judge command is trusted only from the user:
SEATBELT_JUDGE_COMMAND, ~/.seatbelt/policy.json, or the hash-pinned
registry ~/.seatbelt/judges.json (referenced by name). Project
proposals are audit-logged and surfaced by --doctor, never run.
Everything runs against the real hook as a subprocess in tmp dirs
with an isolated HOME.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parent.parent
HOOK = _PKG / "hooks" / "seatbelt_hook.py"


# ── helpers (mirroring test_round9.py) ───────────────────────────────

def drive(payload, cwd, env_extra=None, mode="enforce"):
    env = dict(os.environ, SEATBELT_MODE=mode)
    env.pop("SEATBELT_JUDGE_COMMAND", None)
    env.pop("SEATBELT_JUDGE_TIMEOUT_MS", None)
    if env_extra:
        env.update(env_extra)
    payload = {**payload, "cwd": str(cwd)}
    return subprocess.run([sys.executable, str(HOOK)],
                          input=json.dumps(payload), capture_output=True,
                          text=True, timeout=30, env=env)


def cli(args, cwd, home):
    env = dict(os.environ, HOME=str(home))
    env.pop("SEATBELT_JUDGE_COMMAND", None)
    env.pop("SEATBELT_JUDGE_TIMEOUT_MS", None)
    return subprocess.run([sys.executable, str(HOOK)] + args,
                          capture_output=True, text=True, timeout=30,
                          cwd=str(cwd), env=env)


def pretool(command, session="r14"):
    return {"hook_event_name": "PreToolUse", "session_id": session,
            "tool_name": "Bash", "tool_input": {"command": command}}


def decision_of(proc):
    if not proc.stdout.strip():
        return None
    doc = json.loads(proc.stdout)
    return doc["hookSpecificOutput"]["permissionDecision"]


def audit_records(cwd):
    path = Path(cwd) / ".seatbelt" / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]


def judge_records(cwd):
    return [r for r in audit_records(cwd)
            if r.get("rule_id") == "seatbelt-judge"]


def set_project_policy(tmp, doc):
    seat = Path(tmp) / ".seatbelt"
    seat.mkdir(parents=True, exist_ok=True)
    (seat / "policy.json").write_text(json.dumps(doc), encoding="utf-8")


def set_user_policy(home, doc):
    seat = Path(home) / ".seatbelt"
    seat.mkdir(parents=True, exist_ok=True)
    (seat / "policy.json").write_text(json.dumps(doc), encoding="utf-8")


def marker_judge(tmp, reply, name="judge.py", marker_name="judge-ran.txt"):
    """A judge script that proves it ran by writing a marker file."""
    marker = Path(tmp) / marker_name
    path = Path(tmp) / name
    body = ("import json, sys\n"
            "json.load(sys.stdin)\n"
            "open(%r, 'w').write('ran')\n"
            "sys.stdout.write(%r)" % (str(marker), json.dumps(reply)))
    path.write_text(body, encoding="utf-8")
    return "%s %s" % (sys.executable, path), marker, path


def set_registry(home, entries):
    seat = Path(home) / ".seatbelt"
    seat.mkdir(parents=True, exist_ok=True)
    (seat / "judges.json").write_text(
        json.dumps({"judges": entries}), encoding="utf-8")


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture()
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


ESCALATE = {"escalate": True, "reason": "judge wants a human eye"}


# ── the attack: project-supplied commands ────────────────────────────

def test_project_judge_command_never_executes(tmp_path, home):
    cmd, marker, _p = marker_judge(tmp_path, ESCALATE)
    set_project_policy(tmp_path, {"judge": {"command": cmd}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "allow"  # verdict untouched
    assert not marker.exists()  # the planted command never ran
    recs = judge_records(tmp_path)
    assert len(recs) == 1
    assert recs[0]["judge_outcome"] == "untrusted-project-judge"
    assert recs[0]["decision"] == "allow"


def test_project_command_ignored_when_user_judge_configured(tmp_path,
                                                            home):
    evil_cmd, evil_marker, _p = marker_judge(
        tmp_path, ESCALATE, name="evil.py", marker_name="evil-ran.txt")
    good_cmd, good_marker, _p2 = marker_judge(
        tmp_path, ESCALATE, name="good.py", marker_name="good-ran.txt")
    set_project_policy(tmp_path, {"judge": {"command": evil_cmd}})
    set_user_policy(home, {"judge": {"command": good_cmd}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "ask"  # the USER judge escalated
    assert good_marker.exists()
    assert not evil_marker.exists()  # the project command never ran
    recs = judge_records(tmp_path)
    assert len(recs) == 1 and recs[0]["judge_outcome"] == "escalated"


def test_doctor_flags_project_proposal(tmp_path, home):
    cmd, _m, _p = marker_judge(tmp_path, ESCALATE)
    set_project_policy(tmp_path, {"judge": {"command": cmd}})
    proc = cli(["--doctor"], tmp_path, home)
    assert "project proposes a judge command" in proc.stdout
    assert "NOT trusted, never run" in proc.stdout


# ── trusted sources still work ───────────────────────────────────────

def test_user_policy_command_executes_and_escalates(tmp_path, home):
    cmd, marker, _p = marker_judge(tmp_path, ESCALATE)
    set_user_policy(home, {"judge": {"command": cmd}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "ask"
    assert marker.exists()
    recs = judge_records(tmp_path)
    assert len(recs) == 1 and recs[0]["judge_outcome"] == "escalated"


def test_project_name_resolves_registered_pinned_judge(tmp_path, home):
    _cmd, marker, script = marker_judge(tmp_path, ESCALATE)
    set_registry(home, [{"id": "deploys",
                         "executable": sys.executable,
                         "args": [str(script)],
                         "sha256": sha256_of(sys.executable)}])
    set_project_policy(tmp_path, {"judge": {"name": "deploys"}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "ask"  # registered judge escalated
    assert marker.exists()
    recs = judge_records(tmp_path)
    assert len(recs) == 1 and recs[0]["judge_outcome"] == "escalated"


def test_user_name_resolves_registered_pinned_judge(tmp_path, home):
    _cmd, marker, script = marker_judge(tmp_path, ESCALATE)
    set_registry(home, [{"id": "deploys",
                         "executable": sys.executable,
                         "args": [str(script)],
                         "sha256": sha256_of(sys.executable)}])
    set_user_policy(home, {"judge": {"name": "deploys"}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "ask"
    assert marker.exists()


# ── pinning is enforced ──────────────────────────────────────────────

def test_registry_wrong_sha256_never_executes(tmp_path, home):
    _cmd, marker, script = marker_judge(tmp_path, ESCALATE)
    set_registry(home, [{"id": "deploys",
                         "executable": sys.executable,
                         "args": [str(script)],
                         "sha256": "0" * 64}])  # wrong pin
    set_project_policy(tmp_path, {"judge": {"name": "deploys"}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "allow"  # no escalation
    assert not marker.exists()  # hash mismatch: never executed
    recs = judge_records(tmp_path)
    assert recs and recs[0]["judge_outcome"] == "hash-mismatch"


def test_registry_unpinned_entry_is_untrusted(tmp_path, home):
    _cmd, marker, script = marker_judge(tmp_path, ESCALATE)
    set_registry(home, [{"id": "deploys",
                         "executable": sys.executable,
                         "args": [str(script)]}])  # no sha256 at all
    set_project_policy(tmp_path, {"judge": {"name": "deploys"}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "allow"
    assert not marker.exists()
    recs = judge_records(tmp_path)
    assert recs and recs[0]["judge_outcome"] == "judge-not-registered"


def test_project_name_without_registry_entry(tmp_path, home):
    set_project_policy(tmp_path, {"judge": {"name": "ghost"}})
    proc = drive(pretool("git status"), tmp_path, {"HOME": str(home)})
    assert decision_of(proc) == "allow"
    recs = judge_records(tmp_path)
    assert len(recs) == 1
    assert recs[0]["judge_outcome"] == "judge-not-registered"


# ── the registry CLI ─────────────────────────────────────────────────

def test_register_judge_cli_and_listing(tmp_path, home):
    _cmd, _m, script = marker_judge(tmp_path, ESCALATE)
    proc = cli(["--register-judge", "deploys", "--exec", sys.executable,
                "--arg", str(script), "--timeout-ms", "5000"],
               tmp_path, home)
    assert proc.returncode == 0
    assert "Registered judge 'deploys'" in proc.stdout
    reg_path = Path(home) / ".seatbelt" / "judges.json"
    doc = json.loads(reg_path.read_text(encoding="utf-8"))
    entries = doc["judges"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["id"] == "deploys"
    assert entry["executable"] == sys.executable
    assert entry["args"] == [str(script)]
    assert entry["sha256"] == sha256_of(sys.executable)
    assert entry["timeout_ms"] == 5000
    proc = cli(["--judges"], tmp_path, home)
    assert proc.returncode == 0
    assert "deploys" in proc.stdout
    assert entry["sha256"][:12] in proc.stdout
