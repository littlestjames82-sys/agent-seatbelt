"""Round 7 battery (SHINE7): ASI tagging, shadow mode, Codex ask
mapping, MCP rug-pull watch, evidence bundle, Gemini LEGACY marking."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

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
    env.pop("SEATBELT_AGENT", None)
    env.pop("SEATBELT_MODE", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, str(HOOK)],
                          input=json.dumps(payload), capture_output=True,
                          text=True, cwd=str(cwd), env=env, timeout=25)
    assert proc.returncode == 0, proc.stderr
    return proc


def pretool(command, cwd, session="r7", tool="Bash", tool_input=None):
    return {"hook_event_name": "PreToolUse", "session_id": session,
            "cwd": str(cwd), "tool_name": tool,
            "tool_input": tool_input or {"command": command}}


# ── Y3: ASI everywhere ──────────────────────────────────────────────

def test_every_rule_resolves_an_asi_id():
    ids = set()
    for rule_id, _fn, _why in hook.LOCKED_DENY + hook.LOCKED_ASK:
        ids.add(rule_id)
    ids |= {"seatbelt-locked-secret-read", "seatbelt-mcp-destructive-verb",
            "seatbelt-injection-flag", "seatbelt-flight-plan",
            "seatbelt-locked-brain-edit-tainted", "seatbelt-loop-guard",
            "seatbelt-locked-code-link-following", "seatbelt-mcp-drift"}
    for rule_id in ids:
        asi = hook._asi_for(rule_id)
        assert asi.startswith("ASI0") or asi.startswith("ASI1"), rule_id


def test_audit_records_carry_asi(tmp_path):
    drive(pretool("rm -rf /", tmp_path), tmp_path)
    rows = [json.loads(ln) for ln in
            (tmp_path / ".seatbelt" / "audit.jsonl").read_text().splitlines()]
    assert rows and all("asi" in r for r in rows if r.get("rule_id"))


def test_bench_cases_carry_asi():
    cases = [json.loads(ln) for ln in
             (ROOT / "bench" / "cases.jsonl").read_text().splitlines() if ln.strip()]
    assert all("asi" in c for c in cases)
    assert all(c["asi"].startswith("ASI") for c in cases
               if c["category"] != "benign")


def test_report_groups_by_asi(tmp_path):
    drive(pretool("rm -rf /", tmp_path), tmp_path)
    proc = subprocess.run([sys.executable, str(HOOK), "--report"],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert "OWASP Agentic ASI" in proc.stdout and "ASI02" in proc.stdout


# ── Y5: shadow mode ─────────────────────────────────────────────────

def test_shadow_mode_never_emits(tmp_path):
    proc = drive(pretool("rm -rf /", tmp_path), tmp_path,
                 env_extra={"SEATBELT_MODE": "shadow"})
    assert proc.stdout.strip() == ""
    rows = [json.loads(ln) for ln in
            (tmp_path / ".seatbelt" / "audit.jsonl").read_text().splitlines()]
    shadow_rows = [r for r in rows if r.get("mode") == "shadow"]
    assert shadow_rows and shadow_rows[-1]["decision"] == "deny"


def test_shadow_report_section(tmp_path):
    drive(pretool("rm -rf /", tmp_path), tmp_path,
          env_extra={"SEATBELT_MODE": "shadow"})
    proc = subprocess.run([sys.executable, str(HOOK), "--report"],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert "Shadow mode" in proc.stdout and "would-deny" in proc.stdout


# ── Y2: ask portability ─────────────────────────────────────────────

def test_codex_ask_maps_to_deny_in_strict(tmp_path):
    # On Codex a strict policy must never rest on an ask (Codex hooks
    # can fail open): strict mode upgrades asks, the CI conversion
    # denies them, and the Round 7 wrapper maps any residual ask.
    out = drive(pretool("rm file.txt", tmp_path), tmp_path,
                env_extra={"SEATBELT_AGENT": "codex",
                           "SEATBELT_MODE": "strict"})
    doc = json.loads(out.stdout)
    assert doc["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_ask_survives_in_solo(tmp_path):
    out = drive(pretool("rm file.txt", tmp_path), tmp_path,
                env_extra={"SEATBELT_AGENT": "codex"})
    doc = json.loads(out.stdout)
    assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_doctor_warns_for_no_ask_agent(tmp_path):
    proc = subprocess.run([sys.executable, str(HOOK), "--doctor"],
                          capture_output=True, text=True, cwd=str(tmp_path),
                          env=dict(os.environ, SEATBELT_AGENT="codex"))
    assert "no true ask" in proc.stdout


# ── Y4: MCP rug-pull watch ──────────────────────────────────────────

def _mcp_project(tmp_path, secret="PLANTED-SECRET-VALUE-999"):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "db": {"command": "npx", "args": ["db-mcp"],
               "env": {"API_KEY": secret}}}}))
    return home, proj


def _baseline(home, proj):
    # --accept: re-baselining is the human act that absorbs drift
    # (the first call creates the baseline; later calls move it).
    proc = subprocess.run([sys.executable, str(HOOK), "--baseline",
                           "--accept"],
                          capture_output=True, text=True, cwd=str(proj),
                          env=dict(os.environ, HOME=str(home)), timeout=20)
    assert proc.returncode == 0, proc.stderr


def test_mcp_baseline_stores_no_secret_values(tmp_path):
    home, proj = _mcp_project(tmp_path)
    _baseline(home, proj)
    baseline = (home / ".claude" / "seatbelt" / "mcp-baseline.json").read_text()
    assert "PLANTED-SECRET-VALUE-999" not in baseline
    assert "API_KEY" in baseline  # key NAMES are fine


def test_mcp_new_tool_surface_drifts_and_escalates(tmp_path):
    home, proj = _mcp_project(tmp_path)
    env = dict(os.environ, HOME=str(home))
    _baseline(home, proj)
    payload = pretool("", proj, tool="mcp__db__list_tables",
                      tool_input={})
    out = drive(payload, proj, env_extra=env)
    # First sighting of the tool records surface; with an empty
    # baseline surface it counts as drift -> defer escalates to ask.
    doc = json.loads(out.stdout)
    assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "MCP drift" in doc["hookSpecificOutput"]["permissionDecisionReason"]
    # Re-baseline (human act) absorbs the surface; same call defers.
    _baseline(home, proj)
    out = drive(payload, proj, env_extra=env)
    assert out.stdout.strip() == ""


def test_mcp_config_drift_detected(tmp_path, monkeypatch):
    home, proj = _mcp_project(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    _baseline(home, proj)
    doc = json.loads((proj / ".mcp.json").read_text())
    doc["mcpServers"]["db"]["args"] = ["db-mcp", "--god-mode"]
    (proj / ".mcp.json").write_text(json.dumps(doc))
    drift = hook._mcp_drift(str(proj))
    assert "db" in drift


# ── Y7: evidence bundle ─────────────────────────────────────────────

def test_evidence_bundle_is_valid_json_with_chain_status(tmp_path):
    drive(pretool("rm -rf /", tmp_path), tmp_path)
    proc = subprocess.run([sys.executable, str(HOOK), "--report", "--evidence"],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert proc.returncode == 0
    bundle = json.loads(proc.stdout)
    assert bundle["artifact"].startswith("agent-seatbelt evidence")
    assert bundle["audit"]["chain_verified"] is True
    assert "by_asi" in bundle["audit"]
    assert "not legal advice" in bundle["note"]


# ── Y1: Gemini marked LEGACY consistently ───────────────────────────

def test_gemini_legacy_marking():
    examples_readme = (ROOT / "examples" / "README.md").read_text()
    assert "LEGACY" in examples_readme and "Antigravity" in examples_readme
    assert "2026-06-18" in examples_readme
