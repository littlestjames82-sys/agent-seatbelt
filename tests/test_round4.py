"""Round 4 battery (SHINE4): check-file surface, policy schema,
bench + fuzz floors measured from real runs, robustness sample,
version consistency, log sanitization."""

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "seatbelt_hook.py"
sys.path.insert(0, str(ROOT / "bench"))


def load_hook():
    spec = importlib.util.spec_from_file_location("seatbelt_hook", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = load_hook()


# ── V1: --check-file ────────────────────────────────────────────────

def test_check_file_exit_codes(tmp_path):
    bad = tmp_path / "bad.sh"
    bad.write_text("#!/bin/sh\nls\nrm -rf /\n")
    proc = subprocess.run([sys.executable, str(HOOK), "--check-file", str(bad)],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert proc.returncode == 1
    assert "line 3" in proc.stdout
    good = tmp_path / "good.sh"
    good.write_text("#!/bin/sh\ngit status\nnpm test\n")
    proc = subprocess.run([sys.executable, str(HOOK), "--check-file", str(good)],
                          capture_output=True, text=True, cwd=str(tmp_path))
    assert proc.returncode == 0


def test_precommit_and_action_manifests_parse():
    import re
    pc = (ROOT / ".pre-commit-hooks.yaml").read_text()
    assert "seatbelt-check" in pc and "--check-file" in pc
    action = (ROOT / "action.yml").read_text()
    assert "--check-file" in action and "composite" in action
    assert "hooks/seatbelt_hook.py" in action
    # minimal YAML sanity: no tabs, has the keys we rely on
    assert "\t" not in action and "\t" not in pc
    assert re.search(r"^\s*using:\s*['\"]?composite", action, re.M)


# ── V3: schema validation with a stdlib mini-validator ──────────────

def _validate(instance, schema, root_schema, path="$"):
    errors = []
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        return _validate(instance, root_schema["definitions"][ref],
                         root_schema, path)
    if "anyOf" in schema:
        if not any(not _validate(instance, sub, root_schema, path)
                   for sub in schema["anyOf"]):
            errors.append("%s: matches no anyOf branch" % path)
        return errors
    t = schema.get("type")
    if t == "object":
        if not isinstance(instance, dict):
            return ["%s: not an object" % path]
        for req in schema.get("required", []):
            if req not in instance:
                errors.append("%s: missing %s" % (path, req))
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append("%s: unexpected key %s" % (path, key))
        for key, sub in props.items():
            if key in instance:
                errors += _validate(instance[key], sub, root_schema,
                                    path + "." + key)
    elif t == "array":
        if not isinstance(instance, list):
            return ["%s: not an array" % path]
        for i, item in enumerate(instance):
            errors += _validate(item, schema.get("items", {}), root_schema,
                                "%s[%d]" % (path, i))
    elif t == "string":
        if not isinstance(instance, str):
            errors.append("%s: not a string" % path)
    elif t == "boolean":
        if not isinstance(instance, bool):
            errors.append("%s: not a boolean" % path)
    elif t == "number":
        if not isinstance(instance, (int, float)) or isinstance(instance, bool):
            errors.append("%s: not a number" % path)
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("%s: above maximum" % path)
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errors.append("%s: below minimum" % path)
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r not in enum" % (path, instance))
    if "pattern" in schema and isinstance(instance, str):
        import re as _re
        if not _re.search(schema["pattern"], instance):
            errors.append("%s: pattern mismatch" % path)
    return errors


def _schema():
    return json.loads((ROOT / "policies" / "schema.json").read_text())


def test_all_packs_validate_against_schema():
    schema = _schema()
    overlay_def = schema["definitions"]["overlay"]
    for pack in ("solo", "team-strict", "ci", "paranoid"):
        doc = json.loads((ROOT / "policies" / (pack + ".json")).read_text())
        assert doc.get("$schema") == "./schema.json"
        assert _validate(doc, overlay_def, schema) == [], pack


def test_feed_rules_and_index_validate():
    schema = _schema()
    overlay_def = schema["definitions"]["overlay"]
    for rule_file in sorted((ROOT / "feed" / "rules").glob("*.json")):
        doc = json.loads(rule_file.read_text())
        assert _validate(doc, overlay_def, schema) == [], rule_file.name
    index = json.loads((ROOT / "feed" / "index.json").read_text())
    assert _validate(index, schema["definitions"]["feedIndex"], schema) == []


def test_invalid_pack_rejected():
    schema = _schema()
    bad = {"name": "x", "seatbelt_mode": "yolo", "deny_patterns": "rm"}
    assert _validate(bad, schema["definitions"]["overlay"], schema) != []
    bad_plan = {"id": "p", "created": "x", "task": "t", "ttl_hours": 99,
                "allow": {"verbs": ["fly"]}}
    assert _validate(bad_plan, schema["definitions"]["plan"], schema) != []


# ── V2/V5: bench floors (measured, with margin) ─────────────────────

def test_bench_floor():
    from run_bench import load_cases, load_hook as bench_hook, run_cases
    results = run_cases(bench_hook())
    total = len(results)
    ok = sum(1 for r in results if r["ok"])
    assert total >= 180
    # Measured 202/202 on 2026-10-06; floor set below the measurement.
    assert ok / total >= 0.98, [r["name"] for r in results if not r["ok"]]


def test_fuzz_floor():
    from fuzz import mutations
    from run_bench import load_cases, load_hook as bench_hook
    import tempfile
    from run_bench import _apply_fixture
    hk = bench_hook()
    cases = [c for c in load_cases()
             if c["tool"] == "Bash" and c["expected"] in ("deny", "ask")]
    total = caught = 0
    for case in cases:
        with tempfile.TemporaryDirectory() as td:
            if case.get("fixture"):
                _apply_fixture(td, case["fixture"])
            for _kind, mutated in mutations(case["input"]["command"]):
                total += 1
                if hk.evaluate_bash(mutated, cwd=td)["decision"] in ("deny", "ask"):
                    caught += 1
    # Measured 1111/1111 = 100.0% on 2026-10-06; floor below measurement.
    assert total >= 400
    assert caught / total >= 0.95, (caught, total)


def test_robustness_sample():
    from robustness import gen_payloads, check_one
    import random
    rng = random.Random(20261006)
    payloads = gen_payloads(rng, 500)
    failures = [p for p in (check_one(raw) for raw in payloads) if p]
    assert failures == []


def test_injection_bench_sample():
    sys.path.insert(0, str(ROOT / "bench"))
    import run_injection
    cases = run_injection.load_cases()
    assert len([c for c in cases if c["expected"] == "flagged"]) >= 15
    assert len([c for c in cases if c["expected"] == "clean"]) >= 10
    for case in cases:
        tainted, _ = run_injection.run_case(case)
        assert tainted == (case["expected"] == "flagged"), case["name"]


# ── V6: sanitization composes with the hash chain ───────────────────

def test_ansi_laced_payload_produces_clean_chained_record(tmp_path):
    import os
    payload = {"hook_event_name": "PreToolUse", "session_id": "ansi",
               "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_input": {"command": "echo \x1b[31mRED\x1b[0m && ls"}}
    subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                   capture_output=True, text=True, cwd=str(tmp_path))
    raw = (tmp_path / ".seatbelt" / "audit.jsonl").read_text()
    assert "\x1b" not in raw
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) >= 1
    row = json.loads(lines[-1])
    assert "hash" in row and "prev_hash" in row
    proc = subprocess.run([sys.executable, str(HOOK), "--verify-log",
                           str(tmp_path / ".seatbelt" / "audit.jsonl")],
                          capture_output=True, text=True, cwd=str(tmp_path),
                          env=dict(os.environ))
    assert proc.returncode == 0


# ── Version consistency ─────────────────────────────────────────────

def test_version_consistency():
    import re
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    pyproject = (ROOT / "pyproject.toml").read_text()
    init = (ROOT / "src" / "agent_seatbelt" / "__init__.py").read_text()
    v = plugin["version"]
    assert v == "0.3.0"
    assert 'version = "%s"' % v in pyproject
    assert '__version__ = "%s"' % v in init
    assert hook.VERSION == v
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert market["plugins"][0]["version"] == v


def test_hook_parses_as_python38():
    src = HOOK.read_text()
    ast.parse(src, feature_version=(3, 8))
