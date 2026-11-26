"""Broker evidence ledger (0.4.0, B2): hash chain, monotonic seq
across broker runs, tamper evidence, and prefix-deletion
detection — the same guarantees --verify-log gives the legacy
audit log, verified the same way.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from agent_seatbelt.broker.ledger import Ledger, verify_ledger
from agent_seatbelt.cli import main as cli_main


def read_rows(path):
    return [json.loads(ln) for ln in
            Path(path).read_text(encoding="utf-8").splitlines()
            if ln.strip()]


def write_rows(path, rows):
    Path(path).write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_chain_appends_and_verifies(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path=path, run_id="run-a")
    ledger.append({"event": "broker_start"})
    ledger.append({"event": "transition", "request_id": "r1",
                   "from": "RECEIVED", "to": "VALIDATING"})
    rows = read_rows(path)
    assert rows[0]["prev_hash"] == "GENESIS"
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert rows[1]["run_id"] == "run-a"
    ok, message = verify_ledger(path)
    assert ok, message
    assert "2 chained record(s)" in message


def test_seq_resumes_across_runs(tmp_path):
    path = tmp_path / "ledger.jsonl"
    first = Ledger(path=path, run_id="run-a")
    first.append({"event": "one"})
    first.append({"event": "two"})
    second = Ledger(path=path, run_id="run-b")
    rec = second.append({"event": "three"})
    assert rec["seq"] == 3
    assert rec["run_id"] == "run-b"
    rows = read_rows(path)
    assert rows[2]["prev_hash"] == rows[1]["hash"]  # one chain
    ok, _msg = verify_ledger(path)
    assert ok


def test_tampered_record_fails_verification(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path=path, run_id="run-a")
    ledger.append({"event": "transition", "to": "DENIED"})
    ledger.append({"event": "transition", "to": "COMPLETED"})
    rows = read_rows(path)
    rows[0]["to"] = "COMPLETED"  # rewrite history
    write_rows(path, rows)
    ok, message = verify_ledger(path)
    assert not ok
    assert "line 1" in message


def test_prefix_deletion_fails_verification(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path=path, run_id="run-a")
    for i in range(3):
        ledger.append({"event": "e%d" % i})
    rows = read_rows(path)
    write_rows(path, rows[1:])  # delete the first chained record
    ok, message = verify_ledger(path)
    assert not ok
    assert "prefix missing" in message


def test_truncated_tail_fails_verification(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path=path, run_id="run-a")
    ledger.append({"event": "one"})
    ledger.append({"event": "two"})
    rows = read_rows(path)
    rows[1]["hash"] = rows[1]["hash"][:-4] + "0000"
    write_rows(path, rows)
    ok, _message = verify_ledger(path)
    assert not ok


def test_missing_ledger_reports_not_ok(tmp_path):
    ok, message = verify_ledger(tmp_path / "nope.jsonl")
    assert not ok
    assert "no ledger found" in message


def test_verify_ledger_cli(tmp_path):
    from agent_seatbelt.broker.ledger import run_verify_ledger
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path=path, run_id="run-a")
    ledger.append({"event": "one"})
    buf = io.StringIO()
    assert run_verify_ledger(str(path), out=buf) == 0
    assert "VERIFY-LEDGER: OK" in buf.getvalue()
    assert cli_main(["verify-ledger", str(path)]) == 0
    rows = read_rows(path)
    rows[0]["event"] = "forged"
    write_rows(path, rows)
    assert cli_main(["verify-ledger", str(path)]) == 1
