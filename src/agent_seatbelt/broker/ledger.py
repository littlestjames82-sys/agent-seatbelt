"""Broker-mode evidence ledger (spec §5.6): an append-only,
hash-chained JSONL file at ~/.seatbelt/ledger.jsonl — in the
user's home, outside every project tree, so the agent whose work
it records cannot rewrite it through its workspace.

The chain construction is the same as the legacy hook audit log
(sha256 of the canonical record + prev_hash, GENESIS anchor), and
verification mirrors --verify-log, including the round-12 fix:
the first chained record is anchored, so deleting a prefix is
detected instead of silently verifying.

Each record carries: seq (monotonic per ledger, resumed across
broker runs), run_id (which broker run wrote it), ts, the event
fields the writer supplies, prev_hash, hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


def seatbelt_home():
    """The user's Seatbelt state dir. SEATBELT_HOME overrides (tests)."""
    override = os.environ.get("SEATBELT_HOME")
    if override:
        return Path(override)
    return Path.home() / ".seatbelt"


def default_ledger_path():
    override = os.environ.get("SEATBELT_LEDGER_PATH")
    if override:
        return Path(override)
    return seatbelt_home() / "ledger.jsonl"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sanitize(value, depth=0):
    if depth > 6:
        return "..."
    if isinstance(value, str):
        value = "".join(
            ch for ch in value
            if ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127))
        return value[:2000]
    if isinstance(value, dict):
        return {str(k)[:80]: _sanitize(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v, depth + 1) for v in value[:50]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:200]


class Ledger:
    """Thread-safe append-only writer. One Ledger per broker run."""

    def __init__(self, path=None, run_id=None):
        self.path = Path(path) if path else default_ledger_path()
        self.run_id = run_id or uuid.uuid4().hex
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = "GENESIS"
        self._resume()

    def _resume(self):
        """Continue seq/prev from the existing tail so the chain is
        one chain across broker restarts, not per-run fragments."""
        try:
            data = self.path.read_bytes()
        except OSError:
            return
        lines = [ln for ln in data.splitlines() if ln.strip()]
        if not lines:
            return
        try:
            last = json.loads(lines[-1])
        except ValueError:
            return
        if isinstance(last.get("seq"), int):
            self._seq = last["seq"]
        if last.get("hash"):
            self._prev = last["hash"]

    def append(self, event):
        """Append one event; returns the stored record (with seq,
        run_id, prev_hash, hash)."""
        with self._lock:
            rec = _sanitize(dict(event))
            self._seq += 1
            rec["seq"] = self._seq
            rec["run_id"] = self.run_id
            rec.setdefault("ts", _now())
            rec["prev_hash"] = self._prev
            payload = json.dumps(rec, sort_keys=True,
                                 separators=(",", ":"))
            rec["hash"] = hashlib.sha256(
                (payload + self._prev).encode("utf-8")).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            def _opener(path, flags):
                return os.open(path, flags, 0o600)
            with open(self.path, "a", encoding="utf-8",
                      opener=_opener) as fh:
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._prev = rec["hash"]
            return rec

    @property
    def seq(self):
        return self._seq


def verify_ledger(path=None):
    """Verify the chain at path. Returns (ok, message). Mirrors
    run_verify_log's checks: JSON validity, hash recomputation, and
    the anchor check that makes prefix deletion detectable."""
    path = Path(path) if path else default_ledger_path()
    if not path.exists():
        return False, "VERIFY-LEDGER: no ledger found at %s" % path
    lines = [ln for ln in path.read_text(encoding="utf-8",
                                         errors="replace")
             .splitlines() if ln.strip()]
    prev_expected, chained, legacy = "GENESIS", 0, 0
    last_seq = 0
    for i, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except ValueError:
            return False, ("VERIFY-LEDGER: FAIL at line %d — not valid "
                           "JSON." % i)
        if "hash" not in row:
            legacy += 1
            if chained == 0:
                prev_expected = "LEGACY"
            continue
        if row.get("prev_hash") != prev_expected:
            return False, ("VERIFY-LEDGER: FAIL at line %d — prev_hash "
                           "does not match the expected predecessor "
                           "(chain broken or prefix missing)." % i)
        rec = {k: v for k, v in row.items() if k != "hash"}
        payload = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        expect = hashlib.sha256(
            (payload + row["prev_hash"]).encode("utf-8")).hexdigest()
        if expect != row["hash"]:
            return False, ("VERIFY-LEDGER: FAIL at line %d — record "
                           "content does not match its hash "
                           "(tampered)." % i)
        seq = row.get("seq")
        if isinstance(seq, int):
            if seq <= last_seq:
                return False, ("VERIFY-LEDGER: FAIL at line %d — seq "
                               "not monotonic (%s after %s)."
                               % (i, seq, last_seq))
            last_seq = seq
        prev_expected = row["hash"]
        chained += 1
    return True, ("VERIFY-LEDGER: OK — %d chained record(s), %d legacy "
                  "unchained line(s), %d total (%s)"
                  % (chained, legacy, len(lines), path))


def run_verify_ledger(path_arg=None, out=sys.stdout):
    ok, message = verify_ledger(path_arg)
    out.write(message + "\n")
    return 0 if ok else 1
