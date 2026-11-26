"""Approval lifecycle (spec §4.3).

An ask verdict parks the request in AWAITING_APPROVAL. The only
way out is a decision that carries the *approval capability*: a
token the broker generates into ~/.seatbelt/broker.approval-token
(mode 0600) and hands to the user's own interactive CLI
(`seatbelt approve` / `seatbelt deny`). Agent sessions hold a
session token, which is a different credential and is never
accepted here — an agent cannot approve its own request.

Approvals are single-use and bound to request_hash(): the pending
record stores the hash of the exact request, the decision consumes
the record, and the server re-checks the hash before executing —
a changed request after submission is refused, never approved
retroactively.
"""

from __future__ import annotations

import os
import secrets
import threading
from pathlib import Path

from .ledger import seatbelt_home

TOKEN_FILENAME = "broker.approval-token"


def approval_token_path():
    override = os.environ.get("SEATBELT_APPROVAL_TOKEN_PATH")
    if override:
        return Path(override)
    return seatbelt_home() / TOKEN_FILENAME


def load_or_create_approval_token():
    """Read the approval capability token, creating it (0600) on
    first use. Only code running as the user outside a sandbox can
    read this file: ~/.seatbelt is on the sandbox always-deny list."""
    path = approval_token_path()
    try:
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (token + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return token


def read_approval_token():
    try:
        return approval_token_path().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


class ApprovalError(Exception):
    pass


class ApprovalManager:
    """Pending decisions, keyed by request_id. Thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending = {}   # request_id -> record
        self._consumed = {}  # request_id -> record (single-use proof)

    def park(self, request_id, session_id, req_hash, summary):
        with self._lock:
            if request_id in self._pending or request_id in self._consumed:
                raise ApprovalError("request %s already decided or "
                                    "pending" % request_id)
            self._pending[request_id] = {
                "request_id": request_id,
                "session_id": session_id,
                "request_hash": req_hash,
                "summary": summary,
                "decision": None,
            }

    def decide(self, request_id, approve, capability_token, expected_token):
        """Record the user's decision. Raises ApprovalError unless
        the capability token matches and the request is still
        pending. Returns the pending record on success."""
        if not expected_token or not capability_token or \
                not secrets.compare_digest(capability_token,
                                           expected_token):
            raise ApprovalError("approval capability token missing or "
                                "invalid — only the user's own CLI "
                                "(seatbelt approve/deny) can decide")
        with self._lock:
            rec = self._pending.pop(request_id, None)
            if rec is None:
                if request_id in self._consumed:
                    raise ApprovalError(
                        "request %s was already decided — approvals "
                        "are single-use" % request_id)
                raise ApprovalError("no pending approval for request %s"
                                    % request_id)
            rec["decision"] = "approved" if approve else "denied"
            self._consumed[request_id] = rec
            return rec

    def decision_for(self, request_id):
        """The consumed decision record for request_id, or None."""
        with self._lock:
            rec = self._consumed.get(request_id)
            return dict(rec) if rec is not None else None

    def pending(self):
        with self._lock:
            return [dict(r) for r in self._pending.values()]

    def is_pending(self, request_id):
        with self._lock:
            return request_id in self._pending
