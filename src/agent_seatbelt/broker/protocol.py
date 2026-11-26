"""Broker protocol v1: request validation + the authorization
state machine (spec 0.4.0 §4.1-4.2). Pure code — no I/O, no
execution — so every legal/illegal transition and every malformed
input can be unit-tested without a daemon.

Wire format: newline-delimited JSON objects over a Unix socket.
This module validates the *execute request* document; the server
validates the transport envelope (op / session fields) itself.

State machine (design §5.3):

    RECEIVED -> VALIDATING
    VALIDATING -> DENIED | AWAITING_APPROVAL | AUTHORIZED | FAILED
    AWAITING_APPROVAL -> AUTHORIZED | DENIED | TERMINATED | FAILED
    AUTHORIZED -> PREPARING_SANDBOX | FAILED | TERMINATED
    PREPARING_SANDBOX -> EXECUTING | FAILED | TERMINATED
    EXECUTING -> VERIFYING | FAILED | TERMINATED
    VERIFYING -> COMPLETED | FAILED
    DENIED / COMPLETED / FAILED / TERMINATED are terminal.

Malformed input never advances state: validate_request() raises
before a machine exists, and RequestMachine.transition() raises
ProtocolError on any illegal move.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path

PROTOCOL_VERSION = "1"

STATES = (
    "RECEIVED",
    "VALIDATING",
    "DENIED",
    "AWAITING_APPROVAL",
    "AUTHORIZED",
    "PREPARING_SANDBOX",
    "EXECUTING",
    "VERIFYING",
    "COMPLETED",
    "FAILED",
    "TERMINATED",
)

TERMINAL_STATES = frozenset(
    ("DENIED", "COMPLETED", "FAILED", "TERMINATED"))

_TRANSITIONS = {
    "RECEIVED": frozenset(("VALIDATING", "FAILED", "TERMINATED")),
    "VALIDATING": frozenset(
        ("DENIED", "AWAITING_APPROVAL", "AUTHORIZED",
         "FAILED", "TERMINATED")),
    "AWAITING_APPROVAL": frozenset(
        ("AUTHORIZED", "DENIED", "FAILED", "TERMINATED")),
    "AUTHORIZED": frozenset(
        ("PREPARING_SANDBOX", "FAILED", "TERMINATED")),
    "PREPARING_SANDBOX": frozenset(
        ("EXECUTING", "FAILED", "TERMINATED")),
    "EXECUTING": frozenset(("VERIFYING", "FAILED", "TERMINATED")),
    "VERIFYING": frozenset(("COMPLETED", "FAILED", "TERMINATED")),
    "DENIED": frozenset(),
    "COMPLETED": frozenset(),
    "FAILED": frozenset(),
    "TERMINATED": frozenset(),
}

# Filesystem permission tokens a client may request. The broker maps
# them to sandbox profiles; config decides what may be granted.
FS_TOKENS = ("workspace-read", "workspace-write", "temporary",
             "extended")
NETWORK_PROFILES = ("none", "host")
PROCESS_PROFILES = ("restricted", "unrestricted")

MAX_COMMAND_CHARS = 16384
MAX_ARGV_ITEMS = 512
MAX_ARGV_ITEM_CHARS = 8192
MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 120

_REQUEST_FIELDS = frozenset((
    "protocol_version", "request_id", "session_id", "agent_id",
    "operation", "command", "argv", "working_directory",
    "requested_permissions", "timeout_seconds", "seq",
))

_PERMISSION_FIELDS = frozenset(("filesystem", "network", "process"))


class ProtocolError(Exception):
    """An illegal state transition or protocol-level refusal."""


class ValidationError(ProtocolError):
    """The request document is malformed; no state advances."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_request(doc):
    """Validate an execute-request document and return a normalized
    copy. Raises ValidationError on any defect — the caller must not
    create or advance a state machine for a rejected document."""
    if not isinstance(doc, dict):
        raise ValidationError("request must be a JSON object")
    unknown = set(doc) - _REQUEST_FIELDS
    if unknown:
        raise ValidationError(
            "unknown field(s): %s" % ", ".join(sorted(unknown)))
    if doc.get("protocol_version") != PROTOCOL_VERSION:
        raise ValidationError(
            "protocol_version must be %r" % PROTOCOL_VERSION)
    request_id = doc.get("request_id")
    if not isinstance(request_id, str) or not 8 <= len(request_id) <= 64:
        raise ValidationError("request_id must be a string of 8-64 chars")
    session_id = doc.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ValidationError("session_id must be a non-empty string")
    agent_id = doc.get("agent_id")
    if not isinstance(agent_id, str) or not 1 <= len(agent_id) <= 128:
        raise ValidationError("agent_id must be a string of 1-128 chars")
    if doc.get("operation") != "execute":
        raise ValidationError("operation must be 'execute' in protocol v1")

    argv = doc.get("argv")
    command = doc.get("command")
    if argv is not None:
        if not isinstance(argv, list) or not argv:
            raise ValidationError("argv must be a non-empty list")
        if len(argv) > MAX_ARGV_ITEMS:
            raise ValidationError("argv has too many items")
        for item in argv:
            if not isinstance(item, str) or not item:
                raise ValidationError("argv items must be non-empty strings")
            if len(item) > MAX_ARGV_ITEM_CHARS:
                raise ValidationError("argv item too long")
        if command is not None and not isinstance(command, str):
            raise ValidationError("command must be a string")
    elif command is not None:
        if not isinstance(command, str) or not command.strip():
            raise ValidationError("command must be a non-empty string")
        if len(command) > MAX_COMMAND_CHARS:
            raise ValidationError("command too long")
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise ValidationError("command does not parse: %s" % exc)
        if not argv:
            raise ValidationError("command parses to an empty argv")
    else:
        raise ValidationError("one of argv / command is required")
    if command is None:
        command = shlex.join(argv)

    cwd = doc.get("working_directory")
    if not isinstance(cwd, str) or not cwd:
        raise ValidationError("working_directory must be a non-empty string")
    if not Path(cwd).is_absolute():
        raise ValidationError("working_directory must be absolute")
    cwd = str(Path(cwd).resolve())

    perms = doc.get("requested_permissions") or {}
    if not isinstance(perms, dict):
        raise ValidationError("requested_permissions must be an object")
    unknown = set(perms) - _PERMISSION_FIELDS
    if unknown:
        raise ValidationError(
            "unknown permission field(s): %s" % ", ".join(sorted(unknown)))
    fs = perms.get("filesystem", ["workspace-read"])
    if not isinstance(fs, list) or not fs:
        raise ValidationError("filesystem permissions must be a non-empty list")
    for token in fs:
        if token not in FS_TOKENS:
            raise ValidationError("unknown filesystem token: %r" % (token,))
    network = perms.get("network", "none")
    if network not in NETWORK_PROFILES:
        raise ValidationError("network must be one of %s" % (NETWORK_PROFILES,))
    process = perms.get("process", "restricted")
    if process not in PROCESS_PROFILES:
        raise ValidationError("process must be one of %s" % (PROCESS_PROFILES,))

    timeout = doc.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not _is_int(timeout) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ValidationError(
            "timeout_seconds must be an int in 1..%d" % MAX_TIMEOUT_SECONDS)
    seq = doc.get("seq")
    if seq is not None and (not _is_int(seq) or seq < 0):
        raise ValidationError("seq must be a non-negative int")

    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "operation": "execute",
        "command": command,
        "argv": list(argv),
        "command_was_string": doc.get("argv") is None,
        "working_directory": cwd,
        "requested_permissions": {
            "filesystem": list(fs),
            "network": network,
            "process": process,
        },
        "timeout_seconds": timeout,
        "seq": seq,
    }


def request_hash(normalized):
    """The hash an approval binds to: the exact executable content
    of the request. Any change to argv/command, cwd, permissions or
    timeout produces a different hash, hence a different request."""
    core = {
        "argv": normalized["argv"],
        "command": normalized["command"],
        "working_directory": normalized["working_directory"],
        "requested_permissions": normalized["requested_permissions"],
        "timeout_seconds": normalized["timeout_seconds"],
    }
    payload = json.dumps(core, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RequestMachine:
    """One request's walk through the authorization states. Every
    transition is recorded in .history as (from, to) pairs; the
    server turns each into a ledger event."""

    def __init__(self, request):
        self.request = request
        self.request_id = request["request_id"]
        self.session_id = request["session_id"]
        self.state = "RECEIVED"
        self.history = []
        self.verdict = None
        self.rule_id = None
        self.reason = None
        self.effective_permissions = None
        self.result = None
        self.error = None

    def transition(self, to_state):
        if to_state not in _TRANSITIONS[self.state]:
            raise ProtocolError(
                "illegal transition %s -> %s for request %s"
                % (self.state, to_state, self.request_id))
        self.history.append((self.state, to_state))
        self.state = to_state
        return self.state

    @property
    def terminal(self):
        return self.state in TERMINAL_STATES

    def snapshot(self):
        snap = {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "state": self.state,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "effective_permissions": self.effective_permissions,
        }
        if self.result is not None:
            snap["result"] = self.result
        if self.error is not None:
            snap["error"] = self.error
        return snap
