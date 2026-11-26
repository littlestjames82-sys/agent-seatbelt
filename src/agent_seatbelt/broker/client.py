"""Broker client — the library surface used by `seatbelt exec`,
by approval CLIs, and by anything that routes execution through
the broker (an MCP tool wrapper would sit on top of this).

Fail-closed by construction: if the broker is unreachable, every
operation raises BrokerUnavailable. There is deliberately no code
path here that falls back to executing directly.
"""

from __future__ import annotations

import json
import os
import socket
import uuid

from .server import socket_path


class BrokerUnavailable(Exception):
    """The broker cannot be reached. Execution must not proceed."""


class BrokerError(Exception):
    """The broker refused or failed the operation."""


class BrokerClient:
    def __init__(self, sock=None, timeout=3900.0):
        self.sock_path = str(sock) if sock else str(socket_path())
        self.timeout = timeout
        self.session_id = None
        self.session_token = None
        self.mode = None
        self._agent_id = None
        self._seq = 0

    # ── transport ────────────────────────────────────────────────

    def _rpc(self, doc):
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect(self.sock_path)
        except OSError as exc:
            raise BrokerUnavailable(
                "cannot connect to seatbelt broker at %s: %s — "
                "failing closed; nothing was executed"
                % (self.sock_path, exc))
        try:
            conn.sendall((json.dumps(doc) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError as exc:
            raise BrokerUnavailable(
                "broker connection failed mid-request: %s" % exc)
        finally:
            conn.close()
        try:
            resp = json.loads(buf.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BrokerError("broker sent an unreadable response")
        if not resp.get("ok"):
            raise BrokerError(resp.get("error", "broker error"))
        return resp

    # ── ops ──────────────────────────────────────────────────────

    def status(self):
        return self._rpc({"op": "status"})

    def open_session(self, agent_id, client_label=""):
        resp = self._rpc({"op": "session_open", "agent_id": agent_id,
                          "client_label": client_label})
        self.session_id = resp["session_id"]
        self.session_token = resp["session_token"]
        self.mode = resp.get("mode")
        return resp

    def close_session(self):
        if self.session_id:
            try:
                self._rpc({"op": "session_close",
                           "session_id": self.session_id,
                           "session_token": self.session_token})
            finally:
                self.session_id = None
                self.session_token = None

    def execute(self, argv=None, command=None, cwd=None,
                filesystem=None, network="none", process="restricted",
                timeout_seconds=120, request_id=None):
        """Submit one execution and return the terminal snapshot.
        The broker blocks through any approval wait, so the reply
        is the final state (COMPLETED / DENIED / FAILED /
        TERMINATED)."""
        if self.session_id is None:
            raise BrokerError("open a session before executing")
        request = {
            "protocol_version": "1",
            "request_id": request_id or uuid.uuid4().hex,
            "session_id": self.session_id,
            "agent_id": self._agent_id,
            "operation": "execute",
            "working_directory": cwd or os.getcwd(),
            "requested_permissions": {
                "filesystem": filesystem or ["workspace-read"],
                "network": network,
                "process": process,
            },
            "timeout_seconds": timeout_seconds,
            "seq": self._seq,
        }
        self._seq += 1
        if argv is not None:
            request["argv"] = list(argv)
        if command is not None:
            request["command"] = command
        return self._rpc({"op": "execute",
                          "session_id": self.session_id,
                          "session_token": self.session_token,
                          "request": request})

    def open(self, agent_id, client_label=""):
        self._agent_id = agent_id
        return self.open_session(agent_id, client_label)

    def poll(self, request_id):
        return self._rpc({"op": "poll",
                          "session_id": self.session_id,
                          "session_token": self.session_token,
                          "request_id": request_id})

    # ── user-side operations (approval capability) ───────────────

    def approve(self, request_id, approval_token):
        return self._rpc({"op": "approve", "request_id": request_id,
                          "approval_token": approval_token})

    def deny(self, request_id, approval_token):
        return self._rpc({"op": "deny", "request_id": request_id,
                          "approval_token": approval_token})

    def pending(self, approval_token):
        return self._rpc({"op": "pending",
                          "approval_token": approval_token})

    def shutdown(self, approval_token):
        return self._rpc({"op": "shutdown",
                          "approval_token": approval_token})
