"""The Ghost Execution Broker daemon (spec §4).

A user-level process speaking newline-delimited JSON over a Unix
socket. Every connection's peer uid must equal the broker's uid
(SO_PEERCRED). Agent sessions authenticate with a per-session
token; approvals require the separate approval capability token
(see approvals.py) which agent sessions never hold.

Execution paths:
- isolation mode (Linux + namespaces available): every execution
  runs through sandbox_linux's namespace launcher.
- policy-only mode: the broker authorizes and audits but executes
  WITHOUT a sandbox. This mode is chosen once, at startup (config
  "isolation": "none", a non-Linux platform, or "auto" when the
  namespace probe fails) and is reported by status/--doctor and
  printed at startup — it is never a silent per-request downgrade.
  If the user configured "namespace" and isolation is unavailable,
  the broker refuses to start rather than downgrade.

Crash safety: the client fails closed when the broker is absent —
there is no direct-execution fallback anywhere in this package.
On startup the broker reaps orphaned sandboxes recorded in prior
runs' manifests and appends FAILED events for requests a previous
run left in non-terminal states.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import authz, sandbox_linux
from .approvals import ApprovalManager, ApprovalError, \
    load_or_create_approval_token
from .ledger import Ledger, seatbelt_home
from .protocol import ProtocolError, RequestMachine, ValidationError, \
    request_hash, validate_request

MAX_LINE_BYTES = 1024 * 1024

DEFAULT_CONFIG = {
    "isolation": "auto",  # auto | namespace | none
    "allow_network_host": False,
    "filesystem_max": "workspace-write",
    "extended_dirs": [],
    "session_idle_timeout_seconds": 28800,
    "approval_timeout_seconds": 300,
    "output_cap_bytes": 262144,
    "limits": {
        "cpu_seconds": 120,
        "address_space_mb": 2048,
        "memory_mb": 2048,
        "file_size_mb": 256,
        "open_files": 1024,
        "processes": 128,
    },
}

_FS_RANK = {"read-only": 0, "workspace-write": 1, "temporary": 2,
            "extended": 3}
_TOKEN_TO_PROFILE = {"workspace-read": "read-only",
                     "workspace-write": "workspace-write",
                     "temporary": "temporary",
                     "extended": "extended"}


def socket_path():
    override = os.environ.get("SEATBELT_BROKER_SOCK")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "seatbelt" / "broker.sock"
    return seatbelt_home() / "broker.sock"


def config_path():
    override = os.environ.get("SEATBELT_BROKER_CONFIG")
    if override:
        return Path(override)
    return seatbelt_home() / "broker.json"


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    path = config_path()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = None
    if isinstance(doc, dict):
        for key, value in doc.items():
            if key == "limits" and isinstance(value, dict):
                cfg["limits"].update(value)
            else:
                cfg[key] = value
    return cfg


def requested_profile(fs_tokens):
    profile = "read-only"
    for token in fs_tokens:
        cand = _TOKEN_TO_PROFILE[token]
        if _FS_RANK[cand] > _FS_RANK[profile]:
            profile = cand
    return profile


class BrokerError(Exception):
    pass


class _Session:
    def __init__(self, session_id, token, agent_id, label):
        self.session_id = session_id
        self.token = token
        self.agent_id = agent_id
        self.label = label
        self.last_seen = time.monotonic()
        self.last_seq = -1
        self.request_ids = set()


class Broker:
    def __init__(self, config=None, sock=None, ledger=None):
        self.config = config if config is not None else load_config()
        self.sock_path = Path(sock) if sock else socket_path()
        self.ledger = ledger if ledger is not None else Ledger()
        self.run_id = self.ledger.run_id
        self.approvals = ApprovalManager()
        self.approval_token = load_or_create_approval_token()
        self.sessions = {}
        self.requests = {}  # request_id -> {machine, event, session_id}
        self._lock = threading.Lock()
        self._server = None
        self.mode = self._decide_mode()
        self._manifest_dir = seatbelt_home() / "broker-runs"
        self._manifest = {"run_id": self.run_id, "sandboxes": []}
        self._manifest_lock = threading.Lock()

    # ── mode ─────────────────────────────────────────────────────

    def _decide_mode(self):
        want = str(self.config.get("isolation", "auto")).lower()
        if want == "none":
            return "policy-only"
        available = sys.platform.startswith("linux") and \
            sandbox_linux.probe()
        if want == "namespace":
            if not available:
                raise BrokerError(
                    "isolation 'namespace' configured but unprivileged "
                    "namespaces are unavailable on this host — "
                    "refusing to start rather than silently "
                    "downgrading to policy-only mode")
            return "isolation"
        # auto
        return "isolation" if available else "policy-only"

    # ── manifest / crash recovery ────────────────────────────────

    def _save_manifest(self):
        try:
            self._manifest_dir.mkdir(parents=True, exist_ok=True)
            path = self._manifest_dir / (self.run_id + ".json")
            path.write_text(json.dumps(self._manifest),
                            encoding="utf-8")
        except OSError:
            pass

    def _register_sandbox(self, entry):
        with self._manifest_lock:
            self._manifest["sandboxes"].append(entry)
            self._save_manifest()

    def _recover(self):
        reaped = sandbox_linux.gc_orphans(self._manifest_dir,
                                          self.run_id)
        if reaped:
            self.ledger.append({"event": "orphan_gc", "reaped": reaped})
        self._save_manifest()
        # Requests a previous run left mid-flight never completed:
        # close them out as FAILED so the evidence says so.
        last_state = {}
        try:
            lines = self.ledger.path.read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("event") == "transition" and \
                    row.get("run_id") != self.run_id:
                last_state[row["request_id"]] = row
        from .protocol import TERMINAL_STATES
        for request_id, row in last_state.items():
            if row.get("to") not in TERMINAL_STATES:
                self.ledger.append({
                    "event": "transition",
                    "request_id": request_id,
                    "session_id": row.get("session_id"),
                    "agent_id": row.get("agent_id"),
                    "from": row.get("to"),
                    "to": "FAILED",
                    "reason": "broker restarted; request did not "
                              "complete",
                })

    # ── sessions ─────────────────────────────────────────────────

    def _check_session(self, doc):
        session_id = doc.get("session_id")
        token = doc.get("session_token")
        with self._lock:
            sess = self.sessions.get(session_id)
            if sess is None:
                raise BrokerError("unknown session")
            if not token or not secrets.compare_digest(token,
                                                       sess.token):
                raise BrokerError("invalid session token")
            idle = time.monotonic() - sess.last_seen
            limit = float(self.config.get(
                "session_idle_timeout_seconds", 28800))
            if idle > limit:
                del self.sessions[session_id]
                raise BrokerError("session expired (idle timeout)")
            sess.last_seen = time.monotonic()
            return sess

    # ── ledger helpers ───────────────────────────────────────────

    def _transition(self, machine, to_state, **extra):
        frm = machine.state
        machine.transition(to_state)
        event = {
            "event": "transition",
            "request_id": machine.request_id,
            "session_id": machine.session_id,
            "agent_id": machine.request.get("agent_id"),
            "from": frm,
            "to": to_state,
            "verdict": machine.verdict,
            "engine_decision": getattr(machine, "engine_decision",
                                       None),
            "rule_id": machine.rule_id,
        }
        if machine.effective_permissions is not None:
            event["effective_permissions"] = \
                machine.effective_permissions
        event.update(extra)
        rec = self.ledger.append(event)
        return rec["seq"]

    # ── effective permissions ────────────────────────────────────

    def _effective_permissions(self, normalized):
        req = normalized["requested_permissions"]
        profile = requested_profile(req["filesystem"])
        max_profile = str(self.config.get("filesystem_max",
                                          "workspace-write"))
        if _FS_RANK[profile] > _FS_RANK.get(max_profile, 1):
            profile = max_profile
        extended_dirs = []
        if profile == "extended":
            extended_dirs = list(self.config.get("extended_dirs",
                                                 []))
            if not extended_dirs:
                profile = "workspace-write"
        network = req["network"]
        if network == "host" and not self.config.get(
                "allow_network_host", False):
            network = "none"  # not granted; recorded, never silent
        return {
            "filesystem": profile,
            "network": network,
            "process": "restricted",
            "extended_dirs": extended_dirs,
        }

    # ── request execution ────────────────────────────────────────

    def _run_policy_only(self, normalized, sandbox_id):
        argv = normalized["argv"]
        cwd = normalized["working_directory"]
        timeout = float(normalized["timeout_seconds"])
        cap = int(self.config.get("output_cap_bytes", 262144))
        proc = subprocess.Popen(
            argv, cwd=cwd, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        self._register_sandbox({"sandbox_id": sandbox_id,
                                "launcher_pid": proc.pid,
                                "mode": "policy-only"})
        out_buf = sandbox_linux._TailBuffer(cap)
        err_buf = sandbox_linux._TailBuffer(cap)
        import threading as _t

        def _drain(stream, buf):
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                buf.feed(chunk)

        threads = [_t.Thread(target=_drain, args=(proc.stdout, out_buf),
                             daemon=True),
                   _t.Thread(target=_drain, args=(proc.stderr, err_buf),
                             daemon=True)]
        for t in threads:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait(timeout=10)
        for t in threads:
            t.join(timeout=5)
        return {
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "limit_exceeded": None,
            "mechanism": "none (policy-only mode)",
            "proc_mode": None,
            "init_pid": proc.pid,
            "stdout": bytes(out_buf.data),
            "stderr": bytes(err_buf.data),
            "truncated": out_buf.truncated or err_buf.truncated,
            "error": None,
            "exec_root": None,
        }

    def _execute_authorized(self, machine, normalized):
        self._transition(machine, "PREPARING_SANDBOX")
        sandbox_id = uuid.uuid4().hex[:12]
        eff = machine.effective_permissions
        cwd = normalized["working_directory"]
        if not Path(cwd).is_dir():
            machine.error = "working directory does not exist: %s" % cwd
            self._transition(machine, "FAILED", reason=machine.error)
            return
        self._transition(machine, "EXECUTING")
        try:
            if self.mode == "isolation":
                spec = {
                    "sandbox_id": sandbox_id,
                    "argv": normalized["argv"],
                    "cwd": cwd,
                    "workspace": cwd,
                    "profile": eff["filesystem"],
                    "extended_dirs": eff["extended_dirs"],
                    "network": eff["network"],
                    "home": str(Path.home()),
                    "limits": dict(self.config.get("limits", {})),
                    "timeout_seconds": normalized["timeout_seconds"],
                }

                def _on_spawn(sid, launcher_pid, init_pid):
                    self._register_sandbox({
                        "sandbox_id": sid,
                        "launcher_pid": launcher_pid,
                        "init_pid": init_pid,
                        "mode": "isolation",
                    })

                outcome = sandbox_linux.run_sandboxed(
                    spec, int(self.config.get("output_cap_bytes",
                                              262144)),
                    on_spawn=_on_spawn)
            else:
                outcome = self._run_policy_only(normalized, sandbox_id)
        except Exception as exc:  # launcher failure = fail closed
            machine.error = "execution failed: %s" % exc
            self._transition(machine, "FAILED", reason=machine.error)
            return
        try:
            redact = authz.load_hook().redact
        except Exception:
            redact = lambda s: s  # noqa: E731
        result = {
            "exit_code": outcome["exit_code"],
            "stdout_tail": redact(
                outcome["stdout"].decode("utf-8", errors="replace")),
            "stderr_tail": redact(
                outcome["stderr"].decode("utf-8", errors="replace")),
            "truncated": outcome["truncated"],
            "timed_out": outcome["timed_out"],
            "limit_exceeded": outcome["limit_exceeded"],
            "limits_mechanism": outcome["mechanism"],
            "proc_mode": outcome.get("proc_mode"),
            "sandbox_id": sandbox_id,
            "mode": self.mode,
            "error": outcome.get("error"),
            "exec_root": outcome.get("exec_root"),
        }
        machine.result = result
        environment = {"sandbox_id": sandbox_id,
                       "mechanism": outcome["mechanism"],
                       "proc_mode": outcome.get("proc_mode"),
                       "mode": self.mode}
        if outcome.get("exec_root"):
            environment["exec_root"] = outcome["exec_root"]
        if outcome.get("error"):
            # Sandbox setup or exec failed: the execution never
            # ran. Fail closed with the concrete reason recorded
            # — never a bare exit code in a COMPLETED state.
            machine.error = outcome["error"]
            self._transition(machine, "FAILED",
                             reason=machine.error,
                             environment=environment,
                             result={"exit_code": outcome["exit_code"],
                                     "timed_out": outcome["timed_out"],
                                     "limit_exceeded":
                                         outcome["limit_exceeded"],
                                     "error": outcome["error"]})
            return
        self._transition(machine, "VERIFYING")
        final = "TERMINATED" if outcome["timed_out"] else "COMPLETED"
        self._transition(machine, final,
                         environment=environment,
                         result={"exit_code": outcome["exit_code"],
                                 "timed_out": outcome["timed_out"],
                                 "limit_exceeded":
                                     outcome["limit_exceeded"]})

    def _handle_execute(self, doc):
        sess = self._check_session(doc)
        raw_request = doc.get("request")
        if not isinstance(raw_request, dict):
            raise BrokerError("execute requires a request object")
        normalized = validate_request(raw_request)
        if normalized["session_id"] != sess.session_id:
            raise BrokerError("request session_id does not match the "
                              "authenticated session")
        if normalized["agent_id"] != sess.agent_id:
            raise BrokerError("request agent_id does not match the "
                              "authenticated session")
        req_hash = request_hash(normalized)
        with self._lock:
            prior = self.requests.get(normalized["request_id"])
            if prior is not None:
                if prior["req_hash"] != req_hash:
                    raise BrokerError(
                        "request_id %s was already submitted with "
                        "different content — a changed request is a "
                        "new request; refused"
                        % normalized["request_id"])
                raise BrokerError(
                    "duplicate request_id %s in this session — "
                    "replay refused" % normalized["request_id"])
            seq = normalized.get("seq")
            if seq is not None:
                if seq <= sess.last_seq:
                    raise BrokerError(
                        "seq %s is not monotonic for this session — "
                        "replay refused" % seq)
                sess.last_seq = seq
            machine = RequestMachine(normalized)
            entry = {"machine": machine, "req_hash": req_hash,
                     "session_id": sess.session_id,
                     "event": threading.Event()}
            self.requests[normalized["request_id"]] = entry
            sess.request_ids.add(normalized["request_id"])

        self._transition(machine, "VALIDATING")
        verdict = authz.authorize(normalized, agent_label=sess.label)
        machine.verdict = verdict["verdict"]
        machine.engine_decision = verdict.get("engine_decision")
        machine.rule_id = verdict["rule_id"]
        machine.reason = verdict["reason"]
        machine.effective_permissions = self._effective_permissions(
            normalized)

        if verdict["verdict"] == "deny":
            self._transition(machine, "DENIED",
                             judge_outcome=verdict["judge_outcome"])
            return machine.snapshot()
        if verdict["verdict"] == "ask":
            self._transition(machine, "AWAITING_APPROVAL",
                             judge_outcome=verdict["judge_outcome"])
            self.approvals.park(
                machine.request_id, sess.session_id, req_hash,
                {"command": normalized["command"],
                 "working_directory": normalized["working_directory"],
                 "agent_id": sess.agent_id})
            timeout = float(self.config.get(
                "approval_timeout_seconds", 300))
            entry["event"].wait(timeout=timeout)
            decided = self.approvals.decision_for(machine.request_id)
            if decided is None or decided.get("decision") != "approved":
                if machine.state == "AWAITING_APPROVAL":
                    if decided is not None:
                        self._transition(
                            machine, "DENIED",
                            reason="denied by the user")
                    else:
                        machine.error = "approval timed out"
                        self._transition(machine, "TERMINATED",
                                         reason=machine.error)
                return machine.snapshot()
            if decided.get("request_hash") != req_hash:
                machine.error = "approval was bound to a different " \
                                "request hash — refused"
                self._transition(machine, "FAILED",
                                 reason=machine.error)
                return machine.snapshot()
            self._transition(machine, "AUTHORIZED",
                             reason="approved by the user")
        else:
            self._transition(machine, "AUTHORIZED",
                             judge_outcome=verdict["judge_outcome"])
        self._execute_authorized(machine, normalized)
        return machine.snapshot()

    # ── dispatch ─────────────────────────────────────────────────

    def handle(self, doc):
        if not isinstance(doc, dict):
            return {"ok": False, "error": "message must be an object"}
        op = doc.get("op")
        try:
            if op == "status":
                return {"ok": True, "running": True,
                        "version": _package_version(),
                        "run_id": self.run_id, "mode": self.mode,
                        "sessions": len(self.sessions),
                        "pending_approvals":
                            len(self.approvals.pending())}
            if op == "session_open":
                agent_id = doc.get("agent_id")
                if not isinstance(agent_id, str) or not agent_id:
                    raise BrokerError("agent_id required")
                session_id = uuid.uuid4().hex
                token = secrets.token_urlsafe(32)
                with self._lock:
                    self.sessions[session_id] = _Session(
                        session_id, token, agent_id,
                        str(doc.get("client_label", ""))[:80])
                self.ledger.append({"event": "session_open",
                                    "session_id": session_id,
                                    "agent_id": agent_id})
                return {"ok": True, "session_id": session_id,
                        "session_token": token, "mode": self.mode}
            if op == "session_close":
                sess = self._check_session(doc)
                with self._lock:
                    self.sessions.pop(sess.session_id, None)
                self.ledger.append({"event": "session_close",
                                    "session_id": sess.session_id,
                                    "agent_id": sess.agent_id})
                return {"ok": True}
            if op == "execute":
                snap = self._handle_execute(doc)
                snap["ok"] = True
                snap["evidence_seq"] = self.ledger.seq
                return snap
            if op == "poll":
                sess = self._check_session(doc)
                with self._lock:
                    entry = self.requests.get(doc.get("request_id"))
                if entry is None or \
                        entry["session_id"] != sess.session_id:
                    raise BrokerError("unknown request_id for this "
                                      "session")
                snap = entry["machine"].snapshot()
                snap["ok"] = True
                return snap
            if op in ("approve", "deny"):
                rec = self.approvals.decide(
                    doc.get("request_id"), op == "approve",
                    doc.get("approval_token", ""), self.approval_token)
                self.ledger.append({
                    "event": "approval_decision",
                    "request_id": rec["request_id"],
                    "session_id": rec["session_id"],
                    "decision": rec["decision"],
                })
                with self._lock:
                    entry = self.requests.get(rec["request_id"])
                if entry is not None:
                    entry["event"].set()
                return {"ok": True, "request_id": rec["request_id"],
                        "decision": rec["decision"]}
            if op == "pending":
                token = doc.get("approval_token", "")
                if not token or not secrets.compare_digest(
                        token, self.approval_token):
                    raise BrokerError("approval capability required")
                return {"ok": True,
                        "pending": self.approvals.pending()}
            if op == "shutdown":
                token = doc.get("approval_token", "")
                if not token or not secrets.compare_digest(
                        token, self.approval_token):
                    raise BrokerError("approval capability required")
                threading.Thread(target=self._shutdown_soon,
                                 daemon=True).start()
                return {"ok": True, "shutting_down": True}
            return {"ok": False, "error": "unknown op: %r" % (op,)}
        except (BrokerError, ValidationError, ProtocolError,
                ApprovalError) as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # fail closed, never hang the client
            return {"ok": False,
                    "error": "broker internal error: %s" % exc}

    def _shutdown_soon(self):
        time.sleep(0.1)
        if self._server is not None:
            self._server.shutdown()

    # ── serving ──────────────────────────────────────────────────

    def serve(self):
        self._recover()
        self.sock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.sock_path.parent, 0o700)
        except OSError:
            pass
        try:
            self.sock_path.unlink()
        except OSError:
            pass
        broker = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                # Peer credentials: only the user's own processes
                # may talk to the broker at all.
                try:
                    cred = self.request.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    peer_uid = int.from_bytes(cred[4:8], "little")
                    if peer_uid != os.getuid():
                        return
                except (OSError, IndexError):
                    if sys.platform.startswith("linux"):
                        return
                for raw in self.rfile:
                    if len(raw) > MAX_LINE_BYTES:
                        self.wfile.write(b'{"ok": false, "error": '
                                         b'"message too large"}\n')
                        continue
                    try:
                        doc = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        self.wfile.write(
                            b'{"ok": false, "error": "invalid JSON"}\n')
                        continue
                    resp = broker.handle(doc)
                    self.wfile.write(
                        (json.dumps(resp) + "\n").encode("utf-8"))
                    self.wfile.flush()

        class Server(socketserver.ThreadingMixIn,
                     socketserver.UnixStreamServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server(str(self.sock_path), Handler)
        try:
            os.chmod(self.sock_path, 0o600)
        except OSError:
            pass
        self.ledger.append({"event": "broker_start",
                            "mode": self.mode,
                            "version": _package_version(),
                            "socket": str(self.sock_path)})
        # The legacy hook's --doctor reports broker status but is
        # forbidden network imports by design, so it cannot ping
        # this socket: publish a status file for it to read
        # instead (removed on clean shutdown; a stale one is
        # detected by pid liveness).
        status_file = seatbelt_home() / "broker-status.json"
        try:
            status_file.write_text(json.dumps({
                "pid": os.getpid(), "mode": self.mode,
                "version": _package_version(), "run_id": self.run_id,
                "socket": str(self.sock_path),
                "started_at": time.time()}), encoding="utf-8")
        except OSError:
            status_file = None
        try:
            self._server.serve_forever()
        finally:
            self.ledger.append({"event": "broker_stop",
                                "mode": self.mode})
            if status_file is not None:
                try:
                    status_file.unlink()
                except OSError:
                    pass
            try:
                self.sock_path.unlink()
            except OSError:
                pass


def _package_version():
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--status"]:
        from .client import BrokerClient, BrokerUnavailable
        try:
            client = BrokerClient()
            print(json.dumps(client.status(), indent=1))
            return 0
        except BrokerUnavailable as exc:
            print("broker not reachable: %s" % exc)
            return 1
    if argv[:1] == ["--stop"]:
        from .approvals import read_approval_token
        from .client import BrokerClient, BrokerUnavailable
        try:
            client = BrokerClient()
            print(json.dumps(client.shutdown(read_approval_token())))
            return 0
        except BrokerUnavailable as exc:
            print("broker not reachable: %s" % exc)
            return 1
    if argv[:1] == ["--sandbox-gc"]:
        broker = Broker()
        reaped = sandbox_linux.gc_orphans(broker._manifest_dir,
                                          broker.run_id)
        print("sandbox-gc: reaped %d orphan(s)" % reaped)
        return 0
    if argv[:1] == ["--verify-ledger"]:
        from .ledger import run_verify_ledger
        return run_verify_ledger(argv[1] if len(argv) > 1 else None)
    if argv[:1] == ["--daemonize"]:
        pid = os.fork()
        if pid:
            print("seatbelt-broker daemonized (pid %d)" % pid)
            return 0
        os.setsid()
        # The log lives under ~/.seatbelt; fresh homes do not have
        # the directory yet (the Ledger would create it, but it is
        # constructed after this redirect).
        seatbelt_home().mkdir(parents=True, exist_ok=True)
        log = open(seatbelt_home() / "broker.log", "ab", buffering=0)
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
        os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
    broker = Broker()
    print("seatbelt-broker %s starting — mode: %s "
          "(socket %s)" % (_package_version(), broker.mode,
                           broker.sock_path), flush=True)
    if broker.mode == "policy-only":
        print("WARNING: policy-only mode — executions are authorized "
              "and audited but NOT sandboxed.", flush=True)
    try:
        broker.serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
