"""The `seatbelt` command — broker-mode CLI surface (0.4.0).

Subcommands:
  seatbelt exec [--cwd DIR] [--fs TOKEN]... [--network none|host]
                [--timeout N] [--agent ID] -- ARGV...
  seatbelt exec --command "STRING" [same options]
  seatbelt approve REQUEST_ID
  seatbelt deny REQUEST_ID
  seatbelt pending
  seatbelt broker-status
  seatbelt verify-ledger [PATH]

`exec` routes the command through the Ghost Execution Broker and
fails closed (exit 3) when the broker is unreachable — it never
falls back to running the command directly. Exit codes: the
command's own exit code on COMPLETED; 2 on DENIED; 3 on broker
unavailable / FAILED / TERMINATED.
"""

from __future__ import annotations

import sys

from .broker.approvals import read_approval_token
from .broker.client import BrokerClient, BrokerError, BrokerUnavailable


def _cmd_exec(argv):
    cwd = None
    fs = []
    network = "none"
    timeout = 120
    agent = "seatbelt-exec"
    command = None
    rest = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--" :
            rest = argv[i + 1:]
            break
        if tok in ("--cwd", "--network", "--timeout", "--agent",
                   "--command", "--fs") and i + 1 < len(argv):
            value = argv[i + 1]
            if tok == "--cwd":
                cwd = value
            elif tok == "--network":
                network = value
            elif tok == "--timeout":
                timeout = int(value)
            elif tok == "--agent":
                agent = value
            elif tok == "--command":
                command = value
            elif tok == "--fs":
                fs.append(value)
            i += 2
        else:
            rest = argv[i:]
            break
    if command is None and not rest:
        sys.stderr.write(
            "usage: seatbelt exec [--cwd DIR] [--fs TOKEN]... "
            "[--network none|host] [--timeout N] -- ARGV...\n"
            "       seatbelt exec --command \"STRING\" [options]\n")
        return 2
    client = BrokerClient()
    try:
        client.open(agent, client_label="seatbelt exec")
        snap = client.execute(
            argv=rest if command is None else None,
            command=command, cwd=cwd,
            filesystem=fs or ["workspace-write"],
            network=network, timeout_seconds=timeout)
    except BrokerUnavailable as exc:
        sys.stderr.write("seatbelt: %s\n" % exc)
        return 3
    except BrokerError as exc:
        sys.stderr.write("seatbelt: broker refused: %s\n" % exc)
        return 3
    finally:
        try:
            client.close_session()
        except Exception:
            pass
    state = snap.get("state")
    if state == "DENIED":
        sys.stderr.write("seatbelt: DENIED (%s): %s\n"
                         % (snap.get("rule_id"), snap.get("reason")))
        return 2
    result = snap.get("result") or {}
    if result.get("stdout_tail"):
        sys.stdout.write(result["stdout_tail"])
    if result.get("stderr_tail"):
        sys.stderr.write(result["stderr_tail"])
    if state == "COMPLETED":
        return int(result.get("exit_code") or 0)
    sys.stderr.write("seatbelt: execution ended in state %s (%s)\n"
                     % (state, snap.get("error") or
                        snap.get("reason") or ""))
    return 3


def _cmd_decide(argv, approve):
    if len(argv) != 1:
        sys.stderr.write("usage: seatbelt %s REQUEST_ID\n"
                         % ("approve" if approve else "deny"))
        return 2
    token = read_approval_token()
    if not token:
        sys.stderr.write(
            "seatbelt: no approval capability token found — the "
            "broker creates one at %s when it first starts.\n"
            % "~/.seatbelt/broker.approval-token")
        return 3
    client = BrokerClient()
    try:
        resp = client.approve(argv[0], token) if approve else \
            client.deny(argv[0], token)
    except (BrokerUnavailable, BrokerError) as exc:
        sys.stderr.write("seatbelt: %s\n" % exc)
        return 3
    print("%s request %s" % (resp["decision"], resp["request_id"]))
    return 0


def _cmd_pending(argv):
    token = read_approval_token()
    if not token:
        sys.stderr.write("seatbelt: no approval capability token "
                         "found.\n")
        return 3
    client = BrokerClient()
    try:
        resp = client.pending(token)
    except (BrokerUnavailable, BrokerError) as exc:
        sys.stderr.write("seatbelt: %s\n" % exc)
        return 3
    pending = resp.get("pending", [])
    if not pending:
        print("no pending approvals")
        return 0
    for rec in pending:
        summary = rec.get("summary", {})
        print("%s  %s  (cwd %s, agent %s)"
              % (rec["request_id"], summary.get("command", "?"),
                 summary.get("working_directory", "?"),
                 summary.get("agent_id", "?")))
    return 0


def _cmd_status(argv):
    client = BrokerClient()
    try:
        resp = client.status()
    except BrokerUnavailable as exc:
        sys.stderr.write("seatbelt: %s\n" % exc)
        return 3
    print("broker running — version %s, mode %s, run %s, "
          "%d session(s), %d pending approval(s)"
          % (resp.get("version"), resp.get("mode"),
             resp.get("run_id"), resp.get("sessions", 0),
             resp.get("pending_approvals", 0)))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "exec":
        return _cmd_exec(rest)
    if cmd == "approve":
        return _cmd_decide(rest, True)
    if cmd == "deny":
        return _cmd_decide(rest, False)
    if cmd == "pending":
        return _cmd_pending(rest)
    if cmd == "broker-status":
        return _cmd_status(rest)
    if cmd == "verify-ledger":
        from .broker.ledger import run_verify_ledger
        return run_verify_ledger(rest[0] if rest else None)
    sys.stderr.write("seatbelt: unknown subcommand %r\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
