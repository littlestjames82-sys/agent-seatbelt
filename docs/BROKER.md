# Broker mode (0.4.0): the Ghost Execution Broker

Seatbelt has two modes. They are different products sharing one
policy engine, and this document exists so nobody confuses them.

## Legacy mode (the hook)

The original Seatbelt: a hook (or wrapper) that evaluates each
proposed command against the deterministic policy engine —
~200 rules, guards, mode overlays, judge seam — and allows,
denies, or asks. It is **interception, not isolation**: an allowed
command runs with the user's full permissions. Legacy mode makes
no sandboxing claim, and `--doctor` says so.

## Broker mode (this document)

The Ghost Execution Broker is a user-level daemon that executes
commands **on behalf of** agents, under authorization the agent
cannot forge:

- Agents talk to the broker over a Unix socket
  (`$XDG_RUNTIME_DIR/seatbelt/broker.sock`, falling back to
  `~/.seatbelt/broker.sock`). The broker verifies the peer uid
  (SO_PEERCRED) and a per-session token on every call.
- Every execution request follows an 11-state authorization
  machine (RECEIVED → VALIDATING → POLICY_EVALUATED →
  AWAITING_APPROVAL → AUTHORIZED → PREPARING_SANDBOX → EXECUTING
  → VERIFYING → COMPLETED, with DENIED / FAILED / TERMINATED).
  Illegal transitions are impossible by construction; replayed or
  mutated requests are refused.
- `ask` verdicts park the request in AWAITING_APPROVAL. Only the
  **user** can approve, with an approval capability token that
  lives at `~/.seatbelt/broker.approval-token` and is never given
  to agent sessions. Approvals are single-use and bound to the
  exact request hash — change anything about the request and it
  is a new request needing a new decision.
- Every transition is appended to a hash-chained evidence ledger
  at `~/.seatbelt/ledger.jsonl` — in the user's home, **never in
  the project tree** — verifiable with `seatbelt verify-ledger`,
  including detection of deleted history.
- On Linux, execution runs inside unprivileged namespaces (user
  + mount + pid, plus a network namespace for profile `none`):
  the process sees the workspace (per its filesystem profile),
  system binaries, and an empty home shadow — never the real
  home, SSH keys, cloud credentials, browser profiles, or
  `~/.seatbelt` itself. Resource limits (CPU, address space, file
  size, open files, process count) apply via rlimits, plus a
  broker-side wall clock that kills the whole namespace.

## The boundary, stated plainly

**The broker governs only execution that is routed through it**
— `seatbelt exec`, the broker client API, or a wrapper an
integration chooses to use. A process that never calls the broker
is not governed by it. Broker mode is an authorization and
isolation layer for cooperating integrations, not a claim that
arbitrary code on the machine is contained.

## Modes of execution

| Mode | When | Claim |
|---|---|---|
| isolation | Linux + namespaces available (default when usable) | Authorization **and** runtime isolation as described above |
| policy-only | namespaces unavailable, or `isolation: "none"` configured | Authorization only — the command runs with the user's permissions. The broker labels this mode in its status, in every result, in the ledger, and in `--doctor`. It never pretends to be isolation. |

If `isolation: "namespace"` is configured but namespaces are
unavailable, the broker **refuses to start** rather than silently
downgrading.

## Network profiles (0.4.0)

`none` (its own network namespace: no interfaces, no DNS, no
routes) or `host` (the host network, only when the user's broker
config grants it via `allow_network_host`). There is **no
hostname allowlist proxy in 0.4.0** — that is 0.5.0 scope, and
nothing in 0.4.0 claims per-host filtering.

## Filesystem profiles

Requested per execution, capped by the user's broker config
(`~/.seatbelt/broker.json`, `filesystem_max`):

- `workspace-read` — workspace mounted read-only.
- `workspace-write` — workspace read-write; everything else
  masked or absent.
- `temporary` — workspace read-only plus a private tmpfs scratch.
- `extended` — workspace read-write plus the user-configured
  `extended_dirs`, each mounted read-only.

The always-denied list (`~/.ssh`, `~/.aws`, `~/.azure`,
`~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gcloud`,
`~/.seatbelt`, browser profiles, keyrings, `.netrc`) is masked
even inside otherwise-visible trees.

## Limits and honest mechanisms

cgroup v2 memory/CPU/process limits are used **only** when a
delegated writable cgroup subtree exists; otherwise the floor is
rlimits plus a broker-side process-count watchdog. Every result
and ledger event names the mechanism that actually applied
(`limits_mechanism: "cgroup-v2"` or `"rlimit+watchdog"`), and
whether a fresh `/proc` was mounted (`proc_mode`).

## Crash safety

If the broker dies mid-execution, clients fail closed (they never
fall back to direct execution). On its next start the broker
reaps orphaned sandboxes recorded in `~/.seatbelt/broker-runs/`
and appends a FAILED transition for every request the crash left
non-terminal, so the ledger never shows a request "running"
forever.

## Quick start

```sh
seatbelt-broker --daemonize        # start (mode auto-detected)
seatbelt broker-status             # mode, sessions, pending asks
seatbelt exec -- git status        # routed execution
seatbelt pending                   # what is waiting on you
seatbelt approve <request-id>      # uses your capability token
seatbelt verify-ledger             # check the evidence chain
```

The approval token file is created on first broker start with
mode 0600. Anyone who can read it can approve requests — protect
it like a credential. Agent processes must never be given it.
