"""The seatbelt harness: classify → evaluate → record → (maybe) act.

Agent Seatbelt brings the Ghost Kernel's gateway discipline to any
browser-agent loop:

  1. classify — the action is classified read-only or consequential
     (classify.py); anything the classifier cannot prove read-only
     is consequential.
  2. evaluate — the compiled policy decides: allow / pre_approved /
     ask / hand_off / deny, strictest tier first, fail-closed, with
     the deciding rule named (policy.py).
  3. record — the gateway record (intent + verdict + deciding rule,
     in the Ghost Kernel GatewayRecord's field shape) is written to
     the record sink BEFORE any effect. If the record cannot be
     written, gate() raises and the action must not run: an action
     that is not recorded does not happen.
  4. act — the CALLER executes only when the record's verdict is
     allow or pre_approved (see may_execute) and the record is not a
     dry run. ask and hand_off never execute: the record IS the
     pending action, surfaced for a human decision made outside the
     loop. deny never executes and names its rule.

THE SEAM. This harness was extracted from the governor built into the
Jev browser agent. In Jev, configuration came from JEV_GOVERNOR_*
environment variables and records were written into the agent loop's
state dict. Here, configuration is explicit (constructor arguments)
and records go to a sink you choose — a list in memory, a JSONL file,
or any callable/object with a write(record) method. Everything else —
classification, policy semantics, record field names — is unchanged,
so a policy written for Jev or the Ghost Kernel decides identically
here.

The harness deliberately ships NO approval UI. ask / hand_off halt
the action and hand you the record; collecting the human's answer is
your loop's business, exactly as it was in Jev.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

from .classify import classify_action
from .policy import compile_policy, evaluate_policy

#: Verdicts under which the caller may execute the action.
EXECUTABLE_VERDICTS = {"allow", "pre_approved"}


def default_policy():
    """The shipped policy, the analogue of the Ghost Kernel's default.

    Read-only actions are allowed; consequential actions ask a human.
    A deployment replaces this wholesale with its own policy document.
    """
    return {
        "rules": [
            {
                "id": "seatbelt-read-only",
                "effect": "allow",
                "when": "classification == 'read_only'",
                "note": "Navigation, reads, scrolls, and waits flow without asking.",
            },
            {
                "id": "seatbelt-consequential-ask",
                "effect": "ask",
                "when": "classification == 'consequential'",
                "note": "Form input and any click that may submit, send, buy, or commit asks a human first.",
            },
        ]
    }


def load_policy(source):
    """Compile a policy from a document, a JSON file path, or None.

    None returns the compiled default policy. A document is a dict in
    the Kernel's shape: {"rules": [{id, effect, when, ...}]}. A path
    (str or Path) is read as JSON in that shape. A missing or
    malformed file raises before any action can execute — a seatbelt
    that cannot load its rules governs nothing by accident.
    """
    if source is None:
        return compile_policy(default_policy())
    if isinstance(source, dict):
        return compile_policy(source)
    path = Path(source)
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise ValueError(f"Seatbelt policy {str(path)!r} could not be loaded ({error}); no action executed.") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ValueError(f"Seatbelt policy {str(path)!r} is not a policy document; no action executed.")
    return compile_policy(doc)


class MemorySink:
    """The default record sink: records accumulate in `.records`."""

    def __init__(self):
        self.records = []

    def write(self, record):
        self.records.append(record)


class JsonlSink:
    """Append each record as one JSON line to a file, flushed per record.

    A failed write raises RuntimeError out of gate() — record-first
    means the action then does not run.
    """

    def __init__(self, path):
        self.path = Path(path)

    def write(self, record):
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
                handle.flush()
        except OSError as error:
            raise RuntimeError(f"Seatbelt record could not be written ({error}); no action executed.") from None


class CallableSink:
    """Adapt any one-argument callable into a record sink."""

    def __init__(self, fn):
        self.fn = fn

    def write(self, record):
        self.fn(record)


def _is_compiled(policy):
    """A compiled policy (from compile_policy) carries parsed rules —
    every rule dict has an "ast" entry. A raw document never does."""
    return (
        isinstance(policy, dict)
        and isinstance(policy.get("rules"), list)
        and all(isinstance(rule, dict) and "ast" in rule for rule in policy["rules"])
    )


def _as_sink(sink):
    if sink is None:
        return MemorySink()
    if hasattr(sink, "write"):
        return sink
    if callable(sink):
        return CallableSink(sink)
    raise TypeError("sink must be None, a callable, or an object with a write(record) method")


class Governor:
    """Gate browser actions through a policy, recording before effects.

    policy:   None (default policy), a policy document dict, a path
              to a JSON policy document, or a compiled policy from
              compile_policy(). Loaded once, at construction, failing
              closed: a Governor that cannot load its rules is never
              created.
    sink:     where gateway records go (see _as_sink). Default:
              a MemorySink, reachable as governor.records.
    dry_run:  when True, verdicts are evaluated and recorded with
              dry_run set on the record, and may_execute() is False
              for every record — a policy smoke-test mode.
    actor / kind_prefix / initiator / project_id: the identity fields
              stamped into every context and record. They come from
              the integrator's trusted code, never from the agent's
              own proposal — policy may branch on them (e.g. hold
              initiator == 'routine' runs to a stricter standard).
    """

    def __init__(
        self,
        policy=None,
        *,
        sink=None,
        dry_run=False,
        actor="browser-agent",
        kind_prefix="browser",
        initiator="person",
        project_id="",
    ):
        self._policy = policy if _is_compiled(policy) else load_policy(policy)
        self.sink = _as_sink(sink)
        self.dry_run = bool(dry_run)
        self.actor = actor
        self.kind_prefix = kind_prefix
        self.initiator = initiator
        self.project_id = project_id

    @property
    def records(self):
        """Records written so far, when the sink keeps them (MemorySink)."""
        return getattr(self.sink, "records", None)

    @staticmethod
    def may_execute(record):
        """True only for allow / pre_approved records that are not dry runs."""
        return record["verdict"] in EXECUTABLE_VERDICTS and not record["dry_run"]

    def gate(self, action, page, *, operation=None):
        """Evaluate one decided action and write its gateway record.

        action: the action dict the agent is about to perform
            ({"id", "kind", "label", "role", "value", "node"} — see
            classify.py).
        page:   the observation the action was decided from, as a
            dict with "url", "actions" (the full observed action
            list), and optionally "fingerprint" (any observation id;
            carried on the record as snapshot_id).
        operation: the agent's name for the operation, if it has one
            (Jev passes its decision's operation); recorded and
            visible to policy as a native root. Optional.

        Returns the gateway record. The record is written to the sink
        BEFORE this returns; if the sink write fails, gate() raises
        and the caller must not execute the action.
        """
        actions = page.get("actions", [])
        info = classify_action(action, actions)
        kind = f"{self.kind_prefix}.{action.get('kind')}"
        url = page.get("url", "")
        payload = {
            "label": action.get("label"),
            "role": action.get("role"),
            "value": action.get("value"),
            "url": url,
            "host": urlparse(url).hostname or "",
            "target": action.get("id"),
            "operation": operation,
        }
        context = {
            "kind": kind,
            "permission_class": info["permission_class"],
            "actor": self.actor,
            "project_id": self.project_id,
            # The harness carries no approvals: an ask verdict is
            # exactly how an action surfaces for the approval the
            # harness cannot carry. Same honest stance as in Jev.
            "approved": False,
            "initiator": self.initiator,
            "payload": payload,
            # Browser-agent native roots, resolvable alongside the
            # Kernel's fields.
            "classification": info["classification"],
            "operation": operation,
            "role": action.get("role"),
            "label": action.get("label"),
            "host": payload["host"],
        }
        verdict = evaluate_policy(self._policy, context)
        record = {
            "action_id": action.get("id"),
            "kind": kind,
            "permission_class": info["permission_class"],
            "actor": self.actor,
            "initiator": self.initiator,
            "project_id": self.project_id,
            "verdict": verdict["verdict"],
            "rule_id": verdict["rule_id"],
            "reason": verdict["reason"],
            "handoff_to": verdict["handoff_to"],
            "target_ref": None,
            "snapshot_id": page.get("fingerprint"),
            "target": {"element": action.get("id"), "label": action.get("label"), "role": action.get("role")},
            "action_payload": payload,
            "dry_run": self.dry_run,
            "classification": info["classification"],
            "classification_basis": info["basis"],
        }
        self.sink.write(record)
        return record
