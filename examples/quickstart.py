"""Agent Seatbelt quickstart — a fake agent loop, gated.

Runs offline, no browser: a three-action "page" and a loop that
follows the caller contract (gate first, execute only on an
executable verdict). Watch the read-only click sail through, the
fill ask, and — with a deny rule added — the purchase click refused
by name.

    python examples/quickstart.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_seatbelt import Governor

PAGE = {
    "url": "https://shop.example.test/checkout",
    "fingerprint": "demo-1",
    "actions": [
        {"id": "a1", "kind": "click", "label": "Details", "role": "tab", "node": 1},
        {"id": "a2", "kind": "fill", "label": "Card number", "role": "textbox", "node": 2},
        {"id": "a3", "kind": "click", "label": "Pay now", "role": "button", "node": 3},
    ],
}


def run(governor, label):
    print(f"\n— {label}")
    for act in PAGE["actions"]:
        record = governor.gate(act, PAGE, operation=act["kind"].upper())
        if Governor.may_execute(record):
            outcome = "EXECUTED"
        elif record["verdict"] in {"ask", "hand_off"}:
            outcome = "HELD for a human"
        else:
            outcome = "REFUSED"
        print(f"  {act['label']:<12} {record['verdict']:<12} ({record['rule_id']}) → {outcome}")


run(Governor(), "Default policy: reads flow, consequential actions ask")

run(
    Governor({"rules": [
        {"id": "never-pay", "effect": "deny", "when": "payload.label == 'Pay now'"},
        {"id": "reads", "effect": "allow", "when": "classification == 'read_only'"},
        {"id": "rest-ask", "effect": "ask", "when": "classification == 'consequential'"},
    ]}),
    "With a deny rule: the purchase click is refused, by name",
)
