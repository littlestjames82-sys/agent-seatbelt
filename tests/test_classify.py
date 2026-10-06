"""Classification contracts, carried over from the Jev governor suite.

Only the listed shapes are read-only; everything else — including
unrecognised kinds — is consequential.
"""

import pytest

from agent_seatbelt import classify
from agent_seatbelt.classify import classify_action


def page_actions():
    return [
        {"id": "e1", "kind": "fill", "label": "Search", "role": "textbox", "value": "", "node": 10},
        {"id": "e2", "kind": "click", "label": "Open Search", "role": "textbox", "value": "", "node": 10},
        {"id": "e3", "kind": "click", "label": "Go", "role": "button", "value": "", "node": 20},
        {"id": "wait", "kind": "wait", "label": "Wait"},
    ]


@pytest.mark.parametrize(
    "action,expected",
    [
        ({"kind": "scroll", "label": "Scroll down"}, classify.READ_ONLY),
        ({"kind": "wait", "label": "Wait"}, classify.READ_ONLY),
        ({"kind": "click", "role": "link", "label": "Next page"}, classify.READ_ONLY),
        ({"kind": "click", "role": "tab", "label": "Details"}, classify.READ_ONLY),
        ({"kind": "click", "role": "button", "label": "Go"}, classify.CONSEQUENTIAL),
        ({"kind": "click", "role": "checkbox", "label": "Free cancellation"}, classify.CONSEQUENTIAL),
        ({"kind": "click", "role": "switch", "label": "Nonstop only"}, classify.CONSEQUENTIAL),
        ({"kind": "fill", "role": "textbox", "label": "Search"}, classify.CONSEQUENTIAL),
        ({"kind": "select", "role": "combobox", "label": "Sort → Price"}, classify.CONSEQUENTIAL),
        ({"kind": "teleport", "label": "?"}, classify.CONSEQUENTIAL),
    ],
)
def test_classifier_table(action, expected):
    assert classify_action(action, page_actions())["classification"] == expected


def test_classifier_recognises_the_focus_only_companion_click():
    actions = page_actions()
    companion = next(a for a in actions if a["id"] == "e2")
    info = classify_action(companion, actions)
    assert info["classification"] == classify.READ_ONLY
    assert info["permission_class"] == "READ"
    # The same click shape on a node with no fill companion is a button.
    orphan = {"kind": "click", "role": "textbox", "label": "Open Search", "node": 99}
    assert classify_action(orphan, actions)["classification"] == classify.CONSEQUENTIAL


def test_classifier_permission_classes():
    actions = page_actions()
    by_id = {a["id"]: a for a in actions}
    assert classify_action(by_id["e1"], actions)["permission_class"] == "WRITE_LOCAL"
    assert classify_action(by_id["e3"], actions)["permission_class"] == "NETWORK_WRITE"
