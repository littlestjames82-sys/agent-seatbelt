"""Classification of browser actions: read-only vs consequential.

Extracted unchanged from the governor built for the Jev browser agent.
The classifier is explicit and conservative: only the shapes listed
here are read-only; every other shape — including any kind or role it
does not recognise — is consequential. Classification never grants
anything by itself; it feeds the policy engine (policy.py), whose
verdict decides.

An "action" here is a plain dict describing one thing an agent is
about to do, in the vocabulary browser agents like browser-use and Jev
already produce:

    {"id": ..., "kind": "click" | "fill" | "select" | "scroll" |
     "wait" | ..., "label": ..., "role": ..., "value": ...,
     "node": ...}

`classify_action` also receives the page's full action list, because
one read-only shape — the focus-only companion click — is only
recognisable in context (see below).
"""

READ_ONLY = "read_only"
CONSEQUENTIAL = "consequential"

# Clicks on these roles only switch what the user is looking at.
_VIEW_ROLES = {"tab", "menuitem", "menuitemradio", "option", "gridcell"}
# Clicks on these roles change a form control's state, which a later
# submit would consume — form input, not navigation.
_TOGGLE_ROLES = {"checkbox", "radio", "switch"}


def classify_action(action, actions):
    """Classify one observed action as read-only or consequential.

    Explicit and conservative: only the shapes listed here are
    read-only; every other shape — including any kind or role this
    function does not recognise — is consequential. Returns
    {"classification", "permission_class", "basis"} where
    permission_class uses the Ghost Kernel's class names: READ for
    read-only, WRITE_LOCAL for page-local form state (nothing has
    left the page), NETWORK_WRITE for a click that may submit data.
    """
    kind = action.get("kind")
    role = action.get("role")
    if kind in {"scroll", "wait"}:
        return {
            "classification": READ_ONLY,
            "permission_class": "READ",
            "basis": f"{kind} only moves the viewport or waits; it mutates nothing",
        }
    if kind in {"fill", "select"}:
        return {
            "classification": CONSEQUENTIAL,
            "permission_class": "WRITE_LOCAL",
            "basis": f"{kind} enters a value into a form control",
        }
    if kind == "click":
        # Some snapshot tools emit a companion click ("Open <field>")
        # for every editable element; it only focuses/opens the field.
        # It shares the element's node with the fill action it
        # companions.
        for other in actions:
            if (
                other.get("kind") == "fill"
                and other.get("node") == action.get("node")
                and action.get("label") == f"Open {other.get('label')}"
            ):
                return {
                    "classification": READ_ONLY,
                    "permission_class": "READ",
                    "basis": "focus-only companion click for an editable field",
                }
        if role == "link":
            return {"classification": READ_ONLY, "permission_class": "READ", "basis": "link navigation"}
        if role in _VIEW_ROLES:
            return {
                "classification": READ_ONLY,
                "permission_class": "READ",
                "basis": f"{role} switches the view; it commits nothing",
            }
        if role in _TOGGLE_ROLES:
            return {
                "classification": CONSEQUENTIAL,
                "permission_class": "WRITE_LOCAL",
                "basis": f"{role} changes a form control's state",
            }
        return {
            "classification": CONSEQUENTIAL,
            "permission_class": "NETWORK_WRITE",
            "basis": "a button click may submit, send, or commit; it is not provably navigation",
        }
    return {
        "classification": CONSEQUENTIAL,
        "permission_class": "NETWORK_WRITE",
        "basis": f"unrecognised action kind {kind!r}; unknown shapes are consequential",
    }
