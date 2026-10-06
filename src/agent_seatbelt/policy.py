"""The Ghost Kernel permission policy engine, ported faithfully to Python.

This module is part of Agent Seatbelt (Ghost Developer Studio). The
engine began as a line-for-line semantic port of the Ghost Kernel's
`policy.ts` (shipped in TypeScript as part of GhostGuard), first
ported for the Jev browser agent and extracted here unchanged in
behaviour: the same expression subset, the same tier order
(deny > hand_off > ask > pre_approved > allow), and the same
fail-closed stances, so a policy document written for the Kernel or
GhostGuard is valid here and decides the same way. The one deliberate
superset: the context resolver also exposes browser-agent native
roots (classification, operation, role, label, host) alongside the
Kernel's fields; an unknown root still evaluates to null.

Supported subset (anything outside it is a broken rule):
  literals    'single' / "double" strings, numbers, true, false, null,
              and list literals [a, b, ...]
  fields      kind, permission_class, actor, project_id, approved,
              initiator, payload.<field>, and the browser-agent
              native roots
  operators   ==  !=  <  <=  >  >=  in  &&  ||  !  and parentheses
  functions   startsWith(x, s), endsWith(x, s), contains(x, s),
              matches(x, regex) — matches() compiles the pattern with
              Python's `re` (the Kernel uses JS RegExp; the common
              subset of the two dialects behaves the same)

Semantics (fail-closed throughout, mirroring the Kernel):
  - Tiers are consulted strictest first; the first matching rule of
    the winning effect decides and is named in the decision.
  - No rule matches -> deny. A missing/empty policy permits nothing.
  - A broken rule (unparseable, bad shape) with a deny, ask, or
    hand_off effect denies EVERYTHING, naming itself: since it cannot
    be evaluated, what it might have covered is unknowable. A broken
    allow or pre_approved rule is inert: it never permits, but it
    does not block other rules. The same split applies to
    evaluation-time errors.
  - A hand_off rule without a handoff_to target is broken.
  - Rules may be marked locked: merge_policy_docs carries locked
    rules verbatim and drops overlay rules reusing their id.
"""

import re

EFFECT_TIERS = ("deny", "hand_off", "ask", "pre_approved", "allow")
RESTRICTIVE = {"deny", "ask", "hand_off"}
FUNCTIONS = {"startsWith", "endsWith", "contains", "matches"}


class PolicySyntaxError(Exception):
    pass


class PolicyEvalError(Exception):
    pass


# ── Tokenizer ─────────────────────────────────────────────────────────

_TWO_CHAR_OPS = {"==", "!=", "<=", ">=", "&&", "||"}
_ONE_CHAR_OPS = set("()[],.!<>")
_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"'}


def _tokenize(src):
    toks = []
    i = 0

    def fail(message):
        raise PolicySyntaxError(f"{message} at offset {i} in: {src}")

    while i < len(src):
        c = src[i]
        if c in " \t\n\r":
            i += 1
            continue
        two = src[i : i + 2]
        if two in _TWO_CHAR_OPS:
            toks.append(("op", two))
            i += 2
            continue
        if c in _ONE_CHAR_OPS:
            toks.append(("op", c))
            i += 1
            continue
        if c in "'\"":
            j = i + 1
            out = ""
            while j < len(src) and src[j] != c:
                if src[j] == "\\":
                    nxt = src[j + 1] if j + 1 < len(src) else ""
                    if nxt not in _ESCAPES:
                        fail(f"unsupported escape \\{nxt}")
                    out += _ESCAPES[nxt]
                    j += 2
                else:
                    out += src[j]
                    j += 1
            if j >= len(src):
                fail("unterminated string literal")
            toks.append(("str", out))
            i = j + 1
            continue
        if c.isdigit():
            j = i
            while j < len(src) and (src[j].isdigit() or src[j] == "."):
                j += 1
            try:
                value = float(src[i:j])
            except ValueError:
                fail("malformed number")
            toks.append(("num", int(value) if value.is_integer() and "." not in src[i:j] else value))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < len(src) and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(("ident", src[i:j]))
            i = j
            continue
        fail(f'unexpected character "{c}"')
    return toks


# ── Parser (ASTs are tuples, mirroring the Kernel's Ast union) ────────


class _Parser:
    def __init__(self, toks, src):
        self.toks = toks
        self.src = src
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def fail(self, message):
        raise PolicySyntaxError(f"{message} in: {self.src}")

    def eat_op(self, value):
        tok = self.peek()
        if tok is not None and tok[0] == "op" and tok[1] == value:
            self.pos += 1
            return True
        return False

    def expect_op(self, value):
        if not self.eat_op(value):
            self.fail(f'expected "{value}"')

    def parse(self):
        ast = self.parse_or()
        if self.pos != len(self.toks):
            self.fail("trailing input after complete expression")
        return ast

    def parse_or(self):
        left = self.parse_and()
        while self.eat_op("||"):
            left = ("or", left, self.parse_and())
        return left

    def parse_and(self):
        left = self.parse_cmp()
        while self.eat_op("&&"):
            left = ("and", left, self.parse_cmp())
        return left

    def parse_cmp(self):
        left = self.parse_unary()
        tok = self.peek()
        if tok is not None and tok[0] == "op" and tok[1] in {"==", "!=", "<", "<=", ">", ">="}:
            self.pos += 1
            return ("cmp", tok[1], left, self.parse_unary())
        if tok is not None and tok[0] == "ident" and tok[1] == "in":
            self.pos += 1
            return ("cmp", "in", left, self.parse_unary())
        return left

    def parse_unary(self):
        if self.eat_op("!"):
            return ("not", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok is None:
            self.fail("unexpected end of expression")
        if tok[0] == "op" and tok[1] == "(":
            self.pos += 1
            inner = self.parse_or()
            self.expect_op(")")
            return inner
        if tok[0] == "op" and tok[1] == "[":
            self.pos += 1
            items = []
            if not self.eat_op("]"):
                items.append(self.parse_or())
                while self.eat_op(","):
                    items.append(self.parse_or())
                self.expect_op("]")
            return ("list", items)
        if tok[0] == "str":
            self.pos += 1
            return ("lit", tok[1])
        if tok[0] == "num":
            self.pos += 1
            return ("lit", tok[1])
        if tok[0] == "ident":
            word = tok[1]
            if word == "true":
                self.pos += 1
                return ("lit", True)
            if word == "false":
                self.pos += 1
                return ("lit", False)
            if word == "null":
                self.pos += 1
                return ("lit", None)
            nxt = self.toks[self.pos + 1] if self.pos + 1 < len(self.toks) else None
            if nxt is not None and nxt[0] == "op" and nxt[1] == "(":
                if word not in FUNCTIONS:
                    self.fail(f'unknown function "{word}" (supported: {", ".join(sorted(FUNCTIONS))})')
                self.pos += 2
                args = [self.parse_or()]
                while self.eat_op(","):
                    args.append(self.parse_or())
                self.expect_op(")")
                if len(args) != 2:
                    self.fail(f'function "{word}" takes exactly 2 arguments')
                return ("call", word, args)
            path = [word]
            self.pos += 1
            while self.eat_op("."):
                seg = self.peek()
                if seg is None or seg[0] != "ident":
                    self.fail('expected a field name after "."')
                path.append(seg[1])
                self.pos += 1
            return ("ref", path)
        self.fail("unexpected token")


def parse_policy_expression(src):
    """Parse one rule expression; raises PolicySyntaxError on any problem."""
    if not isinstance(src, str) or not src.strip():
        raise PolicySyntaxError("rule expression is empty")
    return _Parser(_tokenize(src), src).parse()


# ── Evaluation ────────────────────────────────────────────────────────


def _truthy(value):
    """JavaScript truthiness, so && / || / ! decide as the Kernel's do."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and value == value  # 0 and NaN are falsy
    if isinstance(value, str):
        return value != ""
    return True  # lists and dicts are always truthy in JS, even empty ones


def _strict_eq(left, right):
    """JavaScript === for the value shapes a policy context carries."""
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, str) and isinstance(right, str):
        return left == right
    if isinstance(left, (list, dict)) or isinstance(right, (list, dict)):
        return left is right  # JS compares objects by reference
    return False


def _resolve_ref(path, ctx):
    root, rest = path[0], path[1:]
    if root == "payload":
        current = ctx.get("payload") or {}
    elif root in ctx:
        current = ctx[root]
    else:
        return None  # unknown root: absent, like a missing payload field
    for seg in rest:
        if not isinstance(current, dict):
            return None
        current = current.get(seg)
        if current is None:
            return None
    return current


def _type_name(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object"


def _eval(ast, ctx):
    tag = ast[0]
    if tag == "lit":
        return ast[1]
    if tag == "list":
        return [_eval(item, ctx) for item in ast[1]]
    if tag == "ref":
        return _resolve_ref(ast[1], ctx)
    if tag == "not":
        return not _truthy(_eval(ast[1], ctx))
    if tag == "and":
        return _truthy(_eval(ast[1], ctx)) and _truthy(_eval(ast[2], ctx))
    if tag == "or":
        return _truthy(_eval(ast[1], ctx)) or _truthy(_eval(ast[2], ctx))
    if tag == "cmp":
        op, left, right = ast[1], _eval(ast[2], ctx), _eval(ast[3], ctx)
        if op == "==":
            return _strict_eq(left, right)
        if op == "!=":
            return not _strict_eq(left, right)
        if op == "in":
            if not isinstance(right, list):
                raise PolicyEvalError('right side of "in" is not a list')
            return any(_strict_eq(left, item) for item in right)
        orderable = (
            isinstance(left, (int, float)) and not isinstance(left, bool)
            and isinstance(right, (int, float)) and not isinstance(right, bool)
        ) or (isinstance(left, str) and isinstance(right, str))
        if not orderable:
            raise PolicyEvalError(f"cannot order-compare {_type_name(left)} with {_type_name(right)}")
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right
    if tag == "call":
        fn = ast[1]
        first, second = (_eval(arg, ctx) for arg in ast[2])
        if not isinstance(first, str) or not isinstance(second, str):
            raise PolicyEvalError(f"{fn}() needs two string arguments")
        if fn == "startsWith":
            return first.startswith(second)
        if fn == "endsWith":
            return first.endswith(second)
        if fn == "contains":
            return second in first
        # matches
        try:
            return re.search(second, first) is not None
        except re.error as error:
            raise PolicyEvalError(f"bad regex in matches(): {error}") from None
    raise PolicyEvalError(f"unknown AST node {tag}")


# ── Compiled policy ───────────────────────────────────────────────────


def compile_policy(doc):
    """Compile a policy document ({"rules": [...]}) the Kernel's way.

    Broken rules are kept, with their error and their stance: a broken
    restrictive rule fails closed at evaluation; a broken permissive
    rule is inert.
    """
    rules = []
    raw_rules = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(raw_rules, list):
        raw_rules = []
    for idx, raw in enumerate(raw_rules):
        raw = raw if isinstance(raw, dict) else {}
        rule_id = raw.get("id")
        if not (isinstance(rule_id, str) and rule_id.strip()):
            rule_id = f"<invalid rule #{idx + 1}>"
        effect = raw.get("effect")
        effect_ok = effect in EFFECT_TIERS
        handoff_to = raw.get("handoff_to")
        if not (isinstance(handoff_to, str) and handoff_to.strip()):
            handoff_to = None
        ast = None
        error = None
        if not effect_ok:
            error = f"effect must be one of {', '.join(EFFECT_TIERS)} (got {effect!r})"
        elif effect == "hand_off" and not handoff_to:
            error = "hand_off rule has no handoff_to target — there is nowhere to route the action"
        else:
            try:
                ast = parse_policy_expression(raw.get("when") if isinstance(raw.get("when"), str) else "")
            except PolicySyntaxError as exc:
                error = str(exc)
        rules.append(
            {
                "id": rule_id,
                "effect": effect if effect_ok else "deny",
                "when": raw.get("when") if isinstance(raw.get("when"), str) else "",
                "note": raw.get("note") if isinstance(raw.get("note"), str) else None,
                "handoff_to": handoff_to,
                "locked": raw.get("locked") is True,
                "ast": ast,
                "error": error,
                "broken_stance": "inert" if effect_ok and effect not in RESTRICTIVE else "deny",
            }
        )
    return {"rules": rules, "source": doc}


def evaluate_policy(policy, ctx):
    """Evaluate a compiled policy against one action context.

    Strictest tier first, fail-closed — see the module header for the
    exact semantics. Returns {"verdict", "rule_id", "reason",
    "handoff_to"}; rule_id is None only for the no-match deny.
    """
    for rule in policy["rules"]:
        if rule["error"] and rule["broken_stance"] == "deny":
            return {
                "verdict": "deny",
                "rule_id": rule["id"],
                "reason": f'policy rule "{rule["id"]}" is broken ({rule["error"]}) — broken rules fail closed',
                "handoff_to": None,
            }
    for effect in EFFECT_TIERS:
        for rule in policy["rules"]:
            if rule["effect"] != effect or rule["error"]:
                continue
            try:
                matched = _truthy(_eval(rule["ast"], ctx))
            except PolicyEvalError as exc:
                if effect not in RESTRICTIVE:
                    continue  # an erroring permissive rule never grants
                return {
                    "verdict": "deny",
                    "rule_id": rule["id"],
                    "reason": f'policy rule "{rule["id"]}" failed to evaluate ({exc}) — failing closed',
                    "handoff_to": None,
                }
            if matched:
                reasons = {
                    "deny": f'denied by policy rule "{rule["id"]}"',
                    "ask": f'policy rule "{rule["id"]}" requires human approval (ask)',
                    "hand_off": (
                        f'policy rule "{rule["id"]}" hands this action off to '
                        f'"{rule["handoff_to"]}" instead of executing it'
                    ),
                    "pre_approved": (
                        f'policy rule "{rule["id"]}" grants standing approval '
                        "(pre-approved within its bounds)"
                    ),
                    "allow": f'allowed by policy rule "{rule["id"]}"',
                }
                return {
                    "verdict": effect,
                    "rule_id": rule["id"],
                    "reason": reasons[effect],
                    "handoff_to": rule["handoff_to"] if effect == "hand_off" else None,
                }
    return {
        "verdict": "deny",
        "rule_id": None,
        "reason": "no policy rule matched this action — denied by the fail-closed default",
        "handoff_to": None,
    }


def merge_policy_docs(base, overlay):
    """Merge an editable overlay onto a base policy, the Kernel's way.

    Locked base rules are carried verbatim and overlay rules reusing
    their id are dropped; a non-locked base rule is replaced by an
    overlay rule with the same id; other overlay rules append.
    """
    base_rules = base.get("rules") if isinstance(base, dict) else None
    overlay_rules = overlay.get("rules") if isinstance(overlay, dict) else None
    base_rules = base_rules if isinstance(base_rules, list) else []
    overlay_rules = overlay_rules if isinstance(overlay_rules, list) else []
    locked_ids = {r.get("id") for r in base_rules if isinstance(r, dict) and r.get("locked") is True}
    overlay_by_id = {}
    for rule in overlay_rules:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str) and rule["id"] not in locked_ids:
            overlay_by_id[rule["id"]] = rule
    merged = []
    consumed = set()
    for rule in base_rules:
        replacement = None
        if isinstance(rule, dict) and rule.get("locked") is not True:
            replacement = overlay_by_id.get(rule.get("id"))
        if replacement is not None:
            merged.append(replacement)
            consumed.add(rule["id"])
        else:
            merged.append(rule)
    base_ids = {r.get("id") for r in base_rules if isinstance(r, dict)}
    for rule in overlay_rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        if rule["id"] in locked_ids or rule["id"] in consumed or rule["id"] in base_ids:
            continue
        merged.append(rule)
    return {"rules": merged}
