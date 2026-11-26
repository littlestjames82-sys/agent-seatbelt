"""Authorization adapter (spec §4.3): the broker classifies with
the EXISTING deterministic policy engine from hooks/seatbelt_hook.py
— one rulebook, two surfaces. The engine is reused, never forked:
this module loads the hook file the same way bench/run_bench.py
does and calls its evaluate_bash / _resolve_mode_overlay /
_judge_config / _judge_invoke.

Verdicts: allow / ask / deny, exactly as the hook returns them.
Judges configured under the 0.3.5 trust rules may escalate one
tier (allow->ask, ask->deny); they never authorize.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

_hook_module = None


class PolicyEngineUnavailable(Exception):
    pass


def hook_candidates():
    cands = []
    env = os.environ.get("SEATBELT_HOOK_PATH")
    if env:
        cands.append(Path(env))
    # Source tree: src/agent_seatbelt/broker/authz.py -> package root.
    cands.append(Path(__file__).resolve().parents[3]
                 / "hooks" / "seatbelt_hook.py")
    cands.append(Path.cwd() / "hooks" / "seatbelt_hook.py")
    cands.append(Path.home() / ".seatbelt" / "hooks" / "seatbelt_hook.py")
    return cands


def load_hook():
    global _hook_module
    if _hook_module is not None:
        return _hook_module
    for cand in hook_candidates():
        if cand.is_file():
            spec = importlib.util.spec_from_file_location(
                "seatbelt_hook", str(cand))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _hook_module = mod
            return mod
    raise PolicyEngineUnavailable(
        "seatbelt_hook.py not found in any of: %s"
        % ", ".join(str(c) for c in hook_candidates()))


_TIER_UP = {"allow": "ask", "ask": "deny", "deny": "deny"}


def authorize(normalized, agent_label="broker"):
    """Classify one normalized execute request.

    Returns a dict: {verdict, rule_id, reason, judge_outcome}.
    verdict is one of allow | ask | deny.
    """
    hook = load_hook()
    cwd = normalized["working_directory"]
    overlay, mode = hook._resolve_mode_overlay(cwd)
    result = hook.evaluate_bash(normalized["command"], overlay, mode,
                                cwd)
    # The hook's "defer" means "no objection — the host's native
    # flow decides". Broker mode has no native flow behind it, so
    # defer is an allow here; the raw engine decision is preserved
    # in the return value and the ledger.
    engine_decision = result["decision"]
    verdict = "allow" if engine_decision == "defer" else engine_decision
    rule_id = result.get("rule_id")
    reason = result.get("reason", "")
    judge_outcome = None

    # The judge seam, under the 0.3.5 trust rules: it may only
    # escalate, only on allow/ask, and never on a deny.
    if verdict in ("allow", "ask"):
        try:
            cfg, _proposal = hook._judge_config(cwd)
        except Exception:
            cfg = None
        if cfg is not None:
            brief = {
                "tool": "Bash",
                "agent": agent_label,
                "action": normalized["command"],
                "verdict": verdict,
                "rules": [rule_id] if rule_id else [],
                "cwd": cwd,
                "taint": False,
                "session_id": normalized["session_id"],
            }
            try:
                outcome, judge_reason = hook._judge_invoke(cfg, brief)
            except Exception:
                outcome, judge_reason = "crash", ""
            judge_outcome = outcome
            if outcome == "escalated":
                verdict = _TIER_UP[verdict]
                note = (" Judge raised this verdict (%s): %s"
                        % (result["decision"],
                           judge_reason or "no reason given"))
                reason = (reason or "") + note
    return {
        "verdict": verdict,
        "engine_decision": engine_decision,
        "rule_id": rule_id,
        "reason": reason,
        "judge_outcome": judge_outcome,
        "mode": mode,
    }
