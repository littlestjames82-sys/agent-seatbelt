"""Agent Seatbelt — a seatbelt for browser agents.

Record-first, fail-closed policy gating for agent actions, before
they happen: classify the action, decide it against an executable
policy, write the record first — and only then, if the verdict
allows it, let your loop execute.

By Ghost Developer Studio. MIT licensed. The policy engine is a
faithful Python port of the Ghost Kernel's engine (also shipped in
TypeScript as part of GhostGuard, the full governance package);
policy documents are interchangeable across all three.
"""

from .classify import CONSEQUENTIAL, READ_ONLY, classify_action
from .governor import (
    EXECUTABLE_VERDICTS,
    CallableSink,
    Governor,
    JsonlSink,
    MemorySink,
    default_policy,
    load_policy,
)
from .policy import (
    PolicyEvalError,
    PolicySyntaxError,
    compile_policy,
    evaluate_policy,
    merge_policy_docs,
    parse_policy_expression,
)

__version__ = "0.2.0"

__all__ = [
    "CONSEQUENTIAL",
    "EXECUTABLE_VERDICTS",
    "READ_ONLY",
    "CallableSink",
    "Governor",
    "JsonlSink",
    "MemorySink",
    "PolicyEvalError",
    "PolicySyntaxError",
    "classify_action",
    "compile_policy",
    "default_policy",
    "evaluate_policy",
    "load_policy",
    "merge_policy_docs",
    "parse_policy_expression",
]
