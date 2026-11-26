"""Ghost Execution Broker (0.4.0, Phases 2-3 of the approved design).

Broker mode is a routed-execution surface: it governs only the
execution that is sent through it (`seatbelt exec`, the broker
client library). It is NOT transparent interception — the legacy
hook remains the interception surface, and it makes no isolation
claims. See docs/BROKER.md for the honest mode distinction.
"""

from .protocol import (
    PROTOCOL_VERSION,
    STATES,
    TERMINAL_STATES,
    ProtocolError,
    RequestMachine,
    ValidationError,
    request_hash,
    validate_request,
)

__all__ = [
    "PROTOCOL_VERSION",
    "STATES",
    "TERMINAL_STATES",
    "ProtocolError",
    "RequestMachine",
    "ValidationError",
    "request_hash",
    "validate_request",
]
