"""The shared guard for the API, and the process state it is given."""
from __future__ import annotations

from typing import Any, Callable

from deconflicted.ledger.service import get_integrity

from .guard import ResponseGuard

# Used until the detection pipeline supplies the live state. It matches docs/scenario.md: a normal
# tank, and an attacker who will write a setpoint of 95 to plc-1 through eng-ws-01.
DEMO_STATE: dict[str, Any] = {
    "t": 0, "level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0,
    "plc_online": {"plc-1": True},
    "writers": {"plc-1": ["eng-ws-01"]},
    "pending_writes": [{"t": 30, "plc": "plc-1", "register": 40001, "value": 95}],
}

_guard: ResponseGuard | None = None
state_provider: Callable[[str | None], dict[str, Any] | None] = lambda incident_id: DEMO_STATE


def get_guard() -> ResponseGuard:
    """The guard checks the signed config files before every answer."""
    global _guard
    if _guard is None:
        _guard = ResponseGuard(integrity_check=get_integrity().guard_check())
    return _guard


def set_guard(guard: ResponseGuard | None) -> None:
    global _guard
    _guard = guard


def set_state_provider(provider: Callable[[str | None], dict[str, Any] | None]) -> None:
    """The detection pipeline calls this to supply the live process state for an incident."""
    global state_provider
    state_provider = provider
