"""The simulated water tank, controlled by plc-1. One step is one second.

level (percent, 0 to 100) rises by INFLOW while the pump is on and falls by VALVE_COEF * valve.
The PLC runs a bang-bang controller with hysteresis: pump on below setpoint - HYSTERESIS,
pump off above setpoint + HYSTERESIS.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

INFLOW = 0.9
VALVE_COEF = 0.008
HYSTERESIS = 2.0
MODELLED_PLC = "plc-1"
REG_SETPOINT, REG_LEVEL, REG_PUMP, REG_VALVE = 40001, 40002, 40010, 40011


class StateError(ValueError):
    """The process state is missing a field or has a value that makes no sense."""


@dataclass(frozen=True)
class Write:
    t: int
    plc: str
    register: int
    value: float
    source: str | None = None


@dataclass(frozen=True)
class State:
    level: float
    setpoint: float
    pump: bool
    valve: float
    writers: dict[str, list[str]] = field(default_factory=dict)
    pending_writes: tuple[Write, ...] = ()


@dataclass(frozen=True)
class Effect:
    """What a response action does to the process.

    kind: none, plc_offline, block_writes or set_setpoint.
    """
    kind: str = "none"
    value: float | None = None       # set_setpoint
    source: str | None = None        # block_writes: the host whose writes are blocked
    plc: str | None = None           # block_writes: the PLC they are blocked from


@dataclass(frozen=True)
class Sample:
    t: int
    level: float
    setpoint: float


def _number(data: dict, key: str, low: float | None = None, high: float | None = None) -> float:
    if key not in data:
        raise StateError(f"process state has no {key!r}")
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise StateError(f"process state {key!r} is not a finite number")
    if (low is not None and value < low) or (high is not None and value > high):
        raise StateError(f"process state {key!r}={value} is out of range")
    return float(value)


def parse_state(data: dict[str, Any], horizon: int = 300) -> State:
    """Validate a process-state dict. Anything wrong raises StateError (the guard then blocks)."""
    if not isinstance(data, dict):
        raise StateError("process state must be an object")
    if "pump" not in data or not isinstance(data["pump"], bool):
        raise StateError("process state 'pump' must be true or false")
    writes = []
    for item in data.get("pending_writes", []) or []:
        try:
            t = int(item["t"])
            register = int(item["register"])
            value = float(item["value"])
            plc = str(item["plc"])
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError(f"bad pending write {item!r}") from exc
        if not math.isfinite(value) or not 0 <= t <= horizon:
            raise StateError(f"bad pending write {item!r}")
        writes.append(Write(t, plc, register, value, item.get("source")))
    writers = {str(k): [str(h) for h in v] for k, v in (data.get("writers") or {}).items()}
    return State(
        level=_number(data, "level", 0, 100),
        setpoint=_number(data, "setpoint"),
        pump=data["pump"],
        valve=_number(data, "valve", 0, 100),
        writers=writers,
        pending_writes=tuple(sorted(writes, key=lambda w: w.t)),
    )


def _blocked(write: Write, effect: Effect, state: State) -> bool:
    if effect.kind != "block_writes" or write.plc != effect.plc:
        return False
    if write.source is not None:
        return write.source == effect.source
    # A write with no known source is attributed to the PLC's listed writers.
    return effect.source in state.writers.get(write.plc, [])


def simulate(state: State, horizon: int, effect: Effect | None = None) -> list[Sample]:
    """Run the tank for `horizon` seconds. Returns one sample per second, from t=0 to t=horizon."""
    effect = effect or Effect()
    level, setpoint, pump, valve = state.level, state.setpoint, state.pump, state.valve
    if effect.kind == "set_setpoint" and effect.value is not None:
        setpoint = effect.value
    frozen = effect.kind == "plc_offline"
    pump_override: bool | None = None
    pending = [] if frozen else [w for w in state.pending_writes
                                 if w.plc == MODELLED_PLC and not _blocked(w, effect, state)]
    index = 0
    samples = []
    for t in range(horizon + 1):
        while index < len(pending) and pending[index].t <= t:
            write = pending[index]
            index += 1
            if write.register == REG_SETPOINT:
                setpoint = write.value
            elif write.register == REG_PUMP:
                pump_override = write.value != 0
            elif write.register == REG_VALVE:
                valve = min(100.0, max(0.0, write.value))
        samples.append(Sample(t, level, setpoint))
        if not frozen:
            if pump_override is not None:
                pump = pump_override
            elif level < setpoint - HYSTERESIS:
                pump = True
            elif level > setpoint + HYSTERESIS:
                pump = False
        level += (INFLOW if pump else 0.0) - VALVE_COEF * valve
        level = min(100.0, max(0.0, level))
    return samples
