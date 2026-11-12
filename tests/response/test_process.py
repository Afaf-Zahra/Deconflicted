import math

import pytest

from deconflicted.sim.process import Effect, StateError, parse_state, simulate

NORMAL = {"level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0}


def at(samples, t):
    return next(s for s in samples if s.t == t)


def test_normal_operation_cycles_around_the_setpoint():
    samples = simulate(parse_state(NORMAL), 300)
    assert len(samples) == 301 and samples[0].t == 0 and samples[-1].t == 300
    levels = [s.level for s in samples]
    assert 46.5 < min(levels) and max(levels) < 53.5, "the controller should hold the level near 50"


def test_pump_frozen_on_passes_80_at_60_seconds():
    state = parse_state({**NORMAL, "pump": True})
    samples = simulate(state, 300, Effect("plc_offline"))
    assert at(samples, 60).level == pytest.approx(80.0, abs=1e-6)
    assert at(samples, 62).level > 80


def test_pump_frozen_off_passes_below_20_at_75_seconds():
    samples = simulate(parse_state(NORMAL), 300, Effect("plc_offline"))
    assert at(samples, 75).level == pytest.approx(20.0, abs=1e-6)
    assert at(samples, 77).level < 20


def test_setpoint_attack_pushes_level_past_80():
    state = parse_state({**NORMAL, "pending_writes": [{"t": 30, "plc": "plc-1", "register": 40001, "value": 95}]})
    samples = simulate(state, 300)
    first = next(s.t for s in samples if s.level > 80)
    assert 80 <= first <= 100, f"level first passed 80 at {first} s"
    assert at(samples, 29).setpoint == 50 and at(samples, 31).setpoint == 95


def test_blocked_write_never_arrives():
    write = {"t": 30, "plc": "plc-1", "register": 40001, "value": 95}
    state = parse_state({**NORMAL, "writers": {"plc-1": ["eng-ws-01"]}, "pending_writes": [write]})
    blocked = simulate(state, 300, Effect("block_writes", source="eng-ws-01", plc="plc-1"))
    assert max(s.setpoint for s in blocked) == 50
    other = simulate(state, 300, Effect("block_writes", source="ws-help-01", plc="plc-1"))
    assert max(s.setpoint for s in other) == 95, "a different host being blocked must not stop the write"


def test_set_setpoint_takes_effect_at_time_zero():
    assert simulate(parse_state(NORMAL), 10, Effect("set_setpoint", value=45))[0].setpoint == 45


def test_pump_and_valve_writes_are_applied():
    state = parse_state({**NORMAL, "pending_writes": [
        {"t": 5, "plc": "plc-1", "register": 40010, "value": 0},
        {"t": 5, "plc": "plc-1", "register": 40011, "value": 100}]})
    samples = simulate(state, 100)
    assert at(samples, 100).level == 0.0, "pump forced off and valve open drains the tank to the floor"


@pytest.mark.parametrize("bad", [
    {k: v for k, v in NORMAL.items() if k != "level"},
    {**NORMAL, "level": 120}, {**NORMAL, "level": math.nan}, {**NORMAL, "pump": 1}, {**NORMAL, "valve": -1},
    {**NORMAL, "pending_writes": [{"t": 999, "plc": "plc-1", "register": 40001, "value": 1}]},
    {**NORMAL, "pending_writes": [{"plc": "plc-1"}]},
])
def test_bad_state_is_rejected(bad):
    with pytest.raises(StateError):
        parse_state(bad)
