import shutil
from pathlib import Path

import pytest
import yaml

from deconflicted.response import ResponseGuard
from deconflicted.response import guard as guard_module
from deconflicted.response.zero_disruption import run
from deconflicted.schema import Action, Preview

CONFIG = Path(__file__).parents[2] / "config"
STATE = {"t": 0, "level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0,
         "plc_online": {"plc-1": True}, "writers": {"plc-1": ["eng-ws-01"]},
         "pending_writes": [{"t": 30, "plc": "plc-1", "register": 40001, "value": 95}]}


def act(kind, target, **params):
    return Action(id="act-1", kind=kind, target=target, params=params)


@pytest.fixture
def guard():
    return ResponseGuard()


def test_scenario_block_write_is_allowed(guard):
    preview = guard.preview(act("block_write", "eng-ws-01", to="plc-1"), STATE)
    assert preview.decision == "allow", preview.reason
    assert [p.t for p in preview.before_trace] == [float(t) for t in range(0, 301, 10)]
    assert len(preview.after_trace) == 31


def test_scenario_disable_account_is_allowed(guard):
    assert guard.preview(act("disable_account", "alice"), STATE).decision == "allow"


def test_scenario_isolate_plc_is_downgraded_to_block_write(guard):
    preview = guard.preview(act("isolate_host", "plc-1"), STATE)
    assert preview.decision == "downgrade", preview.reason
    assert any(v.rule_id == "level_low" for v in preview.violations)
    first = preview.safer_options[0]
    assert (first.kind, first.target, first.params) == ("block_write", "eng-ws-01", {"to": "plc-1"})
    assert len(preview.safer_options) <= 3
    assert "level_low" in preview.reason and "block_write" in preview.reason


def test_isolate_plc_is_blocked_when_no_option_is_safe(tmp_path):
    config = tmp_path / "config"
    shutil.copytree(CONFIG, config)
    actions = yaml.safe_load((config / "actions.yaml").read_text())
    for name in ("reset_setpoint", "rate_limit_writes"):
        del actions["actions"][name]
    (config / "actions.yaml").write_text(yaml.safe_dump(actions))
    state = {**STATE, "writers": {"plc-1": []}, "pending_writes": []}
    preview = ResponseGuard(str(config)).preview(act("isolate_host", "plc-1"), state)
    assert preview.decision == "block" and preview.safer_options == [], preview.reason
    assert "no safer option" in preview.reason


def test_isolate_plc_with_no_writers_falls_back_to_the_other_options(guard):
    state = {**STATE, "writers": {"plc-1": []}, "pending_writes": []}
    preview = guard.preview(act("isolate_host", "plc-1"), state)
    assert preview.decision == "downgrade"
    assert [o.kind for o in preview.safer_options] == ["rate_limit_writes", "reset_setpoint"]


def test_reset_setpoint_to_an_unsafe_value_is_not_allowed(guard):
    preview = guard.preview(act("reset_setpoint", "plc-1", value=95), STATE)
    assert preview.decision != "allow"
    assert any(v.rule_id == "setpoint_range" for v in preview.violations)


def test_reset_setpoint_to_a_safe_value_is_allowed(guard):
    assert guard.preview(act("reset_setpoint", "plc-1", value=50), STATE).decision == "allow"


def test_an_action_is_not_blamed_for_an_existing_problem(guard):
    state = {**STATE, "level": 90.0, "pending_writes": []}
    assert guard.preview(act("disable_account", "alice"), state).decision == "allow"


@pytest.mark.parametrize("name,action,state", [
    ("unknown kind", Action.model_construct(id="a", kind="launch", target="plc-1", params={}), STATE),
    ("kind not in yaml", Action.model_construct(id="a", kind="bogus", target="alice", params={}), STATE),
    ("unknown target", act("isolate_host", "no-such-host"), STATE),
    ("unknown user", act("disable_account", "mallory"), STATE),
    ("wrong target type", act("disable_account", "plc-1"), STATE),
    ("plc action on a host", act("reset_setpoint", "ws-help-01", value=50), STATE),
    ("unmodelled plc", act("isolate_host", "plc-2"), STATE),
    ("unmodelled plc as to", act("block_write", "eng-ws-01", to="plc-2"), STATE),
    ("missing param", act("block_write", "eng-ws-01"), STATE),
    ("empty process", act("kill_process", "file-01", process=" "), STATE),
    ("bad value", act("reset_setpoint", "plc-1", value="high"), STATE),
    ("bad rate", act("rate_limit_writes", "plc-1", max_per_minute=0), STATE),
    ("state missing level", act("disable_account", "alice"), {k: v for k, v in STATE.items() if k != "level"}),
    ("state nan", act("disable_account", "alice"), {**STATE, "level": float("nan")}),
])
def test_fail_closed(guard, name, action, state):
    preview = guard.preview(action, state)
    assert isinstance(preview, Preview) and preview.decision == "block", f"{name}: {preview.reason}"
    assert preview.reason


def test_a_broken_simulation_blocks(monkeypatch, guard):
    def boom(*_a, **_k):
        raise RuntimeError("model crashed")
    monkeypatch.setattr(guard_module, "simulate", boom)
    preview = guard.preview(act("disable_account", "alice"), STATE)
    assert preview.decision == "block" and "model crashed" in preview.reason


@pytest.mark.parametrize("damage", ["bad yaml", "missing", "unknown register", "no rules", "bad effect"])
def test_bad_configuration_blocks_everything(tmp_path, damage):
    config = tmp_path / "config"
    shutil.copytree(CONFIG, config)
    rules, actions = config / "safety_rules.yaml", config / "actions.yaml"
    if damage == "bad yaml":
        rules.write_text("horizon_seconds: [unclosed", encoding="utf-8")
    elif damage == "missing":
        rules.unlink()
    elif damage == "unknown register":
        rules.write_text(rules.read_text().replace("register: 40002", "register: 49999", 1))
    elif damage == "no rules":
        rules.write_text("horizon_seconds: 300\nrules: []\n")
    else:
        actions.write_text(actions.read_text().replace("process_effect: none", "process_effect: explode", 1))
    guard = ResponseGuard(str(config))
    preview = guard.preview(act("disable_account", "alice"), STATE)
    assert preview.decision == "block" and "configuration" in preview.reason


def test_failed_integrity_check_blocks():
    guard = ResponseGuard(integrity_check=lambda: (False, "safety_rules.yaml changed"))
    preview = guard.preview(act("disable_account", "alice"), STATE)
    assert preview.decision == "block" and "integrity" in preview.reason
    ok = ResponseGuard(integrity_check=lambda: (True, ""))
    assert ok.preview(act("disable_account", "alice"), STATE).decision == "allow"


def test_rules_only_mode(guard):
    isolate = guard.preview(act("isolate_host", "plc-1"), None)
    assert isolate.decision == "block" and "rules-only" in isolate.reason and "uncontrolled" in isolate.reason
    assert guard.preview(act("block_write", "eng-ws-01", to="plc-1"), None).decision == "block"
    assert guard.preview(act("disable_account", "alice"), None).decision == "allow"
    forced = ResponseGuard(rules_only=True)
    assert forced.preview(act("disable_account", "alice"), STATE).reason.startswith("rules-only")
    assert forced.preview(act("isolate_host", "ws-help-01"), STATE).decision == "allow"


def test_prefixed_targets_are_accepted(guard):
    assert guard.preview(act("disable_account", "user:alice"), STATE).decision == "allow"
    assert guard.preview(act("block_write", "host:eng-ws-01", to="plc:plc-1"), STATE).decision == "allow"


def test_zero_disruption_property():
    report = run(cases=300, seed=1)
    assert report.violations == 0, f"{report.violations} violations, examples: {report.examples}"
    assert report.actions == report.cases * 9
    assert report.allowed and report.downgraded and report.blocked, "the property run should exercise all three decisions"


def test_the_property_check_catches_an_unsafe_guard():
    class AlwaysAllow(ResponseGuard):
        def preview(self, action, process_state=None):
            return Preview(action=action, before_trace=[], after_trace=[], violations=[],
                           safer_options=[], decision="allow", reason="unsafe test double")
    report = run(cases=50, seed=1, guard=AlwaysAllow())
    assert report.violations > 0, "the check must fail when the guard allows everything"
