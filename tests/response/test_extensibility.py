"""New safety rules, actions and decoy types by editing YAML only: no code changes."""
import shutil
from pathlib import Path

import pytest
import yaml

from deconflicted.adapters import flow
from deconflicted.deception import DecoyRegistry, DecoyTrigger
from deconflicted.response import ResponseGuard
from deconflicted.schema import Action

CONFIG = Path(__file__).parents[2] / "config"
STATE = {"level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0, "writers": {"plc-1": ["eng-ws-01"]}}


@pytest.fixture
def config(tmp_path):
    copy = tmp_path / "config"
    shutil.copytree(CONFIG, copy)
    return copy


def edit(path: Path, change):
    data = yaml.safe_load(path.read_text())
    change(data)
    path.write_text(yaml.safe_dump(data))


def reset(value):
    return Action(id="a", kind="reset_setpoint", target="plc-1", params={"value": value})


def test_a_new_safety_rule_changes_the_decision(config):
    assert ResponseGuard(str(config)).preview(reset(58), STATE).decision == "allow", "58 is inside 40 to 60"
    edit(config / "safety_rules.yaml", lambda d: d["rules"].append(
        {"id": "setpoint_tight", "register": 40001, "min": 45, "max": 55}))
    preview = ResponseGuard(str(config)).preview(reset(58), STATE)
    assert preview.decision != "allow" and preview.violations[0].rule_id == "setpoint_tight"
    assert "setpoint_tight" in preview.reason
    assert ResponseGuard(str(config)).preview(reset(52), STATE).decision == "allow"


def test_a_new_rules_only_entry_changes_rules_only_mode(config):
    action = Action(id="a", kind="disable_account", target="alice")
    assert ResponseGuard(str(config)).preview(action, None).decision == "allow"
    edit(config / "safety_rules.yaml", lambda d: d["rules_only"].append(
        {"id": "no_disable", "action": "disable_account", "decision": "block", "reason": "accounts stay on during an incident"}))
    blocked = ResponseGuard(str(config)).preview(action, None)
    assert blocked.decision == "block" and "accounts stay on" in blocked.reason


def test_an_action_is_enabled_and_disabled_in_yaml(config):
    limit = Action(id="a", kind="rate_limit_writes", target="plc-1", params={"max_per_minute": 6})
    assert ResponseGuard(str(config)).preview(limit, STATE).decision == "allow"
    edit(config / "actions.yaml", lambda d: d["actions"].pop("rate_limit_writes"))
    assert ResponseGuard(str(config)).preview(limit, STATE).decision == "block", "an action that is not listed is blocked"
    edit(config / "actions.yaml", lambda d: d["actions"].update(
        {"rate_limit_writes": {"target": "plc", "params": ["max_per_minute"], "process_effect": "none"}}))
    assert ResponseGuard(str(config)).preview(limit, STATE).decision == "allow"


def test_an_action_effect_is_changed_in_yaml(config):
    edit(config / "actions.yaml", lambda d: d["actions"]["disable_account"].update({"process_effect": "plc_offline"}))
    # plc_offline only has an effect on a PLC target, and disable_account targets users, so nothing changes.
    assert ResponseGuard(str(config)).preview(Action(id="a", kind="disable_account", target="alice"), STATE).decision == "allow"
    edit(config / "actions.yaml", lambda d: d["actions"]["kill_process"].update({"target": "plc", "process_effect": "plc_offline"}))
    kill = Action(id="a", kind="kill_process", target="plc-1", params={"process": "x"})
    assert ResponseGuard(str(config)).preview(kill, STATE).decision in ("downgrade", "block")


def test_a_new_decoy_type_and_decoy_by_yaml_only(config):
    hosts, decoys = config / "hosts.yaml", config / "decoys.yaml"
    edit(decoys, lambda d: d["types"].update({"fake_historian": {"service": "opcua", "port": 4840, "looks_like": "hist-01", "kinds": ["historian"]}}))
    edit(hosts, lambda d: d["decoys"].update({"hist-decoy-01": {"ip": "10.0.2.95", "kind": "historian", "zone": "it"}}))
    registry = DecoyRegistry(str(config))
    assert {d.id: d.type for d in registry.decoys.values()}["hist-decoy-01"] == "fake_historian"
    assert registry.is_decoy("host:hist-decoy-01") and registry.is_decoy("host:10.0.2.95")
    signal = DecoyTrigger(registry)(flow.parse_line("2026-03-04T05:00:00Z,10.0.1.21,10.0.2.95,4840,tcp,100,2"))
    assert signal.entity_ids == ["host:ws-help-01", "decoy:hist-decoy-01"] and signal.detail["decoy"] == "hist-decoy-01"


def test_an_allowlist_entry_is_added_in_yaml(config):
    event = flow.parse_line("2026-03-04T05:00:00Z,10.0.1.21,10.0.2.99,445,tcp,100,2")
    assert DecoyTrigger(DecoyRegistry(str(config)))(event) is not None
    edit(config / "decoys.yaml", lambda d: d["allowlist"].append({"host": "ws-help-01", "ports": [445], "reason": "vulnerability scan"}))
    assert DecoyTrigger(DecoyRegistry(str(config)))(event) is None
