import json
import shutil
from pathlib import Path

import pytest
import yaml

from deconflicted.adapters import flow, modbus
from deconflicted.deception import DecoyConfigError, DecoyRegistry, DecoyService, DecoyTrigger, trail_ahead
from deconflicted.deception.trail_ahead import reachable, safety_ok
from deconflicted.schema import DecoyRegistry as RegistryProtocol
from deconflicted.schema import DecoyTrigger as TriggerProtocol
from deconflicted.schema import Event

CONFIG = Path(__file__).parents[2] / "config"
FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}


@pytest.fixture
def registry():
    return DecoyRegistry()


def event(fixture_id):
    return Event(**{k: v for k, v in FIXTURES[fixture_id].items() if k != "label"})


def test_registry_entity_forms_and_protocol(registry):
    assert isinstance(registry, RegistryProtocol) and isinstance(DecoyTrigger(registry), TriggerProtocol)
    for form in ("decoy:dc-decoy-01", "host:dc-decoy-01", "host:10.0.2.99", "plc:plc-decoy-1", "host:10.0.4.99"):
        assert registry.is_decoy(form), form
    for form in ("host:dc-01", "host:10.0.2.5", "user:alice", "plc:plc-1"):
        assert not registry.is_decoy(form), form
    assert {d.id: d.type for d in registry.decoys.values()} == {"dc-decoy-01": "fake_dc", "plc-decoy-1": "fake_plc"}


def test_trigger_matches_the_scenario_signal(registry):
    signal = DecoyTrigger(registry)(event("flow-c7621933881f"))
    assert signal is not None
    assert signal.kind == "decoy_hit" and signal.score == 1.0
    assert signal.ts.isoformat() == "2026-03-04T03:48:20+00:00"
    assert signal.entity_ids == ["host:ws-help-01", "decoy:dc-decoy-01"]
    assert signal.event_ids == ["flow-c7621933881f"] and signal.techniques == ["T1018"]
    assert signal.detail == {"decoy": "dc-decoy-01", "allowlisted": False}


def test_trigger_ignores_normal_traffic_and_records_hits(registry):
    trigger = DecoyTrigger(registry)
    assert trigger(event("windows-3d9b0caf56b1")) is None
    assert trigger(event("modbus-06e981d9288c")) is None
    trigger(event("flow-c7621933881f"))
    assert [(h.decoy, h.source) for h in trigger.hits] == [("dc-decoy-01", "ws-help-01")]


def test_allowlisted_source_gives_no_signal(registry):
    trigger = DecoyTrigger(registry)
    allowed = flow.parse_line("2026-03-04T09:00:00Z,10.0.1.10,10.0.2.99,445,tcp,100,2")
    assert trigger(allowed) is None and trigger.allowlisted == 1 and list(trigger.hits) == []
    other_port = flow.parse_line("2026-03-04T09:00:00Z,10.0.1.10,10.0.2.99,3389,tcp,100,2")
    assert trigger(other_port) is not None, "the allowlist is limited to the listed ports"


def test_trigger_sees_a_fake_plc_touched_over_modbus(registry):
    read = modbus.parse_line('{"ts":"2026-03-04T05:00:00.000Z","server":"plc-decoy-1","client_ip":"10.0.3.5","func":3,"address":40001}')
    signal = DecoyTrigger(registry)(read)
    assert signal.entity_ids == ["host:eng-ws-01", "decoy:plc-decoy-1"]


@pytest.mark.parametrize("change", ["outside range", "real address", "unknown type"])
def test_bad_decoy_configuration_fails_at_startup(tmp_path, change):
    config = tmp_path / "config"
    shutil.copytree(CONFIG, config)
    hosts = yaml.safe_load((config / "hosts.yaml").read_text())
    if change == "outside range":
        hosts["decoys"]["dc-decoy-01"]["ip"] = "10.0.2.50"
    elif change == "real address":
        hosts["decoys"]["dc-decoy-01"]["ip"] = "10.0.2.5"
    else:
        settings = yaml.safe_load((config / "decoys.yaml").read_text())
        del settings["types"]["fake_plc"]
        (config / "decoys.yaml").write_text(yaml.safe_dump(settings))
    (config / "hosts.yaml").write_text(yaml.safe_dump(hosts))
    with pytest.raises(DecoyConfigError):
        DecoyRegistry(str(config))


def test_reachability_uses_adjacent_zones():
    assert reachable(1, 2) and reachable(2, 3) and reachable(3, 4) and reachable(2, 2)
    assert not reachable(1, 4) and not reachable(2, 9) and not reachable(9, 9)


def test_trail_ahead_from_the_scenario_foothold(registry):
    placements = trail_ahead(registry, ["host:ws-help-01"])
    assert [(p.host, p.decoy_type, p.safety_ok) for p in placements] == [
        ("dc-01", "fake_dc", True), ("file-01", "fake_dc", True)]
    assert [p.address for p in placements] == ["10.0.2.90", "10.0.2.91"], "each placement gets its own free address"
    assert placements[0].reason == "likely next hop from ws-help-01, reachable, in the server zone"


def test_trail_ahead_skips_zones_without_a_decoy_type_and_unknown_hosts(registry):
    assert trail_ahead(registry, ["host:file-01"]) == [], "eng-ws-01 is in zone 3, which has no decoy type"
    assert trail_ahead(registry, ["host:no-such-host", "ws-admin-01"]) == []


def test_placement_outside_the_reserved_range_is_never_safe(registry):
    assert safety_ok(registry, "fake_dc", "10.0.2.90", set())
    assert not safety_ok(registry, "fake_dc", "10.0.2.50", set())
    assert not safety_ok(registry, "fake_dc", "10.0.2.90", {"10.0.2.90"}), "an address already in use is not safe"


def test_unknown_placement_rule_fails_closed(registry):
    registry.placement_rules = ["reserved_range_only", "made_up_rule"]
    assert not safety_ok(registry, "fake_dc", "10.0.2.90", set())
    registry.placement_rules = []
    assert not safety_ok(registry, "fake_dc", "10.0.2.90", set()), "no rules configured means nothing is proven safe"


def test_service_view_collects_hits_and_placements():
    service = DecoyService()
    assert service.view().hits == [] and service.view().placements == []
    service.trigger(event("flow-c7621933881f"))
    view = service.view("INC-0042")
    assert [d.id for d in view.decoys] == ["dc-decoy-01", "plc-decoy-1"]
    assert [h.decoy for h in view.hits] == ["dc-decoy-01"]
    assert len(view.placements) == 2
    service.incident_hosts = lambda incident_id: ["file-01"]
    assert service.view("x").placements == []


def test_the_hit_list_keeps_only_the_most_recent_hits(registry):
    trigger = DecoyTrigger(registry, max_hits=3)
    for n in range(5):
        trigger(flow.parse_line(f"2026-03-04T03:48:{n:02d}Z,10.0.1.21,10.0.2.99,445,tcp,100,2"))
    assert [h.ts.second for h in trigger.hits] == [2, 3, 4], "the oldest hits are dropped"
    assert len(DecoyService().view().hits) == 0
