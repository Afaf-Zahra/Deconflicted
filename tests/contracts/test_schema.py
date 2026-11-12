"""Checks that the shared contracts, sample data and fakes agree with each other."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from deconflicted import fakes, schema

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
MOCKS = ROOT / "web" / "mock"
GENESIS = "0" * 64


@lru_cache(maxsize=None)
def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def events():
    return [schema.Event(**e) for e in load(FIXTURES / "events.json")]


def signals():
    return [schema.Signal(**s) for s in load(FIXTURES / "signals.json")]


def incident():
    return schema.Incident(**load(FIXTURES / "incident.json"))


def mock_incidents():
    return [schema.Incident(**i) for i in load(MOCKS / "incidents.json")]


def mock_events():
    return [schema.Event(**e) for e in load(MOCKS / "events.json")]


def known_names():
    hosts = yaml.safe_load((ROOT / "config" / "hosts.yaml").read_text(encoding="utf-8"))
    return set(hosts["hosts"]) | set(hosts["decoys"])


def test_event_ids_follow_the_raw_line():
    for e in events() + mock_events():
        expected = f"{e.source}-{hashlib.sha1(e.raw.encode('utf-8')).hexdigest()[:12]}"
        assert e.id == expected, f"{e.id} should be {expected}"


def test_signals_point_at_real_events():
    ids = {e.id for e in events()}
    for s in signals():
        assert set(s.event_ids) <= ids, f"{s.id} points at an unknown event"


def test_incident_is_consistent():
    inc = incident()
    sig_ids = {s.id for s in inc.signals}
    assert {c.signal_id for c in inc.chain} <= sig_ids
    assert set(inc.promoted_held_signal_ids) <= sig_ids
    assert 0 <= inc.chain_stop.index < len(inc.chain)
    assert inc.first_alert_ts >= inc.first_event_ts
    assert {s.id for s in inc.signals} == {s.id for s in signals()}


def test_mock_files_agree_with_each_other():
    mock_ids = {e.id for e in mock_events()}
    assert len(mock_ids) == len(mock_events()), "duplicate event ids in web/mock/events.json"
    for inc in mock_incidents():
        for s in inc.signals:
            assert set(s.event_ids) <= mock_ids, f"{s.id}: evidence missing from web/mock/events.json"
    assert {e.id for e in events()} <= mock_ids
    budget = schema.Budget(**load(MOCKS / "budget.json"))
    assert budget.used == len(mock_incidents())
    graphs = load(MOCKS / "graph.json")
    incident_ids = {i.id for i in mock_incidents()}
    for inc_id, g in graphs.items():
        assert inc_id in incident_ids
        graph = schema.IncidentGraph(**g)
        node_ids = {n.id for n in graph.nodes}
        for edge in graph.edges:
            assert edge.source in node_ids and edge.target in node_ids
            assert ":" in edge.token, f"token {edge.token} should look like category:detail"


def test_entities_exist_in_hosts_yaml():
    names = known_names()
    entities = set(incident().entities)
    for s in signals():
        entities |= set(s.entity_ids)
    for g in load(MOCKS / "graph.json").values():
        entities |= {n["id"] for n in g["nodes"]}
    for ent in entities:
        prefix, _, name = ent.partition(":")
        assert prefix in {"host", "user", "proc", "plc", "decoy"}, ent
        if prefix in {"host", "plc", "decoy"}:
            assert name in names, f"{ent} is not in config/hosts.yaml"


def test_hosts_yaml_decoys_use_the_reserved_ranges():
    hosts = yaml.safe_load((ROOT / "config" / "hosts.yaml").read_text(encoding="utf-8"))
    ips = [v["ip"] for section in hosts.values() for v in section.values()]
    assert len(ips) == len(set(ips)), "duplicate IP addresses in config/hosts.yaml"
    for name, v in hosts["decoys"].items():
        assert v["ip"].rsplit(".", 1)[0] in {"10.0.2", "10.0.4"}, name
        assert 90 <= int(v["ip"].rsplit(".", 1)[1]) <= 99, f"{name} is outside the reserved range"
    for name, v in hosts["hosts"].items():
        assert not 90 <= int(v["ip"].rsplit(".", 1)[1]) <= 99, f"{name} is inside a reserved range"


def test_naive_timestamps_are_rejected():
    data = load(FIXTURES / "events.json")[0] | {"ts": "2026-03-04T03:40:00"}
    with pytest.raises(ValidationError):
        schema.Event(**data)


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        schema.Event(**(load(FIXTURES / "events.json")[0] | {"usr": "typo"}))


def test_fakes_satisfy_their_interfaces():
    pairs = [
        (fakes.FakeEngine(), schema.Engine), (fakes.FakeScorer(), schema.Scorer),
        (fakes.FakeLedger(), schema.Ledger), (fakes.FakeResponseGuard(), schema.ResponseGuard),
        (fakes.FakeDecoyRegistry(), schema.DecoyRegistry), (fakes.FakeDecoyTrigger(), schema.DecoyTrigger),
    ]
    for fake, proto in pairs:
        assert isinstance(fake, proto), type(fake).__name__


def test_fake_ledger_follows_the_hash_recipe():
    ledger = fakes.FakeLedger()
    first = ledger.append("detection", {"a": 1})
    second = ledger.append("approval", {"b": 2})
    assert first.prev_hash == GENESIS and second.prev_hash == first.entry_hash
    payload_hash = hashlib.sha256(json.dumps({"a": 1}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert first.payload_hash == payload_hash
    recipe = f"{first.seq}|{first.ts.isoformat()}|{first.kind}|{first.payload_hash}|{first.prev_hash}"
    assert first.entry_hash == hashlib.sha256(recipe.encode()).hexdigest()


def test_fake_guard_fails_closed_by_default():
    action = incident().proposed_actions[0]
    assert fakes.FakeResponseGuard().preview(action, {}).decision == "block"