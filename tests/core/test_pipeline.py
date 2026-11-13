import contextlib
import io
import json
import types
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deconflicted import adapters
from deconflicted.core.baseline import Baseline
from deconflicted.core.config import load_config
from deconflicted.core.pipeline import Pipeline
from deconflicted.core.settings import Settings
from deconflicted.deception import DecoyRegistry, DecoyTrigger
from deconflicted.ingest.load import read_path
from deconflicted.schema import Event
from deconflicted.sim.build import main as build
from deconflicted.sim.process import parse_state

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}
DECOY, WRITE = "flow-c7621933881f", "modbus-06e981d9288c"
CONFIG = load_config()
_numbers = iter(range(1, 10**9))


def fixture(event_id):
    return Event(**{k: v for k, v in FIXTURES[event_id].items() if k != "label"})


def synth(hour, minute, host, user, cmdline="tool.exe run"):
    n = next(_numbers)
    return Event(id=f"windows-p{n:08d}", ts=datetime(2026, 3, 4, hour, minute, tzinfo=timezone.utc), source="windows",
                 host=host, user=user, process=cmdline.split()[0], cmdline=cmdline, action="proc_create", raw=f"synthetic {n}")


def make(baseline=None, settings=None, recorder=None):
    return Pipeline(config=CONFIG, baseline=baseline or Baseline(CONFIG), settings=settings,
                    decoy_trigger=DecoyTrigger(DecoyRegistry()), recorder=recorder)


def quiet(func, argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return func(argv)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("world")
    quiet(build, ["--out", str(root / "data"), "--benign-days", "6"])
    quiet(build, ["--out", str(root / "held"), "--day", "2026-03-12", "--benign-days", "1", "--seed", "7"])
    baseline = Baseline(CONFIG)
    baseline.fit(read_path(root / "data" / "benign")[0])
    labels = (root / "data" / "demo" / "labels.jsonl").read_text(encoding="utf-8").splitlines()
    return types.SimpleNamespace(
        baseline=baseline, scenario=read_path(root / "data" / "demo" / "scenario.jsonl")[0],
        attack_ids={json.loads(line)["id"] for line in labels}, held_out=read_path(root / "held" / "benign")[0])


# ---------------------------------------------------------------- the demo scenario
def test_the_attack_becomes_one_critical_incident(world):
    pipeline = make(world.baseline)
    pipeline.ingest(world.scenario)
    (incident,) = pipeline.incidents()
    assert incident.severity == "critical"
    assert world.attack_ids <= {event_id for signal in incident.signals for event_id in signal.event_ids}
    assert {"decoy_hit", "log_clear", "ot_invariant"} <= {signal.kind for signal in incident.signals}
    assert incident.first_event_ts.isoformat() == "2026-03-04T03:40:00+00:00"
    assert incident.first_alert_ts is not None and incident.first_alert_ts >= incident.first_event_ts
    assert [step.ts for step in incident.chain] == sorted(step.ts for step in incident.chain)
    assert len(incident.chain) == len(incident.signals)
    assert incident.chain_stop is not None and incident.chain_stop.index >= 1
    assert incident.title == "alice on ws-help-01 ends in an out-of-range write to plc-1"
    actions = incident.proposed_actions
    assert [(a.kind, a.target, a.params) for a in actions] == [
        ("isolate_host", "plc-1", {}), ("block_write", "eng-ws-01", {"to": "plc-1"}), ("disable_account", "alice", {})]
    assert [a.id for a in actions] == [f"act-{incident.id}-{n}" for n in (1, 2, 3)]


def test_the_graph_links_the_workstation_to_the_plc(world):
    pipeline = make(world.baseline)
    pipeline.ingest(world.scenario)
    (incident,) = pipeline.incidents()
    graph = pipeline.graph(incident.id)
    nodes = {node.id: node for node in graph.nodes}
    assert {"user:alice", "host:ws-help-01", "decoy:dc-decoy-01", "host:eng-ws-01", "plc:plc-1"} <= set(nodes)
    assert nodes["plc:plc-1"].anchor and nodes["decoy:dc-decoy-01"].decoy_hit
    edges = {(edge.source, edge.target, edge.token) for edge in graph.edges}
    assert ("host:eng-ws-01", "plc:plc-1", "ot:write_setpoint") in edges
    assert ("host:ws-help-01", "decoy:dc-decoy-01", "net:decoy_touch") in edges
    assert ("host:file-01", "host:eng-ws-01", "net:smb_admin") in edges
    assert pipeline.graph("INC-9999") is None


def test_a_normal_day_stays_within_the_budget(world):
    pipeline = make(world.baseline)
    pipeline.ingest(world.held_out)
    assert len(pipeline.incidents()) <= pipeline.settings.budget
    assert pipeline.budget().used <= pipeline.budget().budget
    assert pipeline.status()["events_seen"] == len(world.held_out)


# ---------------------------------------------------------------- certain signals, budget, repeats
def test_a_certain_signal_alone_opens_an_incident():
    ot = make()
    (incident,) = ot.ingest([fixture(WRITE)])
    assert incident.severity == "critical" and "out-of-range" in incident.title and "plc-1" in incident.title
    assert [a.kind for a in incident.proposed_actions] == ["isolate_host", "block_write"]
    decoy = make()
    (incident,) = decoy.ingest([fixture(DECOY)])
    assert incident.severity == "warning" and incident.title == "ws-help-01 touches the decoy dc-decoy-01"
    assert [(a.kind, a.target) for a in incident.proposed_actions] == [("isolate_host", "ws-help-01")]


def test_unrelated_certain_signals_make_separate_incidents_and_the_budget_counts_them():
    pipeline = make()
    found = pipeline.ingest([fixture(DECOY), fixture(WRITE)])
    assert [i.id for i in found] == ["INC-0001", "INC-0002"]
    assert pipeline.budget().model_dump() == {"budget": 5, "used": 2, "window_hours": 24}
    assert [e.id for e in pipeline.events([DECOY, "nope", WRITE])] == [DECOY, WRITE]


def test_the_same_events_twice_change_nothing():
    pipeline = make()
    assert len(pipeline.ingest([fixture(DECOY)])) == 1
    assert pipeline.ingest([fixture(DECOY)]) == []
    assert len(pipeline.incidents()) == 1
    pipeline.reset()
    assert pipeline.incidents() == [] and pipeline.budget().used == 0


# ---------------------------------------------------------------- held signals, quota, merging
def test_weak_signals_are_held_and_promoted_inside_the_window():
    pipeline = make(settings=Settings(weak=0.0, strong=1.0))  # with no baseline every unmatched event is a weak signal
    weak, other = synth(3, 43, "ws-help-01", "alice", "powershell.exe -enc AAAA"), synth(3, 44, "ops-ws-01", "dave")
    after, too_late = synth(4, 0, "ws-help-01", "alice"), synth(5, 30, "ws-help-01", "alice")
    pipeline.ingest([weak, other, fixture(DECOY), after, too_late])
    (incident,) = pipeline.incidents()
    assert {e for s in incident.signals for e in s.event_ids} == {weak.id, DECOY, after.id}
    assert incident.promoted_held_signal_ids == [f"dev-{weak.id}", f"dev-{after.id}"]
    assert pipeline.status()["held_signals"] == 2  # dave's signal and the one that came too late


def test_the_quota_limits_incidents_opened_by_a_score_alone():
    pipeline = make(settings=Settings(weak=0.0, strong=0.0, non_anchor_quota=2))
    pipeline.ingest([synth(10, 0, "h1", "u1"), synth(10, 10, "h2", "u2"), synth(10, 20, "h3", "u3")])
    assert [i.id for i in pipeline.incidents()] == ["INC-0001", "INC-0002"]
    assert pipeline.status()["held_signals"] == 1
    pipeline.ingest([fixture(DECOY)])  # a certain signal is never held back
    assert len(pipeline.incidents()) == 3


def test_an_anchor_that_links_two_incidents_merges_them():
    pipeline = make(settings=Settings(weak=0.0, strong=0.0, non_anchor_quota=5))
    pipeline.ingest([synth(10, 0, "h1", "u1"), synth(10, 10, "h2", "u2")])
    assert len(pipeline.incidents()) == 2
    pipeline.ingest([synth(10, 20, "h2", "u1")])
    (incident,) = pipeline.incidents()
    assert incident.id == "INC-0001" and len(incident.signals) == 3 and pipeline.incident("INC-0002") is None


# ---------------------------------------------------------------- the ledger and the guard
def test_every_incident_is_recorded_and_a_failing_ledger_does_not_stop_detection():
    records = []
    pipeline = make(recorder=lambda kind, payload: records.append((kind, payload)))
    pipeline.ingest([fixture(DECOY)])
    assert [kind for kind, _ in records] == ["detection"]
    assert records[0][1]["incident_id"] == "INC-0001" and records[0][1]["signal_ids"] == [f"decoy-{DECOY}"]

    def down(kind, payload):
        raise RuntimeError("ledger is down")

    broken = make(recorder=down)
    assert len(broken.ingest([fixture(DECOY)])) == 1
    assert len(broken.status()["record_errors"]) == 1 and "ledger is down" in broken.status()["record_errors"][0]


def test_the_guard_gets_the_process_state_from_the_ot_events():
    pipeline = make()
    level = adapters.get("modbus").parse_line(json.dumps({
        "ts": "2026-03-04T04:40:00.000Z", "server": "plc-1", "client_ip": "10.0.3.5", "func": 3, "address": 40002, "value": 47.5}))
    (incident,) = pipeline.ingest([level, fixture(WRITE)])
    state = pipeline.process_state(incident.id)
    assert state["level"] == 47.5 and state["setpoint"] == 50.0  # the breaching write is not taken as the setpoint
    assert state["writers"]["plc-1"] == ["eng-ws-01"] and state["plc_online"]["plc-1"] is True
    assert state["pending_writes"] == [{"t": 30, "plc": "plc-1", "register": 40001, "value": 95.0, "source": "eng-ws-01"}]
    assert parse_state(state).pending_writes[0].value == 95.0  # the guard accepts it
    assert pipeline.process_state(None)["pending_writes"] == []
    assert pipeline.incident_hosts(incident.id) == ["eng-ws-01", "plc-1"]