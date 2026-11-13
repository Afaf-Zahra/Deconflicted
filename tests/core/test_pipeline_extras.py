import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deconflicted.adapters.hosts import config_dir
from deconflicted.core.baseline import Baseline
from deconflicted.core.config import load_config
from deconflicted.core.pipeline import Pipeline
from deconflicted.core.settings import SettingsError, load_settings
from deconflicted.deception import DecoyRegistry, DecoyTrigger
from deconflicted.ledger import service as ledger_service
from deconflicted.ledger.integrity import ConfigIntegrity
from deconflicted.schema import Event, Signal

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}
DECOY = "flow-c7621933881f"
CONFIG = load_config()
PROBLEM = "config/safety_rules.yaml does not match the ledger"
_numbers = iter(range(1, 10**9))


def fixture(event_id):
    return Event(**{k: v for k, v in FIXTURES[event_id].items() if k != "label"})


def synth(hour, minute, host, user, cmdline="tool.exe run"):
    n = next(_numbers)
    return Event(id=f"windows-q{n:08d}", ts=datetime(2026, 3, 4, hour, minute, tzinfo=timezone.utc), source="windows",
                 host=host, user=user, process=cmdline.split()[0], cmdline=cmdline, action="proc_create", raw=f"synthetic {n}")


def make(**options):
    return Pipeline(config=CONFIG, baseline=Baseline(CONFIG), decoy_trigger=DecoyTrigger(DecoyRegistry()), **options)


def integrity_signal():
    return Signal(id="integrity-abc123", ts=datetime(2030, 1, 1, tzinfo=timezone.utc), entity_ids=["host:ledger"],
                  kind="integrity_violation", score=1.0, event_ids=[], techniques=["T1562"], detail={"problems": [PROBLEM]})


# ---------------------------------------------------------------- integrity
def test_a_config_change_becomes_a_critical_incident_at_the_log_time():
    state = {"signals": []}
    pipeline = make(integrity_check=lambda: list(state["signals"]), integrity_interval=0)
    pipeline.ingest([fixture(DECOY)])
    assert [i.id for i in pipeline.incidents()] == ["INC-0001"]  # only the decoy hit so far
    state["signals"] = [integrity_signal()]
    assert [i.id for i in pipeline.ingest([])] == ["INC-0002"]
    incident = pipeline.incident("INC-0002")
    assert incident.severity == "critical" and incident.title == f"Protected configuration changed: {PROBLEM}"
    assert incident.signals[0].ts == fixture(DECOY).ts  # the log time, not the clock of this machine
    assert (incident.chain[0].tactic, incident.chain[0].technique) == ("Defense Evasion", "T1562")
    assert incident.chain[0].description == PROBLEM and incident.proposed_actions == []
    assert pipeline.ingest([]) == []  # the same problem is not raised again
    state["signals"] = []
    pipeline.ingest([])  # fixed: nothing breaks and the incident stays for the analyst
    assert len(pipeline.incidents()) == 2


def test_a_config_change_shows_up_without_any_event_and_counts_toward_the_budget():
    pipeline = make(integrity_check=lambda: [integrity_signal()], integrity_interval=0)
    assert [i.severity for i in pipeline.incidents()] == ["critical"]
    assert pipeline.budget().used == 1
    assert pipeline.ingest([fixture(DECOY)])[0].id == "INC-0002"  # old log times still work afterwards


def test_a_real_config_edit_is_detected_through_the_ledger(tmp_path, monkeypatch):
    monkeypatch.delenv("DECONFLICTED_LEDGER_NODES", raising=False)
    monkeypatch.setenv("DECONFLICTED_LEDGER_EMBEDDED", "1")
    monkeypatch.setenv("DECONFLICTED_LEDGER_DB", str(tmp_path / "client.db"))
    client = ledger_service.build_client()
    try:
        root = tmp_path / "repo"
        shutil.copytree(config_dir(), root / "config")
        integrity = ConfigIntegrity(client, client.policy, root=root)
        integrity.ensure_anchor()
        pipeline = make(integrity_check=integrity.check, integrity_interval=0)
        assert pipeline.incidents() == []
        rules = root / "config" / "safety_rules.yaml"
        original = rules.read_bytes()
        rules.write_bytes(original + b"\n# loosened\n")
        (incident,) = pipeline.incidents()
        assert incident.severity == "critical" and "config/safety_rules.yaml" in incident.title
        rules.write_bytes(original)
        assert pipeline.ingest([]) == []
        assert any(entry.kind == "detection" for entry in client.entries(limit=50))
    finally:
        client.close()


# ---------------------------------------------------------------- the scorer
class FakeScorer:
    def __init__(self):
        self.calls = []

    def score(self, entity_id, tokens):
        self.calls.append((entity_id, tuple(tokens)))
        return 1.0 if tokens[-1] == "proc:powershell_enc" else 0.0


def test_the_scorer_only_supports_it_never_opens_an_incident():
    scorer = FakeScorer()
    pipeline = make(scorer=scorer)
    quiet, odd = synth(3, 40, "ws-help-01", "alice"), synth(3, 43, "ws-help-01", "alice", "powershell.exe -enc AAAA")
    assert pipeline.ingest([quiet, odd]) == []
    assert scorer.calls == [("user:alice", ("proc:tool",)), ("user:alice", ("proc:tool", "proc:powershell_enc"))]
    assert pipeline.status()["held_signals"] == 1 and pipeline.status()["scorer"] == "on"
    (incident,) = pipeline.ingest([fixture(DECOY)])
    assert incident.promoted_held_signal_ids == [f"ml-{odd.id}"]
    assert [s.kind for s in incident.signals] == ["scorer_anomaly", "decoy_hit"]


def test_a_scorer_that_fails_is_switched_off_and_detection_goes_on():
    class Broken:
        def score(self, entity_id, tokens):
            raise RuntimeError("weights corrupted")

    pipeline = make(scorer=Broken())
    assert len(pipeline.ingest([synth(3, 43, "ws-help-01", "alice"), fixture(DECOY)])) == 1
    assert pipeline.status()["scorer"].startswith("off: failed") and "weights corrupted" in pipeline.status()["scorer"]


def test_the_scorer_settings_are_read_and_checked(tmp_path):
    assert (load_settings(tmp_path).scorer_enabled, load_settings(tmp_path).scorer_weak) == (False, 0.99)
    (tmp_path / "detection.yaml").write_text("scorer:\n  enabled: true\n  weak: 0.95\n", encoding="utf-8")
    settings = load_settings(tmp_path)
    assert settings.scorer_enabled is True and settings.scorer_weak == 0.95 and settings.strong == 0.9999
    (tmp_path / "detection.yaml").write_text("scorer:\n  weak: 1.5\n", encoding="utf-8")
    with pytest.raises(SettingsError, match="scorer"):
        load_settings(tmp_path)