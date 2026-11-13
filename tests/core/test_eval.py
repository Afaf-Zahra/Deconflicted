import contextlib
import io
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deconflicted import adapters
from deconflicted.core.baseline import Baseline
from deconflicted.core.config import load_config
from deconflicted.core.settings import Settings, SettingsError, load_settings
from deconflicted.eval.calibrate import CANDIDATES, choose_threshold, ledger_checks, safety_check
from deconflicted.eval.calibrate import main as calibrate
from deconflicted.eval.data import DataError, Scenario, organizer_world, simulated_world
from deconflicted.eval.intake import main as intake
from deconflicted.eval.metrics import aggregate, attack_metrics, replay
from deconflicted.schema import Event
from deconflicted.sim.build import main as build

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}
DECOY, WRITE, CLEAR = "flow-c7621933881f", "modbus-06e981d9288c", "windows-46ff3d489abb"
CONFIG = load_config()


def fixture(event_id):
    return Event(**{k: v for k, v in FIXTURES[event_id].items() if k != "label"})


def quiet(func, argv):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = func(argv)
    return code, buffer.getvalue()


# ---------------------------------------------------------------- intake
def test_intake_reads_a_folder_and_reports_the_answer_key(tmp_path):
    quiet(build, ["--out", str(tmp_path / "data"), "--benign-days", "1"])
    out = tmp_path / "intake.json"
    code, text = quiet(intake, ["--input", str(tmp_path / "data" / "demo"), "--out", str(out), "--mappings", str(tmp_path / "none")])
    assert code == 0 and "answer key" in text
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["events"] == 186 and summary["lines_skipped"] == 0 and summary["unrecognized"] == []
    assert summary["labels"] == {"attack_events": 6, "found_in_logs": 6}
    assert summary["days"] == {"2026-03-04": 186}


def test_intake_fails_clearly_without_data(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / ".gitkeep").write_text("", encoding="utf-8")
    for folder in (empty, tmp_path / "missing"):
        code, text = quiet(intake, ["--input", str(folder), "--out", str(tmp_path / "x.json")])
        assert code == 1 and "FAILED" in text
    assert not (tmp_path / "x.json").exists()


# ---------------------------------------------------------------- metrics
def test_attack_metrics_count_steps_time_and_techniques():
    scenario = Scenario("two certain steps", [fixture(DECOY), fixture(WRITE)], {DECOY: 3, WRITE: 9})
    pipeline = replay(scenario.events, Baseline(CONFIG), Settings(), CONFIG)
    assert attack_metrics(pipeline, scenario) == {
        "incidents_with_attack": 2, "other_incidents": 0, "one_incident": False, "chain_recall": 1.0,
        "time_to_first_alert_s": 0.0, "mapping_accuracy": 1.0}


def test_an_attack_that_is_missed_scores_zero():
    event = Event(id="windows-eval0001", ts=datetime(2026, 3, 4, 3, 40, tzinfo=timezone.utc), source="windows",
                  host="ws-help-01", user="alice", process="tool.exe", cmdline="tool.exe run", action="proc_create", raw="x")
    scenario = Scenario("missed", [event], {event.id: 1})
    result = attack_metrics(replay(scenario.events, Baseline(CONFIG), Settings(), CONFIG), scenario)
    assert (result["incidents_with_attack"], result["chain_recall"], result["time_to_first_alert_s"],
            result["mapping_accuracy"]) == (0, 0.0, None, 0.0)


def test_aggregate_gives_the_mean_and_the_worst_case():
    good = {"incidents_with_attack": 1, "other_incidents": 0, "one_incident": True, "chain_recall": 1.0,
            "time_to_first_alert_s": 100.0, "mapping_accuracy": 1.0}
    bad = {"incidents_with_attack": 0, "other_incidents": 2, "one_incident": False, "chain_recall": 0.5,
           "time_to_first_alert_s": None, "mapping_accuracy": 0.5}
    summary = aggregate([good, bad])
    assert summary["scenarios"] == 2 and summary["missed"] == 1 and summary["one_incident_rate"] == 0.5
    assert summary["chain_recall"] == {"mean": 0.75, "worst": 0.5}
    assert summary["time_to_first_alert_s"] == {"mean": 100.0, "worst": 100.0}
    assert summary["other_incidents"] == {"mean": 1, "worst": 2}
    empty = aggregate([])
    assert empty["one_incident_rate"] is None and empty["chain_recall"] is None and empty["other_incidents"] is None


# ---------------------------------------------------------------- the threshold search
def test_the_threshold_search_takes_the_lowest_candidate_that_fits():
    chosen, tried, met = choose_threshold([fixture(DECOY)], Baseline(CONFIG), Settings(), CONFIG, 3)
    assert (chosen, met) == (CANDIDATES[0], True)
    assert tried == [{"strong": CANDIDATES[0], "incidents_on_day_a": 1}]


def test_the_threshold_search_says_so_when_nothing_fits():
    stray = adapters.get("flow").parse_line("2026-03-04T05:00:00Z,10.0.3.8,10.0.2.99,445,tcp,100,1")
    day = [fixture(DECOY), fixture(WRITE), fixture(CLEAR), stray]  # four certain signals on four separate entities
    chosen, tried, met = choose_threshold(day, Baseline(CONFIG), Settings(), CONFIG, 3)
    assert (chosen, met, len(tried)) == (1.0, False, len(CANDIDATES))
    assert all(item["incidents_on_day_a"] == 4 for item in tried)


# ---------------------------------------------------------------- the data
def test_the_simulated_world_has_training_days_two_test_days_and_the_attacks(tmp_path):
    world = simulated_world(tmp_path / "work", train_days=3, variants=2)
    assert world.source == "simulated" and world.train_days == 3
    assert len(world.train) > 3 * 15000 and len(world.day_a) > 15000 and len(world.day_b) > 15000
    assert [s.name for s in world.scenarios] == ["main attack", "variant 1", "variant 2"]
    assert all(sorted(s.labels.values()) == [1, 2, 3, 3, 7, 9] for s in world.scenarios)
    assert len(world.scenarios[0].events) == 186
    assert max(e.ts for e in world.train) < min(e.ts for e in world.day_a) < min(e.ts for e in world.day_b)


def test_the_organizer_world_groups_events_by_day_and_reads_the_labels(tmp_path):
    quiet(build, ["--out", str(tmp_path / "sim"), "--benign-days", "4"])
    organizer = tmp_path / "organizer"
    shutil.copytree(tmp_path / "sim" / "benign", organizer / "benign")
    shutil.copy(tmp_path / "sim" / "demo" / "scenario.jsonl", organizer / "scenario.jsonl")
    shutil.copy(tmp_path / "sim" / "demo" / "labels.jsonl", organizer / "labels.jsonl")
    world = organizer_world(organizer)
    assert world.source == "organizer" and world.train_days == 2
    assert len(world.scenarios) == 1 and sorted(world.scenarios[0].labels.values()) == [1, 2, 3, 3, 7, 9]
    assert len(world.scenarios[0].events) == 186 and len(world.day_a) > 15000
    sorted((organizer / "benign").glob("*.jsonl"))[0].unlink()
    with pytest.raises(DataError, match="at least 4"):
        organizer_world(organizer)


# ---------------------------------------------------------------- safety, ledger, settings, the whole run
def test_the_ledger_and_the_safety_checks_pass(tmp_path):
    assert ledger_checks(tmp_path) == {"clean_verify_ok": True, "tampers": 5, "tampers_detected_at_the_right_entry": 5}
    safety = safety_check(20, 1)
    assert safety["violations"] == 0 and safety["cases"] == 20 and safety["actions"] == 180


def test_the_calibrated_threshold_overrides_detection_yaml(tmp_path):
    (tmp_path / "detection.yaml").write_text("thresholds:\n  strong: 0.999\n", encoding="utf-8")
    assert load_settings(tmp_path).strong == 0.999
    (tmp_path / "calibration.yaml").write_text("# written by make calibrate\nstrong: 0.99995\n", encoding="utf-8")
    assert load_settings(tmp_path).strong == 0.99995
    (tmp_path / "calibration.yaml").write_text("strong: 2\n", encoding="utf-8")
    with pytest.raises(SettingsError):
        load_settings(tmp_path)


def test_calibrate_writes_a_complete_report(tmp_path):
    report_path = tmp_path / "report.json"
    code, text = quiet(calibrate, ["--simulate", "--work", str(tmp_path / "work"), "--report", str(report_path),
                                   "--train-days", "3", "--variants", "2", "--safety-cases", "20", "--no-scorer", "--no-save"])
    assert code == 0 and "report written" in text
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["data"]["source"] == "simulated" and report["data"]["attack_scenarios"] == 3
    assert report["calibration"]["strong"] in CANDIDATES
    metrics = report["metrics"]
    assert {"false_incidents_per_24h", "calibration_check", "one_incident_per_attack", "chain_recall",
            "time_to_first_alert_s", "attack_mapping_accuracy"} <= set(metrics)
    assert metrics["zero_disruption_violations"]["value"] == 0 and metrics["zero_disruption_violations"]["pass"] is True
    assert metrics["ledger_tamper_detection"]["pass"] is True and report["scorer"]["evaluated"] is False