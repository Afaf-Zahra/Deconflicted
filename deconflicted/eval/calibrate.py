"""Set the strong threshold, measure everything in docs/metrics.md and write data/eval/report.json.

  python -m deconflicted.eval.calibrate --input data/organizer --report data/eval/report.json

The data is the organizer's (grouped by day, with labels.jsonl) when --input has any, otherwise the built-in simulator
(--simulate forces it). The baseline learns from the training days. The strong threshold is the lowest one that gives at
most 0.6 x budget incidents on benign day A. Benign day B, held out, checks it. Unless --no-save is given, the trained
baseline goes to deconflicted/core/model/baseline.json and the threshold to config/calibration.yaml.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path

from deconflicted.adapters.hosts import config_dir
from deconflicted.core.baseline import Baseline
from deconflicted.core.config import CoreConfigError, load_config
from deconflicted.core.service import DEFAULT_MODEL
from deconflicted.core.settings import SettingsError, load_settings

from .data import DataError, World, load_world
from .metrics import evaluate, replay

CANDIDATES = (0.99, 0.995, 0.998, 0.999, 0.9995, 0.9998, 0.9999, 0.99995, 0.99998, 0.99999, 1.0)


def choose_threshold(events, baseline, settings, config, target: int) -> tuple[float, list[dict], bool]:
    """The lowest candidate with at most `target` incidents on these (benign) events. The quota is off for the search."""
    tried: list[dict] = []
    for candidate in CANDIDATES:
        trial = replace(settings, strong=candidate, weak=min(settings.weak, candidate), non_anchor_quota=1_000_000)
        count = len(replay(events, baseline, trial, config).incidents())
        tried.append({"strong": candidate, "incidents_on_day_a": count})
        if count <= target:
            return candidate, tried, True
    return CANDIDATES[-1], tried, False


def safety_check(cases: int, seed: int) -> dict:
    """Ayaz's zero-disruption check: many random states, every kind of action, the allowed ones applied and simulated."""
    from deconflicted.response.zero_disruption import run

    report = run(cases, seed)
    return {"cases": report.cases, "actions": report.actions, "allowed": report.allowed,
            "downgraded": report.downgraded, "blocked": report.blocked, "violations": report.violations}


def ledger_checks(directory: str | Path) -> dict:
    """A clean ledger verifies; a payload changed at any entry is found, at that entry. Throw-away in-process ledgers."""
    from deconflicted.ledger.client import LedgerClient
    from deconflicted.ledger.policy import load_policy
    from deconflicted.ledger.service import embedded_nodes

    base, policy = Path(directory), load_policy()

    def fresh(name: str) -> LedgerClient:
        folder = base / name
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
        client = LedgerClient(folder / "client.db", embedded_nodes(policy, folder / "nodes"), policy)
        for number in range(5):
            client.append("detection", {"incident_id": f"INC-{number}", "n": number})
        return client

    clean = fresh("clean")
    try:
        report = clean.verify()
        clean_ok = report.ok and report.checked >= 5
    finally:
        clean.close()
    detected = 0
    for seq in range(5):
        client = fresh(f"tamper-{seq}")
        try:
            client.tamper(seq)
            found = client.verify()
            if not found.ok and min(error.seq for error in found.errors) == seq:
                detected += 1
        finally:
            client.close()
    return {"clean_verify_ok": clean_ok, "tampers": 5, "tampers_detected_at_the_right_entry": detected}


def compare_scorer(world: World, baseline, settings, config, without: dict) -> dict:
    """Run again with the PyTorch scorer. Recommend turning it on only if nothing gets worse."""
    try:
        from deconflicted.ml.scorer import GRUScorer

        scorer = GRUScorer.load()
    except Exception as exc:  # no torch or no usable weights
        return {"evaluated": False, "reason": str(exc), "recommend_enable": False}
    with_scorer = evaluate(world, baseline, settings, config, scorer)
    worse = []
    if with_scorer["day_b"]["incidents"] > without["day_b"]["incidents"]:
        worse.append("false incidents on the held-out day")
    new, old = with_scorer["attack"], without["attack"]
    if new["chain_recall"] and old["chain_recall"] and new["chain_recall"]["mean"] < old["chain_recall"]["mean"]:
        worse.append("chain recall")
    if new["time_to_first_alert_s"] and old["time_to_first_alert_s"] \
            and new["time_to_first_alert_s"]["mean"] > old["time_to_first_alert_s"]["mean"]:
        worse.append("time to first alert")
    if new["one_incident_rate"] is not None and old["one_incident_rate"] is not None \
            and new["one_incident_rate"] < old["one_incident_rate"]:
        worse.append("one incident per attack")
    def key_numbers(result: dict) -> dict:
        attack = result["attack"]
        return {"day_b_incidents": result["day_b"]["incidents"], "one_incident_rate": attack["one_incident_rate"],
                "chain_recall_mean": attack["chain_recall"]["mean"] if attack["chain_recall"] else None,
                "time_to_first_alert_mean_s": attack["time_to_first_alert_s"]["mean"] if attack["time_to_first_alert_s"] else None}

    return {"evaluated": True, "recommend_enable": not worse, "worse": worse,
            "without_scorer": key_numbers(without), "with_scorer": key_numbers(with_scorer)}


def _entry(value, target, passed, note: str = "") -> dict:
    entry = {"value": value, "target": target, "pass": passed}
    if note:
        entry["note"] = note
    return entry


def _todo(note: str) -> dict:
    return {"value": None, "target": "TODO", "pass": None, "note": note}


def _summary(summary: dict | None, note: str) -> dict:
    if summary is None:
        return _todo(note)
    return {"mean": summary["mean"], "worst": summary["worst"], "target": "TODO", "pass": None}


def _rounded(value):
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, dict):
        return {key: _rounded(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_rounded(item) for item in value]
    return value


def build_report(world: World, settings, strong: float, tried: list[dict], met: bool, target: int, result: dict,
                 scorer: dict, safety: dict, ledger: dict) -> dict:
    budget, day_b, attack = settings.budget, result["day_b"], result["attack"]
    a_count = tried[-1]["incidents_on_day_a"]
    metrics = {
        "false_incidents_per_24h": _entry(day_b["incidents"], f"<= {budget}", day_b["incidents"] <= budget,
                                          "incidents on the held-out benign day B, with the alert budget in force"),
        "calibration_check": _entry({"day_a": a_count, "day_b": day_b["incidents"]}, f"day B <= {budget}",
                                    day_b["incidents"] <= budget, "the threshold is set on day A and checked on day B"),
        "alert_reduction": {"signals": day_b["signals"], "signals_over_threshold": day_b["signals_over_threshold"],
                            "incidents": day_b["incidents"],
                            "note": "held-out day B: what a tool alerting on every strong signal would raise, against incidents"},
    }
    if attack["scenarios"]:
        rate = attack["one_incident_rate"]
        metrics["one_incident_per_attack"] = _entry(rate, "1.0", rate == 1.0, f"{attack['scenarios']} attack scenarios")
        metrics["scenarios_missed"] = _entry(attack["missed"], "0", attack["missed"] == 0)
        metrics["chain_recall"] = _summary(attack["chain_recall"], "the attack has no labeled steps")
        metrics["time_to_first_alert_s"] = _summary(attack["time_to_first_alert_s"], "no attack was detected")
        metrics["attack_mapping_accuracy"] = _summary(attack["mapping_accuracy"], "no labeled step has a known technique")
        metrics["other_incidents_in_attack_scenarios"] = {"mean": attack["other_incidents"]["mean"],
                                                          "worst": attack["other_incidents"]["worst"]}
    else:
        for name in ("one_incident_per_attack", "scenarios_missed", "chain_recall", "time_to_first_alert_s",
                     "attack_mapping_accuracy"):
            metrics[name] = _todo("the data has no labeled attack")
    metrics["zero_disruption_violations"] = _entry(safety["violations"], "0", safety["violations"] == 0,
                                                   f"{safety['cases']} random states, {safety['actions']} actions")
    metrics["ledger_clean_verify"] = _entry(ledger["clean_verify_ok"], "true", ledger["clean_verify_ok"] is True)
    metrics["ledger_tamper_detection"] = _entry(
        f"{ledger['tampers_detected_at_the_right_entry']} of {ledger['tampers']}", "all",
        ledger["tampers_detected_at_the_right_entry"] == ledger["tampers"], "found, and at the right entry")
    return {
        "data": {"source": world.source, "train_days": world.train_days, "train_events": len(world.train),
                 "day_a_events": len(world.day_a), "day_b_events": len(world.day_b),
                 "attack_scenarios": len(world.scenarios)},
        "settings": {"budget": budget, "non_anchor_quota": settings.non_anchor_quota, "weak": min(settings.weak, strong)},
        "calibration": {"strong": strong, "target_incidents_on_day_a": target, "met_target_on_day_a": met,
                        "rule": "the lowest strong threshold with at most 0.6 x budget incidents on benign day A",
                        "candidates_tried": tried},
        "metrics": metrics,
        "scenarios": result["scenarios"],
        "scorer": scorer,
        "performance": {"events_per_sec": result["events_per_sec"],
                        "note": "this machine, the detection engine over the held-out benign day; it varies between runs"},
        "not_measured_here": ["unsafe_actions_stopped", "fail_closed", "ledger_quorum"],
        "not_measured_note": "these are covered by the pytest suites in tests/response and tests/ledger, not by this run",
    }


def _show(value) -> str:
    return "n/a" if value is None else f"{value:.4g}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deconflicted.eval.calibrate", description="Calibrate and measure")
    parser.add_argument("--input", default="data/organizer")
    parser.add_argument("--report", default="data/eval/report.json")
    parser.add_argument("--work", default="data/eval/work", help="where the simulated data is built")
    parser.add_argument("--train-days", type=int, default=8)
    parser.add_argument("--variants", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--safety-cases", type=int, default=300)
    parser.add_argument("--simulate", action="store_true", help="ignore --input and use the built-in simulator")
    parser.add_argument("--no-scorer", action="store_true", help="skip the comparison with the PyTorch scorer")
    parser.add_argument("--no-save", action="store_true", help="write the report only, not the baseline and the threshold")
    parser.add_argument("--save-model", default=str(DEFAULT_MODEL))
    parser.add_argument("--calibration", help="default: config/calibration.yaml")
    args = parser.parse_args(argv)
    try:
        config, settings = load_config(), load_settings()
        world = load_world(args.input, args.work, args.simulate, args.train_days, args.variants, args.seed)
    except (CoreConfigError, SettingsError, DataError, OSError, ValueError) as exc:
        print(f"FAILED {exc}")
        return 1
    print(f"data: {world.source}, {world.train_days} training days ({len(world.train)} events), day A {len(world.day_a)} events, "
          f"day B {len(world.day_b)} events, {len(world.scenarios)} attack scenarios")

    baseline = Baseline(config)
    baseline.fit(world.train)
    target = settings.budget * 6 // 10
    strong, tried, met = choose_threshold(world.day_a, baseline, settings, config, target)
    final = replace(settings, strong=strong, weak=min(settings.weak, strong))
    result = evaluate(world, baseline, final, config)
    scorer = ({"evaluated": False, "reason": "skipped (--no-scorer)", "recommend_enable": False} if args.no_scorer
              else compare_scorer(world, baseline, final, config, result))
    safety = safety_check(args.safety_cases, args.seed)
    ledger = ledger_checks(Path(args.work) / "ledger")
    report = build_report(world, final, strong, tried, met, target, result, scorer, safety, ledger)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(_rounded(report), indent=2) + "\n", encoding="utf-8", newline="\n")
    if not args.no_save:
        baseline.save(args.save_model)
        calibration = Path(args.calibration) if args.calibration else config_dir() / "calibration.yaml"
        calibration.parent.mkdir(parents=True, exist_ok=True)
        calibration.write_text("# Written by make calibrate: the strong threshold chosen on benign day A.\n"
                               "# Delete this file to fall back to thresholds.strong in detection.yaml.\n"
                               f"strong: {strong!r}\n", encoding="utf-8", newline="\n")

    attack, day_b = result["attack"], result["day_b"]
    print(f"strong threshold {strong} ({'meets' if met else 'DOES NOT meet'} the target of at most {target} incidents on day A: "
          f"{tried[-1]['incidents_on_day_a']})")
    print(f"held-out day B: {day_b['incidents']} incidents (budget {settings.budget}); {day_b['signals']} signals, "
          f"{day_b['signals_over_threshold']} of them over the threshold")
    if attack["scenarios"]:
        recall, first = attack["chain_recall"], attack["time_to_first_alert_s"]
        print(f"attacks ({attack['scenarios']} scenarios): one incident in {_show(attack['one_incident_rate'])} of them, "
              f"{attack['missed']} missed; chain recall mean {_show(recall and recall['mean'])} worst {_show(recall and recall['worst'])}; "
              f"time to first alert mean {_show(first and first['mean'])} s worst {_show(first and first['worst'])} s")
    print(f"safety: {safety['violations']} violations in {safety['cases']} cases; ledger: clean verify {ledger['clean_verify_ok']}, "
          f"tampers found {ledger['tampers_detected_at_the_right_entry']} of {ledger['tampers']}")
    if scorer["evaluated"]:
        print("scorer: " + ("turn it on (nothing got worse)" if scorer["recommend_enable"]
                            else "keep it off (worse: " + ", ".join(scorer["worse"]) + ")"))
    else:
        print(f"scorer: not evaluated ({scorer['reason']})")
    print(f"report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())