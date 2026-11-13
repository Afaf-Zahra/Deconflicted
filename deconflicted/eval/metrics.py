"""The numbers of docs/metrics.md for one run of the detection engine over a benign day or an attack scenario."""
from __future__ import annotations

import time
from statistics import mean

from deconflicted.core.baseline import Baseline
from deconflicted.core.config import CoreConfig
from deconflicted.core.pipeline import CERTAIN, Pipeline
from deconflicted.core.settings import Settings
from deconflicted.deception import DecoyRegistry, DecoyTrigger
from deconflicted.schema import Event

from .data import Scenario, World

# The ATT&CK technique of each label step (docs/scenario.md). Steps that are not listed are not scored for the mapping.
EXPECTED_TECHNIQUE = {1: "T1078", 2: "T1059.001", 3: "T1018", 7: "T1070.001", 9: "T0836"}


def replay(events: list[Event], baseline: Baseline, settings: Settings, config: CoreConfig, scorer=None) -> Pipeline:
    """A fresh pipeline that has taken all the events."""
    pipeline = Pipeline(config=config, baseline=baseline, settings=settings, scorer=scorer,
                        decoy_trigger=DecoyTrigger(DecoyRegistry()))
    pipeline.ingest(events)
    return pipeline


def day_stats(pipeline: Pipeline) -> dict:
    """Incidents against the signals a tool without correlation and budget would have alerted on."""
    incidents = pipeline.incidents()
    signals = [signal for incident in incidents for signal in incident.signals] + list(pipeline._held.values())  # on purpose
    strong = pipeline.settings.strong
    over = [s for s in signals if s.kind in CERTAIN or (s.kind in ("role_deviation", "routine_break") and s.score >= strong)]
    return {"incidents": len(incidents), "signals": len(signals), "signals_over_threshold": len(over)}


def attack_metrics(pipeline: Pipeline, scenario: Scenario) -> dict:
    labels = scenario.labels
    incidents = pipeline.incidents()
    hit = [i for i in incidents if labels.keys() & {e for s in i.signals for e in s.event_ids}]
    all_steps = {step for step in labels.values() if step is not None}
    found: set[str] = set()
    matches = 0
    for incident in hit:
        by_signal = {step.signal_id: step for step in incident.chain}
        for signal in incident.signals:
            for event_id in signal.event_ids:
                if event_id in labels and event_id not in found:
                    found.add(event_id)
                    expected = EXPECTED_TECHNIQUE.get(labels[event_id])
                    if expected and by_signal[signal.id].technique == expected:
                        matches += 1
    found_steps = {labels[event_id] for event_id in found if labels[event_id] is not None}
    scored = sum(1 for step in labels.values() if step in EXPECTED_TECHNIQUE)
    starts = [e.ts for e in scenario.events if e.id in labels]
    alerts = [i.first_alert_ts for i in hit if i.first_alert_ts is not None]
    return {
        "incidents_with_attack": len(hit),
        "other_incidents": len(incidents) - len(hit),
        "one_incident": len(hit) == 1,
        "chain_recall": len(found_steps & all_steps) / len(all_steps) if all_steps else None,
        "time_to_first_alert_s": max(0.0, (min(alerts) - min(starts)).total_seconds()) if alerts and starts else None,
        "mapping_accuracy": matches / scored if scored else None,
    }


def aggregate(results: list[dict]) -> dict:
    """The mean and the worst case over the scenarios."""
    def summary(key: str, worst) -> dict | None:
        found = [r[key] for r in results if r[key] is not None]
        return {"mean": mean(found), "worst": worst(found)} if found else None

    others = [r["other_incidents"] for r in results]
    return {
        "scenarios": len(results),
        "missed": sum(1 for r in results if r["incidents_with_attack"] == 0),
        "one_incident_rate": mean(1.0 if r["one_incident"] else 0.0 for r in results) if results else None,
        "chain_recall": summary("chain_recall", min),
        "time_to_first_alert_s": summary("time_to_first_alert_s", max),
        "mapping_accuracy": summary("mapping_accuracy", min),
        "other_incidents": {"mean": mean(others), "worst": max(others)} if others else None,
    }


def evaluate(world: World, baseline: Baseline, settings: Settings, config: CoreConfig, scorer=None) -> dict:
    """The held-out benign day and every attack scenario, with these settings."""
    started = time.perf_counter()
    day = replay(world.day_b, baseline, settings, config, scorer)
    seconds = time.perf_counter() - started
    results = [attack_metrics(replay(s.events, baseline, settings, config, scorer), s) for s in world.scenarios]
    return {"day_b": day_stats(day), "events_per_sec": len(world.day_b) / seconds if seconds > 0 else None,
            "attack": aggregate(results), "scenarios": {s.name: r for s, r in zip(world.scenarios, results)}}