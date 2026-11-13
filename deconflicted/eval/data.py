"""The data the evaluation runs on: benign days to learn from and to test on, and attack scenarios with their labels."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from deconflicted.adapters.hosts import config_dir
from deconflicted.ingest.load import read_path
from deconflicted.ingest.mapper import load_mappings
from deconflicted.schema import Event
from deconflicted.sim.build import main as build


class DataError(ValueError):
    """The data cannot be used for the evaluation. The message says why."""


@dataclass
class Scenario:
    name: str
    events: list[Event]
    labels: dict[str, int | None]  # event id -> step, for the attack events only


@dataclass
class World:
    source: str  # "simulated" or "organizer"
    train: list[Event]  # benign days the baseline learns from
    train_days: int
    day_a: list[Event]  # a benign day: the strong threshold is set on it
    day_b: list[Event]  # another benign day, held out: the threshold is checked on it
    scenarios: list[Scenario] = field(default_factory=list)  # the main attack first, then its variants


def read_labels(path: str | Path) -> dict[str, int | None]:
    """labels.jsonl: one {"id", "attack", "step"} per line. Returns the attack events and their steps."""
    steps: dict[str, int | None] = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                item = json.loads(line)
                if item.get("attack"):
                    steps[str(item["id"])] = item.get("step")
            except (json.JSONDecodeError, KeyError, AttributeError) as exc:
                raise DataError(f"{path}:{number}: not a label line ({exc})") from exc
    return steps


def _build(argv: list[str]) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        build(argv)


def _scenario(name: str, folder: Path) -> Scenario:
    return Scenario(name, read_path(folder / "demo" / "scenario.jsonl")[0], read_labels(folder / "demo" / "labels.jsonl"))


def simulated_world(work: str | Path, train_days: int = 8, variants: int = 10, seed: int = 1) -> World:
    """Build the data with sim/build.py: train_days + 2 benign days, the main attack and its variants."""
    work = Path(work)
    for old in [work / "main", *work.glob("variant-*")]:
        shutil.rmtree(old, ignore_errors=True)
    _build(["--out", str(work / "main"), "--benign-days", str(train_days + 2), "--seed", str(seed)])
    days = [read_path(path)[0] for path in sorted((work / "main" / "benign").glob("*.jsonl"))]
    scenarios = [_scenario("main attack", work / "main")]
    for number in range(1, variants + 1):
        folder = work / f"variant-{number}"
        _build(["--out", str(folder), "--benign-days", "0", "--variant", str(number), "--seed", str(seed)])
        scenarios.append(_scenario(f"variant {number}", folder))
    return World("simulated", [e for day in days[:-2] for e in day], train_days, days[-2], days[-1], scenarios)


def organizer_world(path: str | Path, year: int = 2026) -> World:
    """The organizer's data grouped by UTC day. Days with labeled attack events are scenarios, the others are benign."""
    root = Path(path)
    events, _ = read_path(root, mappings=load_mappings(config_dir() / "mappings"), year=year)
    labels_file = root / "labels.jsonl"
    labels = read_labels(labels_file) if labels_file.is_file() else {}
    by_day: dict = defaultdict(list)
    for event in events:
        by_day[event.ts.date()].append(event)
    attack_days = sorted(day for day, items in by_day.items() if any(e.id in labels for e in items))
    benign_days = sorted(day for day in by_day if day not in attack_days)
    if len(benign_days) < 4:
        raise DataError(f"{root} has {len(benign_days)} benign days; the evaluation needs at least 4 "
                        "(training days, a threshold day and a held-out day)")
    scenarios = []
    for day in attack_days:
        ids = {e.id for e in by_day[day]}
        scenarios.append(Scenario(f"attack day {day.isoformat()}", by_day[day],
                                  {key: step for key, step in labels.items() if key in ids}))
    train = [e for day in benign_days[:-2] for e in by_day[day]]
    return World("organizer", train, len(benign_days) - 2, by_day[benign_days[-2]], by_day[benign_days[-1]], scenarios)


def load_world(input_dir: str | Path, work: str | Path, simulate: bool = False, train_days: int = 8,
               variants: int = 10, seed: int = 1) -> World:
    """The organizer's data when the folder has any, otherwise the built-in simulator."""
    root = Path(input_dir)
    has_data = root.is_dir() and any(
        p.is_file() and p.name != "labels.jsonl" and not any(part.startswith(".") for part in p.relative_to(root).parts)
        for p in root.rglob("*"))
    if has_data and not simulate:
        return organizer_world(root)
    if not simulate:
        print(f"no organizer data in {root}: using the built-in simulator")
    return simulated_world(work, train_days, variants, seed)