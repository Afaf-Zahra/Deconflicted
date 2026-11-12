"""See what the detection checks think of a log.

  python -m deconflicted.core.explain --train data/benign --show data/demo/scenario.jsonl
  python -m deconflicted.core.explain --train data/benign --save deconflicted/core/model/baseline.json
  python -m deconflicted.core.explain --model deconflicted/core/model/baseline.json --show data/demo/scenario.jsonl

The most unusual events of the shown file are listed with the routine and invariant checks beside them. When a
labels.jsonl sits next to the shown file, the attack events are listed with their rank (ties are ordered by time).
Nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deconflicted.ingest.load import read_path

from .baseline import Baseline, BaselineError
from .config import CoreConfigError, load_config
from .entities import acting_host
from .invariants import Invariants
from .routines import RoutineRegistry

HEADER = "rank  time      score   why       actor                 behaviour               routine  rule"


def _labels(show: Path, given: str | None) -> dict[str, int | None]:
    path = Path(given) if given else (show.parent if show.is_file() else show) / "labels.jsonl"
    steps: dict[str, int | None] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                if item.get("attack"):
                    steps[item["id"]] = item.get("step")
    return steps


def _row(rank: int, row: tuple, labels: dict[str, int | None]) -> str:
    event, obs, routine, signal = row
    rule = signal.detail["rule"] if signal else "-"
    mark = ""
    if event.id in labels:
        mark = f"  <- attack step {labels[event.id] if labels[event.id] is not None else '?'}"
    return (f"{rank:>4}  {event.ts:%H:%M:%S}  {obs.score:.4f}  {obs.reason:<8}  {obs.actor:<20}  "
            f"{obs.token:<22}  {routine.status:<7}  {rule:<16}{mark}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deconflicted.core.explain", description="Explain the detection checks")
    parser.add_argument("--train", help="benign logs (a file or a folder) to learn from")
    parser.add_argument("--model", help="a saved baseline to use instead of --train")
    parser.add_argument("--save", help="write the learned baseline here")
    parser.add_argument("--show", help="the log file or folder to explain")
    parser.add_argument("--labels", help="labels.jsonl (default: the one next to --show)")
    parser.add_argument("--top", type=int, default=12, help="how many of the most unusual events to list")
    args = parser.parse_args(argv)
    if not args.train and not args.model:
        parser.error("give --train or --model")
    try:
        config = load_config()
        if args.model:
            baseline = Baseline.load(args.model, config)
            print(f"loaded the baseline from {args.model} ({baseline.trained_events} training events)")
        else:
            events, report = read_path(args.train)
            if not events:
                print("FAILED no events to learn from")
                return 1
            baseline = Baseline(config)
            used = baseline.fit(events)
            print(f"learned from {used} events in {len(report.files)} files; {len(baseline.vocab)} behaviours")
        if args.save:
            baseline.save(args.save)
            print(f"saved the baseline to {args.save}")
        if not args.show:
            return 0
        shown, _ = read_path(args.show)
        labels = _labels(Path(args.show), args.labels)
    except (CoreConfigError, BaselineError, OSError, ValueError) as exc:
        print(f"FAILED {exc}")
        return 1

    routines, invariants = RoutineRegistry(config), Invariants(config)
    baseline.reset()
    rows = []
    for event in shown:
        obs = baseline.observe(event)
        routine = routines.check(obs.token, obs.actor, obs.role, acting_host(event), event.ts)
        rows.append((event, obs, routine, invariants.check(event)))
    order = sorted(range(len(rows)), key=lambda i: (-rows[i][1].score, rows[i][0].ts))
    rank = {index: place for place, index in enumerate(order, start=1)}
    print(f"\nthe {min(args.top, len(rows))} most unusual of {len(rows)} events")
    print(HEADER)
    for index in order[: args.top]:
        print(_row(rank[index], rows[index], labels))
    marked = sorted((i for i, row in enumerate(rows) if row[0].id in labels), key=lambda i: rows[i][0].ts)
    if marked:
        print("\nthe attack events")
        print(HEADER)
        for index in marked:
            print(_row(rank[index], rows[index], labels))
    return 0


if __name__ == "__main__":
    sys.exit(main())