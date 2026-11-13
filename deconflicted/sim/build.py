"""Builds the demo and evaluation data.   python -m deconflicted.sim.build --out data

  data/benign/<date>.jsonl        benign days before the attack day, for baselines, calibration and the scorer
  data/demo/scenario.jsonl        the attack day around the attack, for the replay container
  data/demo/labels.jsonl          which events are the attack (id, attack, step); never shown to the detector
  data/demo/scenario_full.jsonl   the whole attack day (only with --full)

Every file is one {"source": ..., "raw": ...} object per line, in time order: the replay format.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, time, timedelta
from pathlib import Path

from deconflicted import adapters
from deconflicted.adapters.common import make_id
from deconflicted.sim.attack.script import ATTACK_DAY, Step, attack_steps, distractor_steps, pivot_steps
from deconflicted.sim.roles import day_lines

Row = tuple[datetime, str, str, int | None]  # time, source, raw line, attack step (None for background)


def build_day(day: date, seed: int, extra: list[Step] | None = None) -> list[Row]:
    """One day of benign traffic from the role scripts, with any extra steps mixed in, in time order."""
    rows: list[Row] = [(adapters.get(source).parse_line(raw).ts, source, raw, None) for source, raw in day_lines(day, seed)]
    rows += [(step.ts, step.source, step.raw, step.step) for step in extra or []]
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    return rows


def write_lines(path: Path, rows: list[Row]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for _, source, raw, _ in rows:
            handle.write(json.dumps({"source": source, "raw": raw}, separators=(",", ":")) + "\n")


def write_labels(path: Path, rows: list[Row]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for _, source, raw, step in rows:
            if step is not None:
                handle.write(json.dumps({"id": make_id(source, raw), "attack": True, "step": step}) + "\n")


def _window(rows: list[Row], text: str | None) -> list[Row]:
    attack = [row[0] for row in rows if row[3] is not None]
    if text:
        low, high = (time.fromisoformat(part) for part in text.split("-"))
        return [row for row in rows if low <= row[0].time() <= high]
    low, high = min(attack) - timedelta(minutes=10), max(attack) + timedelta(minutes=10)
    return [row for row in rows if low <= row[0] <= high]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the benign days and the attack scenario")
    parser.add_argument("--out", default="data")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--day", default=ATTACK_DAY.isoformat(), help="the attack day")
    parser.add_argument("--benign-days", type=int, default=8, help="benign days before the attack day")
    parser.add_argument("--variant", type=int, default=None, help="build a repeatable variant of the attack")
    parser.add_argument("--window", default=None, help="HH:MM-HH:MM of the demo file (default: the attack plus 10 minutes each side)")
    parser.add_argument("--no-distractors", action="store_true", help="leave out the unusual but harmless svc-backup activity")
    parser.add_argument("--full", action="store_true", help="also write the whole attack day")
    args = parser.parse_args(argv)
    day, out = date.fromisoformat(args.day), Path(args.out)
    for back in range(args.benign_days, 0, -1):
        benign_day = day - timedelta(days=back)
        write_lines(out / "benign" / f"{benign_day.isoformat()}.jsonl", build_day(benign_day, args.seed + back))
    attack = attack_steps(day, args.variant)
    extra = attack + pivot_steps(attack) + ([] if args.no_distractors else distractor_steps(day))
    rows = build_day(day, args.seed, extra)
    demo = _window(rows, args.window)
    write_lines(out / "demo" / "scenario.jsonl", demo)
    write_labels(out / "demo" / "labels.jsonl", rows)
    if args.full:
        write_lines(out / "demo" / "scenario_full.jsonl", rows)
    print(f"{args.benign_days} benign days, scenario of {len(demo)} lines "
          f"({demo[0][0].time().isoformat()} to {demo[-1][0].time().isoformat()} UTC), "
          f"{sum(1 for row in rows if row[3] is not None)} labeled attack events")
    return 0


if __name__ == "__main__":
    sys.exit(main())