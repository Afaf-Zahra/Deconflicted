"""Train the scorer on benign days.

  python -m deconflicted.ml.train --days data/benign --out deconflicted/ml/weights
  python -m deconflicted.ml.train --simulate 3 --out deconflicted/ml/weights

--days reads *.jsonl files with one {"source": ..., "raw": ...} object per line (the replay format).
--simulate N builds N benign days from the role scripts instead.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import defaultdict
from pathlib import Path

from deconflicted import adapters
from deconflicted.sim.roles import day_lines

from .scorer import DEFAULT_DIR, ScorerError, train
from .tokens import entity_of, event_token


def sequences_from_lines(lines: list[tuple[str, str]]) -> list[list[str]]:
    """One token sequence per entity, in time order."""
    events = sorted((adapters.get(s).parse_line(r) for s, r in lines), key=lambda e: (e.ts, e.id))
    per_entity: dict[str, list[str]] = defaultdict(list)
    for event in events:
        per_entity[entity_of(event)].append(event_token(event))
    return [tokens for _, tokens in sorted(per_entity.items())]


def read_days(directory: str | Path) -> list[tuple[str, str]]:
    lines = []
    for path in sorted(Path(directory).glob("*.jsonl")):
        for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if text.strip():
                try:
                    item = json.loads(text)
                    lines.append((item["source"], item["raw"]))
                except (json.JSONDecodeError, KeyError) as exc:
                    raise ScorerError(f"{path}:{number}: not a replay line ({exc})") from exc
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the Deconflicted scorer")
    parser.add_argument("--days", help="folder of benign *.jsonl files")
    parser.add_argument("--simulate", type=int, default=0, help="build this many benign days from the role scripts")
    parser.add_argument("--out", default=str(DEFAULT_DIR))
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    sequences: list[list[str]] = []
    if args.days:
        sequences += sequences_from_lines(read_days(args.days))
    start = datetime.date(2026, 3, 1)
    for n in range(args.simulate):
        sequences += sequences_from_lines(day_lines(start + datetime.timedelta(days=n), args.seed + n))
    if not sequences:
        print("nothing to train on: pass --days or --simulate")
        return 1
    try:
        report = train(sequences, args.out, epochs=args.epochs, seed=args.seed)
    except ScorerError as exc:
        print(f"FAILED {exc}")
        return 1
    print(f"trained on {report.sequences} sequences, {report.windows} windows, vocabulary {report.vocab_size}, "
          f"final loss {report.final_loss:.4f}, {report.seconds:.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
