"""Check the organizer's data.   python -m deconflicted.eval.intake --input data/organizer

Reads every file with the format sniffer and the mappings (docs/ingest.md), prints what was found and writes a summary to
data/eval/intake.json. A labels.jsonl in the folder (one {"id", "attack", "step"} per line) is read as the answer key.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from deconflicted.adapters.hosts import config_dir
from deconflicted.ingest.load import read_path
from deconflicted.ingest.mapper import MappingError, load_mappings

from .data import DataError, read_labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deconflicted.eval.intake", description="Check the organizer's data")
    parser.add_argument("--input", default="data/organizer")
    parser.add_argument("--out", default="data/eval/intake.json")
    parser.add_argument("--mappings")
    parser.add_argument("--year", type=int, default=2026)
    args = parser.parse_args(argv)
    root = Path(args.input)
    try:
        mappings = load_mappings(args.mappings or config_dir() / "mappings")
        events, report = read_path(root, mappings=mappings, year=args.year)
        labels_file = (root if root.is_dir() else root.parent) / "labels.jsonl"
        labels = read_labels(labels_file) if labels_file.is_file() else {}
    except (MappingError, DataError, OSError, ValueError) as exc:
        print(f"FAILED {exc}")
        return 1
    if not report.files:
        print(f"FAILED no files in {root}: put the organizer's logs there, or run make calibrate to use the built-in simulator")
        return 1
    for item in report.files:
        if Path(item.path).name == "labels.jsonl":
            print(f"{item.path}: answer key ({len(labels)} attack events)")
            continue
        print(f"{item.path}: {item.format or 'not recognized'}, {item.lines} lines, {item.accepted} read, {item.errors} skipped")
        for example in item.examples:
            print(f"    {example}")
    if not events:
        print("FAILED no events could be read")
        return 1
    days = dict(sorted(Counter(e.ts.date().isoformat() for e in events).items()))
    by_source = dict(sorted(Counter(e.source for e in events).items()))
    unrecognized = [Path(p).as_posix() for p in report.unrecognized if Path(p).name != "labels.jsonl"]
    found = sum(1 for e in events if e.id in labels)
    print(f"read {len(events)} events ({', '.join(f'{k} {v}' for k, v in by_source.items())}), "
          f"{events[0].ts.isoformat()} to {events[-1].ts.isoformat()}; {report.errors} lines skipped")
    print("days: " + ", ".join(f"{day} {count}" for day, count in days.items()))
    if labels:
        print(f"labels: {len(labels)} attack events in labels.jsonl, {found} found in the logs")
    if unrecognized:
        print("not recognized (write a mapping, docs/ingest.md): " + ", ".join(unrecognized))
    summary = {
        "files": [{"path": Path(i.path).as_posix(), "format": i.format, "lines": i.lines, "accepted": i.accepted,
                   "errors": i.errors} for i in report.files],
        "events": len(events), "sources": by_source, "first_event": events[0].ts.isoformat(),
        "last_event": events[-1].ts.isoformat(), "days": days, "lines_skipped": report.errors,
        "unrecognized": unrecognized,
        "labels": {"attack_events": len(labels), "found_in_logs": found} if labels else None,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())