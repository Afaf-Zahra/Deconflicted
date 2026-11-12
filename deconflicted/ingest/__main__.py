"""Read logs and show what was found.   python -m deconflicted.ingest <file or folder>

  --out FILE        also write the events, in time order, as replay lines (what the replay container reads)
  --format NAME     treat every file as this format: a source name, replay, or the name of a mapping
  --mappings DIR    folder of mapping YAML files (default: config/mappings)
  --year 2026       the year of syslog lines, which carry none
  --strict-time     reject times without a time zone instead of reading them as UTC
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from deconflicted.adapters.hosts import config_dir

from .load import read_path, to_replay_lines
from .mapper import MappingError, load_mappings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deconflicted.ingest", description="Read log files of any known format")
    parser.add_argument("path", help="a log file or a folder of log files")
    parser.add_argument("--out")
    parser.add_argument("--format", dest="wanted")
    parser.add_argument("--mappings")
    parser.add_argument("--year", type=int, default=2026)
    parser.add_argument("--strict-time", action="store_true")
    args = parser.parse_args(argv)
    try:
        mappings = load_mappings(args.mappings or config_dir() / "mappings")
        events, report = read_path(args.path, mappings=mappings, wanted=args.wanted, year=args.year,
                                   assume_utc=not args.strict_time)
    except (MappingError, LookupError, OSError) as exc:
        print(f"FAILED {exc}")
        return 1
    for item in report.files:
        print(f"{item.path}: {item.format or 'not recognized'}, {item.lines} lines, {item.accepted} read, {item.errors} skipped")
        for example in item.examples:
            print(f"    {example}")
    if not events:
        print("FAILED no events could be read")
        return 1
    by_source = ", ".join(f"{name} {count}" for name, count in sorted(Counter(e.source for e in events).items()))
    print(f"read {len(events)} events from {len(report.files)} files ({by_source}), "
          f"{events[0].ts.isoformat()} to {events[-1].ts.isoformat()}; {report.errors} lines skipped")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(line + "\n" for line in to_replay_lines(events)), encoding="utf-8", newline="\n")
        print(f"wrote {len(events)} lines to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())