"""Reads log files of any known format into Events. A line that fails is counted and skipped, never fatal."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from deconflicted import adapters
from deconflicted.adapters.common import fail
from deconflicted.schema import Event

from .mapper import Mapper
from .sniff import REPLAY, _DATE, read_sample, sniff_lines


@dataclass
class FileReport:
    path: str
    format: str | None = None  # a source name, "replay", a mapping name, or None when the file is not recognized
    lines: int = 0
    accepted: int = 0
    errors: int = 0
    examples: list[str] = field(default_factory=list)  # the first few error messages


@dataclass
class Report:
    files: list[FileReport] = field(default_factory=list)

    @property
    def accepted(self) -> int:
        return sum(item.accepted for item in self.files)

    @property
    def errors(self) -> int:
        return sum(item.errors for item in self.files)

    @property
    def unrecognized(self) -> list[str]:
        return [item.path for item in self.files if item.format is None]


def _choose(lines: list[str], mappings: Sequence[Mapper], wanted: str | None) -> tuple[str | None, Mapper | None]:
    named = {mapper.name: mapper for mapper in mappings}
    if wanted:
        if wanted == REPLAY or wanted in adapters.ADAPTERS:
            return wanted, None
        if wanted in named:
            return wanted, named[wanted]
        raise LookupError(f"unknown format {wanted!r}; use replay, a source name or a mapping ({', '.join(named) or 'none loaded'})")
    found = sniff_lines(lines)
    if found:
        return found, None
    for mapper in mappings:
        if mapper.matches(lines):
            return mapper.name, mapper
    return None, None


def _adapter(source: str, raw: str, name: str, lineno: int, year: int, assume_utc: bool) -> Event:
    extra = {"year": year} if source == "linux" else {}
    return adapters.get(source).parse_line(raw, file=name, lineno=lineno, assume_utc=assume_utc, **extra)


def _parse(fmt: str, mapper: Mapper | None, line: str, name: str, lineno: int, year: int, assume_utc: bool) -> Event:
    if mapper:
        return mapper.parse_line(line, file=name, lineno=lineno, assume_utc=assume_utc)
    if fmt == REPLAY:
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise fail(f"not valid JSON ({exc.msg})", name, lineno) from exc
        if not (isinstance(item, dict) and isinstance(item.get("source"), str) and isinstance(item.get("raw"), str)):
            raise fail('expected {"source": ..., "raw": ...}', name, lineno)
        return _adapter(item["source"], item["raw"], name, lineno, year, assume_utc)
    return _adapter(fmt, line, name, lineno, year, assume_utc)


def read_file(path: str | Path, *, mappings: Sequence[Mapper] = (), wanted: str | None = None, year: int = 2026,
              assume_utc: bool = True, max_examples: int = 5) -> tuple[list[Event], FileReport]:
    """Events of one file, in file order, and what happened. wanted forces a format: a source, replay or a mapping name.

    assume_utc accepts times that carry no zone as UTC, as /ingest does. year is for syslog, which has none.
    """
    name = str(path)
    report = FileReport(name)
    fmt, mapper = _choose(read_sample(path), mappings, wanted)
    report.format = fmt
    if fmt is None:
        return [], report
    if mapper:
        mapper.reset()
    events: list[Event] = []
    first = True
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            was_first, first = first, False
            if mapper and mapper.needs_header and not mapper.has_header:
                mapper.set_header(line)
                continue
            if fmt == "flow" and was_first:
                parts = line.split(",")
                if len(parts) == 7 and not _DATE.match(parts[0].strip()):
                    continue  # a header row; the flow adapter reads files without one
            report.lines += 1
            try:
                events.append(_parse(fmt, mapper, line, name, lineno, year, assume_utc))
                report.accepted += 1
            except (ValueError, TypeError) as exc:
                report.errors += 1
                if len(report.examples) < max_examples:
                    message = str(exc)
                    report.examples.append(message if message.startswith(name) else f"{name}:{lineno}: {message}")
    return events, report


def read_path(path: str | Path, **options) -> tuple[list[Event], Report]:
    """A file or a folder (every file inside, hidden files skipped). The events come back sorted by time."""
    root = Path(path)
    if root.is_dir():
        files = sorted(item for item in root.rglob("*")
                       if item.is_file() and not any(part.startswith(".") for part in item.relative_to(root).parts))
    elif root.is_file():
        files = [root]
    else:
        raise FileNotFoundError(f"{path} does not exist")
    events: list[Event] = []
    report = Report()
    for file in files:
        found, file_report = read_file(file, **options)
        events += found
        report.files.append(file_report)
    events.sort(key=lambda event: (event.ts, event.id))
    return events, report


def to_replay_lines(events: Sequence[Event]) -> list[str]:
    """The events as replay-format lines: one {"source": ..., "raw": ...} object each."""
    return [json.dumps({"source": event.source, "raw": event.raw}, separators=(",", ":")) for event in events]