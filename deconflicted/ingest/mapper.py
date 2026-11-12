"""A generic mapper: describe a log format in YAML and get a parser that works like an adapter.

The YAML format is explained in docs/ingest.md.
"""
from __future__ import annotations

import copy
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, get_args

import yaml

from deconflicted.adapters import ADAPTERS
from deconflicted.adapters.common import build, clean_host, clean_process, clean_user, fail, parse_ts
from deconflicted.adapters.hosts import resolve_ip
from deconflicted.schema import Event, EventAction, Source

from .sniff import REPLAY

FORMATS = ("json", "csv", "regex")
TIME_FORMATS = ("iso", "epoch", "epoch_ms")
FIELDS = ("host", "user", "process", "parent_process", "cmdline", "src_ip", "dst_ip", "dst_port", "obj", "value")
KEYS = {"name", "source", "format", "columns", "delimiter", "pattern", "timestamp", "action", "fields", "detect"}


class MappingError(ValueError):
    """A mapping file is wrong. The message names the file."""


def _clean(value: Any) -> Any:
    """Empty cells and the usual dash for 'nothing' become None."""
    if isinstance(value, str):
        value = value.strip()
        if value in ("", "-"):
            return None
    return value


def _get(record: dict, path: str) -> Any:
    """A field of the record. A dotted path walks into nested JSON, unless the key itself contains dots."""
    if path in record:
        return record[path]
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class Mapper:
    """Parses one log format described by a mapping. parse_line has the same call as the adapters."""

    def __init__(self, spec: Any, file: str = "<mapping>") -> None:
        def bad(message: str) -> MappingError:
            return MappingError(f"{file}: {message}")

        if not isinstance(spec, dict):
            raise bad("expected a YAML mapping at the top level")
        if set(spec) - KEYS:
            raise bad("unknown key(s): " + ", ".join(sorted(map(str, set(spec) - KEYS))))
        self.name = str(spec.get("name") or Path(file).stem)
        self.source = spec.get("source")
        if self.source not in get_args(Source):
            raise bad("source must be one of " + ", ".join(get_args(Source)))
        self.format = spec.get("format")
        if self.format not in FORMATS:
            raise bad("format must be one of " + ", ".join(FORMATS))
        self.delimiter = str(spec.get("delimiter", ","))
        self.columns = spec.get("columns")
        if self.columns is not None and not (isinstance(self.columns, list) and all(isinstance(c, str) for c in self.columns)):
            raise bad("columns must be a list of names")
        self.pattern = None
        if self.format == "regex":
            try:
                self.pattern = re.compile(str(spec.get("pattern", "")))
            except re.error as exc:
                raise bad(f"bad pattern: {exc}") from exc
            if not self.pattern.groupindex:
                raise bad("pattern needs named groups, like (?P<host>\\S+)")
        stamp = spec.get("timestamp")
        if not isinstance(stamp, dict) or not stamp.get("field"):
            raise bad("timestamp.field is required")
        self.ts_field = str(stamp["field"])
        self.ts_format = str(stamp.get("format", "iso"))
        if self.ts_format not in TIME_FORMATS and "%" not in self.ts_format:
            raise bad("timestamp.format must be iso, epoch, epoch_ms or a strptime pattern such as %Y-%m-%d %H:%M:%S")
        self.ts_utc = bool(stamp.get("assume_utc", False))
        action = spec.get("action")
        if not isinstance(action, dict):
            raise bad("action is required")
        self.action_constant = action.get("constant")
        self.action_field = action.get("field")
        table = action.get("map") or {}
        if not isinstance(table, dict):
            raise bad("action.map must be a mapping from log values to actions")
        self.action_map = {str(key): value for key, value in table.items()}
        self.action_default = action.get("default")
        if (self.action_constant is None) == (self.action_field is None):
            raise bad("action needs either constant or field")
        valid = get_args(EventAction)
        for name in (self.action_constant, self.action_default, *self.action_map.values()):
            if name is not None and name not in valid:
                raise bad(f"unknown action {name!r}; use one of " + ", ".join(valid))
        fields = spec.get("fields") or {}
        if not isinstance(fields, dict) or set(fields) - set(FIELDS):
            raise bad("fields may only use: " + ", ".join(FIELDS))
        if not all(isinstance(value, str) for value in fields.values()):
            raise bad("each entry of fields names a field of the log")
        self.fields = dict(fields)
        detect = spec.get("detect") or {}
        if not isinstance(detect, dict) or set(detect) - {"has"}:
            raise bad("detect may only have: has")
        self.detect = [str(name) for name in detect.get("has", [])]
        known = set(self.pattern.groupindex) if self.pattern else set(self.columns or []) if self.format == "csv" and self.columns else None
        if known is not None:
            used = [self.ts_field, *self.fields.values(), *self.detect] + ([self.action_field] if self.action_field else [])
            for name in used:
                if name not in known:
                    raise bad(f"{name!r} is not a {'group of the pattern' if self.pattern else 'column'}")
        self._header: list[str] | None = None

    # ---- csv header
    @property
    def needs_header(self) -> bool:
        return self.format == "csv" and self.columns is None

    @property
    def has_header(self) -> bool:
        return self._header is not None

    def reset(self) -> None:
        """Forget the header. Call it before reading a new file."""
        self._header = None

    def set_header(self, line: str) -> None:
        try:
            self._header = [name.strip() for name in next(csv.reader([line], delimiter=self.delimiter))]
        except (csv.Error, StopIteration):
            self._header = []

    # ---- parsing
    def _record(self, line: str, file: str, lineno: int) -> dict:
        if self.format == "json":
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise fail(f"not valid JSON ({exc.msg})", file, lineno) from exc
            if not isinstance(data, dict):
                raise fail("expected a JSON object", file, lineno)
            return data
        if self.format == "csv":
            names = self.columns if self.columns is not None else self._header
            if not names:
                raise fail("the csv header has not been read", file, lineno)
            try:
                cells = next(csv.reader([line], delimiter=self.delimiter))
            except (csv.Error, StopIteration) as exc:
                raise fail("not a csv line", file, lineno) from exc
            if len(cells) != len(names):
                raise fail(f"expected {len(names)} columns, found {len(cells)}", file, lineno)
            return dict(zip(names, (cell.strip() for cell in cells)))
        match = self.pattern.match(line)
        if not match:
            raise fail("line does not match the pattern", file, lineno)
        return match.groupdict()

    def _time(self, record: dict, file: str, lineno: int, assume_utc: bool) -> datetime:
        value = _clean(_get(record, self.ts_field))
        if value is None:
            raise fail(f"missing field {self.ts_field!r}", file, lineno)
        if self.ts_format == "iso":
            return parse_ts(value, file, lineno, assume_utc or self.ts_utc)
        try:
            if self.ts_format in ("epoch", "epoch_ms"):
                seconds = float(value) / (1000 if self.ts_format == "epoch_ms" else 1)
                return datetime.fromtimestamp(seconds, tz=timezone.utc)
            ts = datetime.strptime(str(value), self.ts_format)
        except (ValueError, OverflowError, OSError) as exc:
            raise fail(f"bad timestamp {value!r}", file, lineno) from exc
        if ts.tzinfo is None:
            if not (assume_utc or self.ts_utc):
                raise fail(f"timestamp {value!r} has no time zone", file, lineno)
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    def _action(self, record: dict, file: str, lineno: int) -> str:
        if self.action_constant is not None:
            return self.action_constant
        value = _clean(_get(record, self.action_field))
        key = "" if value is None else str(value)
        if key in self.action_map:
            return self.action_map[key]
        if self.action_default is not None:
            return self.action_default
        raise fail(f"no action is mapped for {self.action_field} = {value!r}", file, lineno)

    def parse_line(self, line: str, *, file: str = "", lineno: int = 0, assume_utc: bool = False, **_ignored: Any) -> Event:
        record = self._record(line, file, lineno)
        ts = self._time(record, file, lineno, assume_utc)
        action = self._action(record, file, lineno)
        found = {name: _clean(_get(record, path)) for name, path in self.fields.items()}
        host, src_ip = found.pop("host", None), found.get("src_ip")
        if host is not None:
            host = resolve_ip(clean_host(host))
        elif src_ip is not None:
            host = resolve_ip(str(src_ip))
        else:
            raise fail("no host: map the host field, or src_ip so the host can be looked up", file, lineno)
        values: dict[str, Any] = {}
        for name, value in found.items():
            if value is None:
                continue
            if name == "user":
                values[name] = clean_user(value)
            elif name in ("process", "parent_process"):
                values[name] = clean_process(value)
            elif name == "dst_port":
                try:
                    values[name] = int(float(value))
                except ValueError as exc:
                    raise fail(f"bad port {value!r}", file, lineno) from exc
            elif name == "value":
                try:
                    values[name] = float(value)
                except (TypeError, ValueError):
                    values[name] = str(value)
            else:
                values[name] = str(value)
        return build(line, file, lineno, source=self.source, ts=ts, host=host, action=action, **values)

    def matches(self, lines: list[str]) -> bool:
        """True when most of the sample lines have every field named in detect.has. Without detect it never matches."""
        if not self.detect:
            return False
        probe = copy.copy(self)
        probe.reset()
        rows = list(lines)
        if probe.needs_header and rows:
            probe.set_header(rows.pop(0))
        hits = 0
        for number, line in enumerate(rows, start=1):
            try:
                record = probe._record(line, "", number)
            except ValueError:
                continue
            if all(_clean(_get(record, name)) is not None for name in self.detect):
                hits += 1
        return bool(rows) and hits * 2 >= len(rows)


def load_mappings(folder: str | Path) -> list[Mapper]:
    """Every .yaml and .yml file in the folder. A missing folder means no mappings."""
    root = Path(folder)
    if not root.is_dir():
        return []
    mappers: list[Mapper] = []
    for path in sorted([*root.glob("*.yaml"), *root.glob("*.yml")]):
        try:
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise MappingError(f"{path}: not valid YAML ({exc})") from exc
        mapper = Mapper(spec, str(path))
        if mapper.name in ADAPTERS or mapper.name == REPLAY:
            raise MappingError(f"{path}: the name {mapper.name!r} is a built-in format")
        if any(other.name == mapper.name for other in mappers):
            raise MappingError(f"{path}: the name {mapper.name!r} is used twice")
        mappers.append(mapper)
    return mappers