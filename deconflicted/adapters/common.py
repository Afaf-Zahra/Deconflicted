"""Helpers shared by the six adapters."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from pydantic import ValidationError

from deconflicted.schema import Event

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class AdapterError(ValueError):
    """A line could not be turned into an Event. The message names the file and line."""


def fail(message: str, file: str = "", lineno: int = 0) -> AdapterError:
    return AdapterError(f"{file or '<input>'}:{lineno}: {message}")


def make_id(source: str, raw: str) -> str:
    return f"{source}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def clean_user(value: Any) -> str | None:
    """Keep only the part after the last backslash or slash."""
    if value is None:
        return None
    name = re.split(r"[\\/]", str(value).strip())[-1]
    return name or None


def clean_process(path: Any) -> str | None:
    """File name only, lower case."""
    if path is None:
        return None
    name = re.split(r"[\\/]", str(path).strip())[-1].lower()
    return name or None


def clean_host(name: Any) -> str:
    """Lower case, domain suffix removed. IP addresses are kept whole."""
    text = str(name).strip().lower()
    if _IP.match(text):
        return text
    return text.split(".")[0]


def parse_ts(value: Any, file: str = "", lineno: int = 0, assume_utc: bool = False) -> datetime:
    """Parse an ISO 8601 timestamp. A timestamp without a time zone is rejected unless assume_utc is set."""
    try:
        ts = datetime.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise fail(f"bad timestamp {value!r}", file, lineno) from exc
    if ts.tzinfo is None:
        if not assume_utc:
            raise fail(f"timestamp {value!r} has no time zone", file, lineno)
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def require(data: dict, key: str, file: str, lineno: int) -> Any:
    if key not in data or data[key] in (None, ""):
        raise fail(f"missing field {key!r}", file, lineno)
    return data[key]


def build(raw: str, file: str, lineno: int, **fields: Any) -> Event:
    """Build the Event. The id always comes from the unchanged raw line."""
    source = fields["source"]
    try:
        return Event(id=make_id(source, raw), raw=raw, **fields)
    except ValidationError as exc:
        raise fail(f"invalid event: {exc.errors()[0]['msg']}", file, lineno) from exc


def iter_file(parse_line: Callable[..., Event], path: str | Path, **kwargs: Any) -> Iterator[Event]:
    """Yield one Event per non-empty line. Errors name the file and the line number."""
    name = str(path)
    with open(path, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.rstrip("\r\n")
            if line.strip():
                yield parse_line(line, file=name, lineno=lineno, **kwargs)
