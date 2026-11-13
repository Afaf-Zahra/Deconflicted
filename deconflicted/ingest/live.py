"""Turn one JSON object into an Event: a replay item, a built-in record, or a record that a mapping describes."""
from __future__ import annotations

import json
from typing import Any, Sequence

from deconflicted import adapters
from deconflicted.adapters.common import AdapterError
from deconflicted.schema import Event

from .mapper import Mapper
from .sniff import sniff_line


def canonical(record: dict) -> str:
    """The raw text of a JSON record: sorted keys, so the same record always gets the same event id."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _mapper(name: str, mappings: Sequence[Mapper]) -> Mapper:
    for mapper in mappings:
        if mapper.name == name:
            return mapper
    raise AdapterError(f"no mapping named {name!r}")


def _parse(source: str, raw: str, mappings: Sequence[Mapper]) -> Event:
    if source in adapters.ADAPTERS:
        return adapters.get(source).parse_line(raw, assume_utc=True)
    for mapper in mappings:
        if mapper.name == source:
            return mapper.parse_line(raw, assume_utc=True)
    raise AdapterError(f"no adapter or mapping named {source!r}")


def parse_item(item: Any, *, source: str | None = None, mapping: str | None = None,
               mappings: Sequence[Mapper] = ()) -> Event:
    """One JSON object to an Event.

    {"source": ..., "raw": ...} is a log line, as /ingest takes it. Any other object is the record itself: it goes to
    the mapping or built-in source you name, otherwise the built-in format it looks like, otherwise the first mapping
    whose detect.has fields it has.
    """
    if not isinstance(item, dict):
        raise AdapterError("expected a JSON object")
    if set(item) == {"source", "raw"} and isinstance(item["source"], str) and isinstance(item["raw"], str):
        return _parse(item["source"], item["raw"], mappings)
    raw = canonical(item)
    if mapping:
        return _mapper(mapping, mappings).parse_line(raw, assume_utc=True)
    if source:
        return _parse(source, raw, mappings)
    found = sniff_line(raw)
    if found in adapters.ADAPTERS:
        return adapters.get(found).parse_line(raw, assume_utc=True)
    for candidate in mappings:
        if candidate.matches([raw]):
            return candidate.parse_line(raw, assume_utc=True)
    raise AdapterError("cannot tell what this JSON is (no built-in format matches and no mapping detects it); "
                       'add a mapping (docs/ingest.md) or send it as {"source": ..., "raw": ...}')