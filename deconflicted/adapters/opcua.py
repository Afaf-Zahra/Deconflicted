"""OPC-UA-style JSON log, one object per line."""
from __future__ import annotations

import json
from typing import Iterator

from deconflicted.schema import Event

from .common import build, clean_host, fail, iter_file, parse_ts, require

SOURCE = "opcua"


def parse_line(line: str, *, file: str = "", lineno: int = 0, assume_utc: bool = False) -> Event:
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise fail(f"not valid JSON ({exc.msg})", file, lineno) from exc
    if not isinstance(data, dict):
        raise fail("expected a JSON object", file, lineno)
    service = str(require(data, "service", file, lineno)).lower()
    if service not in ("read", "write"):
        raise fail(f"unsupported OPC-UA service {data['service']!r}", file, lineno)
    value = data.get("value")
    return build(line, file, lineno, source=SOURCE, ts=parse_ts(require(data, "ts", file, lineno), file, lineno, assume_utc),
                 host=clean_host(require(data, "server", file, lineno)),
                 src_ip=data.get("client_ip"), dst_port=4840, action=service,
                 obj=require(data, "node", file, lineno),
                 value=float(value) if value is not None else None)


def parse_file(path, assume_utc: bool = False) -> Iterator[Event]:
    return iter_file(parse_line, path, assume_utc=assume_utc)
