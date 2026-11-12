"""Flow CSV with no header: ts,src_ip,dst_ip,dst_port,proto,bytes,packets."""
from __future__ import annotations

from typing import Iterator

from deconflicted.schema import Event

from .common import build, fail, iter_file, parse_ts
from .hosts import resolve_ip

SOURCE = "flow"


def parse_line(line: str, *, file: str = "", lineno: int = 0, assume_utc: bool = False) -> Event:
    fields = [part.strip() for part in line.split(",")]
    if len(fields) != 7:
        raise fail(f"expected 7 columns, found {len(fields)}", file, lineno)
    ts_text, src, dst, port, _proto, size, _packets = fields
    ts = parse_ts(ts_text, file, lineno, assume_utc)
    try:
        return build(line, file, lineno, source=SOURCE, ts=ts, host=resolve_ip(src), src_ip=src,
                     dst_ip=dst, dst_port=int(port), action="flow", value=float(size))
    except ValueError as exc:
        raise fail("bad port or byte count", file, lineno) from exc


def parse_file(path, assume_utc: bool = False) -> Iterator[Event]:
    return iter_file(parse_line, path, assume_utc=assume_utc)
