"""Windows Sysmon-style JSON, one object per line."""
from __future__ import annotations

import json
from typing import Iterator

from deconflicted.schema import Event

from .common import (AdapterError, build, clean_host, clean_process, clean_user, fail,
                     iter_file, parse_ts, require)

SOURCE = "windows"


def parse_line(line: str, *, file: str = "", lineno: int = 0, assume_utc: bool = False) -> Event:
    """Parse one Sysmon-style line.

    Real Sysmon writes UtcTime without a zone ("2026-03-04 03:43:02.110"). It is UTC by definition, so the
    ingest layer passes assume_utc=True for such logs. The default is strict: a time without a zone is an error.
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise fail(f"not valid JSON ({exc.msg})", file, lineno) from exc
    if not isinstance(data, dict):
        raise fail("expected a JSON object", file, lineno)
    event_id = data.get("EventID")
    ts = parse_ts(require(data, "UtcTime", file, lineno), file, lineno, assume_utc)
    host = clean_host(require(data, "Computer", file, lineno))
    common = dict(source=SOURCE, ts=ts, host=host)
    if event_id == 1:
        return build(line, file, lineno, **common, action="proc_create",
                     user=clean_user(data.get("User")),
                     process=clean_process(require(data, "Image", file, lineno)),
                     parent_process=clean_process(data.get("ParentImage")),
                     cmdline=data.get("CommandLine"))
    if event_id == 3:
        port = data.get("DestinationPort")
        return build(line, file, lineno, **common, action="net_conn",
                     user=clean_user(data.get("User")),
                     process=clean_process(require(data, "Image", file, lineno)),
                     src_ip=data.get("SourceIp"), dst_ip=data.get("DestinationIp"),
                     dst_port=int(port) if port is not None else None)
    if event_id in (4624, 4625):
        failed = event_id == 4625
        obj = "failed" if failed else f"logon_type:{require(data, 'LogonType', file, lineno)}"
        return build(line, file, lineno, **common, action="logon",
                     user=clean_user(require(data, "TargetUserName", file, lineno)),
                     src_ip=data.get("IpAddress"), obj=obj)
    if event_id == 5140:
        share = clean_user(require(data, "ShareName", file, lineno))
        return build(line, file, lineno, **common, action="net_conn",
                     user=clean_user(data.get("SubjectUserName")),
                     src_ip=data.get("IpAddress"), dst_port=445, obj=share)
    if event_id == 1102:
        return build(line, file, lineno, **common, action="log_clear",
                     user=clean_user(data.get("SubjectUserName")))
    raise fail(f"unsupported EventID {event_id!r}", file, lineno)


def parse_file(path, assume_utc: bool = False) -> Iterator[Event]:
    return iter_file(parse_line, path, assume_utc=assume_utc)


__all__ = ["parse_line", "parse_file", "AdapterError"]
