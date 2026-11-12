"""Squid native access.log."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterator
from urllib.parse import urlsplit

from deconflicted.schema import Event

from .common import build, clean_user, fail, iter_file
from .hosts import resolve_ip

SOURCE = "proxy"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _port(url: str) -> int | None:
    if "://" not in url:  # CONNECT lines look like host:port
        host, _, port = url.rpartition(":")
        return int(port) if port.isdigit() else None
    parts = urlsplit(url)
    if parts.port:
        return parts.port
    return 443 if parts.scheme == "https" else 80 if parts.scheme == "http" else None


def parse_line(line: str, *, file: str = "", lineno: int = 0, assume_utc: bool = False) -> Event:
    """assume_utc is accepted so every adapter can be called the same way. Squid times are epoch seconds (UTC)."""
    fields = line.split()
    if len(fields) < 9:
        raise fail("expected at least 9 Squid fields", file, lineno)
    epoch, _elapsed, client, _result, size, _method, url, ident, hier = fields[:9]
    try:
        seconds, _, fraction = epoch.partition(".")
        ts = _EPOCH + timedelta(seconds=int(seconds), microseconds=int(fraction.ljust(6, "0")[:6] or 0))
        value = float(size)
    except ValueError as exc:
        raise fail("bad epoch or byte count", file, lineno) from exc
    if not _IP.match(client):
        raise fail(f"client {client!r} is not an IP address", file, lineno)
    dst = hier.rsplit("/", 1)[-1]
    return build(line, file, lineno, source=SOURCE, ts=ts, host=resolve_ip(client),
                 user=None if ident == "-" else clean_user(ident), src_ip=client,
                 dst_ip=dst if _IP.match(dst) else None, dst_port=_port(url),
                 action="http_request", obj=url, value=value)


def parse_file(path, assume_utc: bool = False) -> Iterator[Event]:
    return iter_file(parse_line, path, assume_utc=assume_utc)
