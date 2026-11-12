"""Linux syslog (sshd logons and sudo commands). Lines carry no year; the year is a parameter."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

from deconflicted.schema import Event

from .common import build, clean_host, clean_process, clean_user, fail, iter_file

SOURCE = "linux"
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
_ACCEPTED = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_FAILED = re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
_SUDO = re.compile(r"^(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$")


def parse_line(line: str, *, file: str = "", lineno: int = 0, year: int = 2026, assume_utc: bool = False) -> Event:
    """Syslog times carry no zone and are always read as UTC; assume_utc is accepted for a uniform call."""
    match = _LINE.match(line)
    if not match or match["mon"] not in MONTHS:
        raise fail("not a syslog line", file, lineno)
    h, m, s = (int(part) for part in match["time"].split(":"))
    try:
        ts = datetime(year, MONTHS[match["mon"]], int(match["day"]), h, m, s, tzinfo=timezone.utc)
    except ValueError as exc:
        raise fail(f"bad date: {exc}", file, lineno) from exc
    host, prog, msg = clean_host(match["host"]), match["prog"], match["msg"].strip()
    common = dict(source=SOURCE, ts=ts, host=host)
    if prog == "sshd":
        accepted = _ACCEPTED.match(msg)
        if accepted:
            return build(line, file, lineno, **common, action="logon", user=clean_user(accepted["user"]),
                         src_ip=accepted["ip"], obj="logon_type:ssh")
        failed = _FAILED.match(msg)
        if failed:
            return build(line, file, lineno, **common, action="logon", user=clean_user(failed["user"]),
                         src_ip=failed["ip"], obj="failed")
    if prog == "sudo":
        sudo = _SUDO.match(msg)
        if sudo:
            command = sudo["cmd"].strip()
            return build(line, file, lineno, **common, action="proc_create", user=clean_user(sudo["user"]),
                         process=clean_process(command.split()[0]), cmdline=command)
    raise fail(f"unsupported syslog message from {prog!r}", file, lineno)


def parse_file(path, year: int = 2026, assume_utc: bool = False) -> Iterator[Event]:
    return iter_file(parse_line, path, year=year, assume_utc=assume_utc)
