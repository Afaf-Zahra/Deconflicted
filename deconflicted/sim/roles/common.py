"""Helpers for the benign-day scripts. They write raw log lines in the six source formats."""
from __future__ import annotations

import json
import random
from datetime import date, datetime, timedelta, timezone

from deconflicted.adapters.hosts import load_hosts

Line = tuple[datetime, str, str]          # (time, source, raw line)

PS = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
EXPLORER = "C:/Windows/explorer.exe"
SERVICES = "C:/Windows/System32/services.exe"
SYS32 = "C:/Windows/System32/"


def rng_for(day: date, seed: int, actor: str) -> random.Random:
    """A generator that depends only on the day, the seed and the actor (never the global one)."""
    return random.Random(f"{seed}|{day.isoformat()}|{actor}")


def ip_of(name: str) -> str:
    info = load_hosts()
    for section in ("hosts", "decoys", "external"):
        if name in (info.get(section) or {}):
            return info[section][name]["ip"]
    raise KeyError(name)


def at(day: date, hour: int, minute: int = 0, second: int = 0, ms: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, second, ms * 1000, tzinfo=timezone.utc)


def jitter(rng: random.Random, when: datetime, minutes: int = 15) -> datetime:
    return when + timedelta(seconds=rng.randint(-minutes * 60, minutes * 60), milliseconds=rng.randint(0, 999))


def iso_ms(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def ms(ts: datetime) -> datetime:
    """The time as the raw line records it: whole milliseconds."""
    return ts.replace(microsecond=ts.microsecond // 1000 * 1000)


def sec(ts: datetime) -> datetime:
    """The time as flow and syslog lines record it: whole seconds."""
    return ts.replace(microsecond=0)


def finish(lines: list[Line]) -> list[Line]:
    return sorted(lines, key=lambda item: (item[0], item[1], item[2]))


def strip(lines: list[Line]) -> list[tuple[str, str]]:
    return [(source, raw) for _, source, raw in lines]


def _dump(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"))


def win_proc(ts, host, user, image, parent, cmd) -> Line:
    raw = _dump({"EventID": 1, "UtcTime": iso_ms(ts), "Computer": host, "User": f"CORP/{user}",
                 "Image": image, "ParentImage": parent, "CommandLine": cmd})
    return ms(ts), "windows", raw


def win_logon(ts, host, user, ip, logon_type) -> Line:
    raw = _dump({"EventID": 4624, "UtcTime": iso_ms(ts), "Computer": host, "TargetUserName": user,
                 "IpAddress": ip, "LogonType": logon_type})
    return ms(ts), "windows", raw


def win_share(ts, host, user, ip, share="C$") -> Line:
    raw = _dump({"EventID": 5140, "UtcTime": iso_ms(ts), "Computer": host, "SubjectUserName": f"CORP/{user}",
                 "IpAddress": ip, "ShareName": f"\\\\*\\{share}"})
    return ms(ts), "windows", raw


def flow(ts, src_ip, dst_ip, port, size, packets, proto="tcp") -> Line:
    return sec(ts), "flow", f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')},{src_ip},{dst_ip},{port},{proto},{size},{packets}"


def proxy(ts, client_ip, url, size, dst_ip, ident="-") -> Line:
    stamp = f"{int(ts.timestamp())}.{ts.microsecond // 1000:03d}"
    return ms(ts), "proxy", f"{stamp} {rng_elapsed(ts):6d} {client_ip} TCP_MISS/200 {size} GET {url} {ident} HIER_DIRECT/{dst_ip} text/html"


def rng_elapsed(ts: datetime) -> int:
    return 20 + (ts.microsecond // 1000) % 180


def syslog(ts, host, program, message, pid=None) -> Line:
    tag = f"{program}[{pid}]" if pid else program
    return sec(ts), "linux", f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {host} {tag}: {message}"


def modbus(ts, server, client_ip, func, address, value=None) -> Line:
    data = {"ts": iso_ms(ts), "server": server, "client_ip": client_ip, "func": func, "address": address}
    if value is not None:
        data["value"] = value
    return ms(ts), "modbus", _dump(data)


def opcua(ts, server, client_ip, service, node, value=None) -> Line:
    data = {"ts": iso_ms(ts), "server": server, "client_ip": client_ip, "service": service, "node": node}
    if value is not None:
        data["value"] = value
    return ms(ts), "opcua", _dump(data)
