"""Background traffic: proxy requests, flows between hosts that normally talk, the historian's OPC-UA reads."""
from __future__ import annotations

from datetime import date, timedelta

from . import common as c

ACTOR = "background"
# (source host, destination host, port, flows per hour)
PAIRS = [
    ("ws-admin-01", "file-01", 445, 12), ("ws-help-01", "file-01", 445, 12), ("ws-help-01", "dc-01", 389, 20),
    ("ws-admin-01", "dc-01", 88, 20), ("file-01", "dc-01", 389, 20), ("bak-01", "file-01", 445, 2),
    ("eng-ws-01", "plc-1", 502, 30), ("ops-ws-01", "plc-1", 502, 60), ("ops-ws-01", "plc-2", 502, 60),
    ("hist-01", "opc-1", 4840, 60), ("eng-ws-01", "hist-01", 80, 10),
]


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    lines: list[c.Line] = []
    for src, dst, port, per_hour in PAIRS:
        src_ip, dst_ip = c.ip_of(src), c.ip_of(dst)
        for hour in range(7, 19):
            for _ in range(max(1, int(2 * per_hour * rng.uniform(0.7, 1.3)))):
                when = c.at(day, hour) + timedelta(seconds=rng.randint(0, 3599), milliseconds=rng.randint(0, 999))
                lines.append(c.flow(when, src_ip, dst_ip, port, rng.randint(300, 120000), rng.randint(2, 200)))
    update_ip = c.ip_of("update-server")
    for client in ("ws-admin-01", "ws-help-01"):  # software updates through the proxy
        for _ in range(rng.randint(10, 16)):
            when = c.at(day, 7) + timedelta(seconds=rng.randint(0, 11 * 3600), milliseconds=rng.randint(0, 999))
            lines.append(c.proxy(when, c.ip_of(client), f"http://{update_ip}/pkg/update-{rng.randint(1, 40)}.tar",
                                 rng.randint(2000, 900000), update_ip))
    when, end = c.at(day, 0, 0, 5), c.at(day, 23, 59)
    while when < end:  # the historian reads the tank level over OPC-UA every 30 seconds
        lines.append(c.opcua(when, "opc-1", c.ip_of("hist-01"), "Read", "ns=2;s=Tank1.Level", round(rng.uniform(47, 53), 1)))
        when += timedelta(seconds=30, milliseconds=rng.randint(0, 400))
    for server in ("dc-01", "file-01"):  # routine update checks run by the system account
        for hour in (3, 15):
            when = c.at(day, hour, rng.randint(0, 59), rng.randint(0, 59), rng.randint(0, 999))
            lines.append(c.win_proc(when, server, "SYSTEM", c.SYS32 + "wuauclt.exe", c.SERVICES, "wuauclt.exe /detectnow"))
    return c.finish(lines)


def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
