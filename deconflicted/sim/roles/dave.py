"""dave (operator): from ops-ws-01, reads the level of plc-1 and plc-2 every 10 seconds in working hours."""
from __future__ import annotations

from datetime import date, timedelta

from . import common as c

ACTOR = "dave"


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    ip = c.ip_of("ops-ws-01")
    lines = [c.win_logon(c.jitter(rng, c.at(day, 7, 45)), "ops-ws-01", ACTOR, ip, 2)]
    start, end = c.at(day, 8), c.at(day, 17)
    step = 0
    while start + timedelta(seconds=10 * step) < end:
        base = start + timedelta(seconds=10 * step)
        for server in ("plc-1", "plc-2"):
            when = base + timedelta(milliseconds=rng.randint(0, 900))
            lines.append(c.modbus(when, server, ip, rng.choice([3, 4]), 40002, round(rng.uniform(47, 53), 1)))
        step += 1
    return c.finish(lines)


def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
