"""carol (engineer): logs on to eng-ws-01, reads the tank level and writes the setpoint inside 40 to 60."""
from __future__ import annotations

from datetime import date, timedelta

from . import common as c

ACTOR = "carol"


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    ip = c.ip_of("eng-ws-01")
    lines = [c.win_logon(c.jitter(rng, c.at(day, 8, 0)), "eng-ws-01", ACTOR, ip, 2)]
    when, end = c.jitter(rng, c.at(day, 8, 10)), c.at(day, 17)
    while when < end:  # a level read every five minutes
        lines.append(c.modbus(when, "plc-1", ip, rng.choice([3, 4]), 40002, round(rng.uniform(47, 53), 1)))
        when += timedelta(minutes=5, milliseconds=rng.randint(0, 999))
    for _ in range(rng.randint(2, 4)):  # setpoint changes, always inside the allowed range
        when = c.at(day, 9) + (c.at(day, 16) - c.at(day, 9)) * rng.random()
        lines.append(c.modbus(when, "plc-1", ip, 6, 40001, rng.randint(45, 55)))
    return c.finish(lines)


def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
