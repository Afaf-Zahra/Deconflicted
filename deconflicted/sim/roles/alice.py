"""alice (admin): logs on to dc-01 in the morning and runs known admin routines from ws-admin-01."""
from __future__ import annotations

from datetime import date

from . import common as c

ACTOR = "alice"
SCRIPTS = ["cleanup", "patch-check", "inventory", "cert-renew"]


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    host, ip = "ws-admin-01", c.ip_of("ws-admin-01")
    lines = [c.win_logon(c.jitter(rng, c.at(day, 8, 45)), "dc-01", ACTOR, ip, 3)]
    for hour, minute in ((9, 15), (15, 30)):  # the ad_health_check routine
        when = c.jitter(rng, c.at(day, hour, minute))
        lines.append(c.win_proc(when, host, ACTOR, c.SYS32 + "nltest.exe", c.PS, "nltest /dclist:corp"))
    for _ in range(rng.randint(3, 6)):
        when = c.at(day, 9, 30) + (c.at(day, 17) - c.at(day, 9, 30)) * rng.random()
        script = rng.choice(SCRIPTS)
        lines.append(c.win_proc(when, host, ACTOR, c.PS, c.EXPLORER, f"powershell.exe -File C:/admin/{script}.ps1"))
    for _ in range(rng.randint(8, 14)):  # normal directory traffic
        when = c.at(day, 8, 30) + (c.at(day, 17) - c.at(day, 8, 30)) * rng.random()
        lines.append(c.flow(when, ip, c.ip_of("dc-01"), rng.choice([88, 389, 445]), rng.randint(900, 9000), rng.randint(6, 40)))
    return c.finish(lines)


def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
