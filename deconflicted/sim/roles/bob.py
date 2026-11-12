"""bob (helpdesk): bursts of password resets through PowerShell from ws-help-01."""
from __future__ import annotations

from datetime import date, timedelta

from . import common as c

ACTOR = "bob"
USERS = ["jdoe", "asmith", "mlee", "kpatel", "rjones", "tchan"]


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    host, ip = "ws-help-01", c.ip_of("ws-help-01")
    lines = [c.win_logon(c.jitter(rng, c.at(day, 8, 15)), "dc-01", ACTOR, ip, 3)]
    for hour, minute in ((10, 15), (14, 30)):  # the helpdesk_password_reset routine
        when = c.jitter(rng, c.at(day, hour, minute))
        for _ in range(rng.randint(2, 6)):
            user = rng.choice(USERS)
            lines.append(c.win_proc(when, host, ACTOR, c.PS, c.EXPLORER,
                                    f"powershell.exe -Command Set-ADAccountPassword -Identity {user}"))
            when += timedelta(seconds=rng.randint(20, 60), milliseconds=rng.randint(0, 999))
    for _ in range(rng.randint(8, 14)):
        when = c.at(day, 8, 30) + (c.at(day, 17) - c.at(day, 8, 30)) * rng.random()
        lines.append(c.flow(when, ip, c.ip_of("dc-01"), rng.choice([88, 389, 445]), rng.randint(900, 9000), rng.randint(6, 40)))
    return c.finish(lines)


def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
