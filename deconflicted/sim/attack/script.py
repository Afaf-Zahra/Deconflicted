"""The red-team script. It only uses normal admin tools, in a harmful order. docs/scenario.md tells the story."""
from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from deconflicted.sim.roles import common as c

ATTACK_DAY = date(2026, 3, 4)
START = (3, 40)  # 03:40:00 UTC on the attack day
PAYLOAD = "JABzAD0ATgBlAHcA"
# Seconds after the first step: logon, encoded PowerShell, nltest, decoy touch, log clear, setpoint write.
OFFSETS = (0.0, 182.110, 485.020, 500.0, 2400.0, 4200.0)
# The position numbers used by the labels in tests/fixtures/events.json. Steps 4 to 6 and 8 are not in the six-step incident.
STEP_LABELS = (1, 2, 3, 3, 7, 9)


@dataclass(frozen=True)
class Step:
    ts: datetime
    source: str
    raw: str
    step: int | None = None  # attack position for the labels; None for background events


def _json(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"))


def attack_steps(day: date = ATTACK_DAY, variant: int | None = None) -> list[Step]:
    """The six attack events. variant=None is the main scenario exactly as in docs/scenario.md.

    A number gives a repeatable variant: the start time moves, the gaps and the payload change, and the setpoint
    value differs. The attacker always starts from ws-help-01, which is not on the decoy allowlist.
    """
    rng = random.Random(f"attack|{variant}") if variant is not None else None
    shift = timedelta(minutes=rng.randint(-120, 120)) if rng else timedelta()
    offsets = list(OFFSETS)
    if rng:
        offsets = [0.0]
        for before, after in zip(OFFSETS, OFFSETS[1:]):
            offsets.append(offsets[-1] + (after - before) * rng.uniform(0.7, 1.3))
    payload = PAYLOAD if not rng else "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(16))
    value = 95 if not rng else rng.randint(61, 100)
    base = c.at(day, *START) + shift
    at = [c.ms(base + timedelta(seconds=offset)) for offset in offsets]
    foothold = "ws-help-01"
    lines = [
        c.win_logon(at[0], "dc-01", "alice", c.ip_of(foothold), 3),
        c.win_proc(at[1], foothold, "alice", c.PS, c.EXPLORER, f"powershell.exe -enc {payload}"),
        c.win_proc(at[2], foothold, "alice", c.SYS32 + "nltest.exe", c.PS, "nltest /dclist:corp"),
        c.flow(at[3], c.ip_of(foothold), c.ip_of("dc-decoy-01"), 445, 812, 9),
        (at[4], "windows", _json({"EventID": 1102, "UtcTime": c.iso_ms(at[4]), "Computer": "file-01", "SubjectUserName": "alice"})),
        c.modbus(at[5], "plc-1", c.ip_of("eng-ws-01"), 6, 40001, value),
    ]
    return [Step(ts, source, raw, label) for (ts, source, raw), label in zip(lines, STEP_LABELS)]


def distractor_steps(day: date = ATTACK_DAY) -> list[Step]:
    """INC-0041: svc-backup runs remote tools outside its backup window. Unusual, but it is not the attack, so no label."""
    start = c.at(day, 1, 30, 10)
    second = start + timedelta(seconds=30)
    lines = [
        c.win_proc(start, "file-01", "svc-backup", c.PS, c.SERVICES, "powershell.exe -File C:/scripts/remote.ps1"),
        (c.ms(second), "windows", _json({"EventID": 3, "UtcTime": c.iso_ms(second), "Computer": "file-01", "User": "CORP/svc-backup",
                                         "Image": c.SYS32 + "svchost.exe", "SourceIp": c.ip_of("file-01"),
                                         "DestinationIp": c.ip_of("eng-ws-01"), "DestinationPort": 445})),
        c.win_proc(start + timedelta(seconds=70), "file-01", "svc-backup", "C:/Windows/System32/wbem/WMIC.exe", c.PS,
                   "wmic /node:eng-ws-01 process call create cmd.exe"),
    ]
    return [Step(ts, source, raw) for ts, source, raw in lines]

def pivot_steps(attack: list[Step]) -> list[Step]:
    """The attacker moves on with alice's account: the admin share on file-01 from ws-help-01, then the one on eng-ws-01
    from file-01 (the path in web/mock/graph.json). They are unlabeled: the labels stay the six steps of the fixtures."""
    start = attack[0].ts
    lines = [
        c.win_share(start + timedelta(minutes=20), "file-01", "alice", c.ip_of("ws-help-01")),
        c.win_share(start + timedelta(minutes=22), "eng-ws-01", "alice", c.ip_of("file-01")),
    ]
    return [Step(ts, source, raw) for ts, source, raw in lines]

def pivot_steps(attack: list[Step]) -> list[Step]:
    """The attacker moves on with alice's account: the admin share on file-01 from ws-help-01, then the one on eng-ws-01
    from file-01 (the path in web/mock/graph.json). They are unlabeled: the labels stay the six steps of the fixtures."""
    start = attack[0].ts
    lines = [
        c.win_share(start + timedelta(minutes=20), "file-01", "alice", c.ip_of("ws-help-01")),
        c.win_share(start + timedelta(minutes=22), "eng-ws-01", "alice", c.ip_of("file-01")),
    ]
    return [Step(ts, source, raw) for ts, source, raw in lines]