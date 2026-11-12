import datetime
import re

import pytest

from deconflicted import adapters
from deconflicted.sim.roles import ACTORS, day_lines

DAY = datetime.date(2026, 3, 4)
DECOY_IPS = {"10.0.2.99", "10.0.4.99"}
EXTERNAL_ATTACKER = "10.0.9.77"


@pytest.fixture(scope="module")
def events():
    return {name: [adapters.get(s).parse_line(r) for s, r in module.lines_for_day(DAY, 1)]
            for name, module in ACTORS.items()}


@pytest.fixture(scope="module")
def all_events(events):
    return [e for group in events.values() for e in group]


def test_same_seed_same_day_and_other_seeds_differ():
    first = day_lines(DAY, 1)
    assert day_lines(DAY, 1) == first
    other = day_lines(DAY, 2)
    assert other != first and abs(len(other) - len(first)) < 0.3 * len(first), "days differ but stay similar in size"
    assert day_lines(datetime.date(2026, 3, 5), 1) != first


def test_every_line_parses_and_the_day_is_sorted_and_big_enough():
    lines = day_lines(DAY, 1)
    assert 15_000 <= len(lines) <= 60_000, f"{len(lines)} lines"
    stamps = [adapters.get(s).parse_line(r).ts for s, r in lines]
    assert stamps == sorted(stamps)
    assert all(ts.date() == DAY for ts in stamps), "every event belongs to the requested day"
    assert {s for s, _ in lines} == set(adapters.ADAPTERS), "all six sources appear"


def test_each_actors_lines_are_time_sorted_and_deterministic():
    for name, module in ACTORS.items():
        lines = module.lines_for_day(DAY, 3)
        stamps = [adapters.get(s).parse_line(r).ts for s, r in lines]
        assert stamps == sorted(stamps), name
        assert module.lines_for_day(DAY, 3) == lines, name


def test_nothing_touches_a_decoy_or_uses_the_attacker_address(all_events):
    for event in all_events:
        assert event.src_ip not in DECOY_IPS and event.dst_ip not in DECOY_IPS, event.raw
        assert event.host not in ("dc-decoy-01", "plc-decoy-1"), event.raw
        assert EXTERNAL_ATTACKER not in event.raw


def test_no_attack_behaviour_in_a_benign_day(all_events):
    for event in all_events:
        assert "-enc" not in (event.cmdline or "").lower() and event.action != "log_clear", event.raw
        assert "certutil" not in (event.process or "") and event.process != "wmic.exe"


def test_setpoint_writes_stay_inside_the_allowed_range(events):
    writes = [e for e in events["carol"] if e.action == "write"]
    assert 2 <= len(writes) <= 4
    assert all(e.obj == "reg:40001" and 40 <= e.value <= 60 and e.host == "plc-1" and e.src_ip == "10.0.3.5" for e in writes)
    others = [e for group in events.values() for e in group if e.action == "write" and e.source == "modbus"]
    assert len(others) == len(writes), "only carol writes to the PLC"


def test_alice(events):
    mine = events["alice"]
    logon = next(e for e in mine if e.action == "logon")
    assert (logon.host, logon.user, logon.obj, logon.src_ip) == ("dc-01", "alice", "logon_type:3", "10.0.1.10")
    assert datetime.time(8, 29) <= logon.ts.time() <= datetime.time(9, 1)
    nltest = [e for e in mine if e.process == "nltest.exe"]
    assert len(nltest) == 2 and all(e.cmdline == "nltest /dclist:corp" and e.host == "ws-admin-01" for e in nltest)
    scripts = [e for e in mine if e.process == "powershell.exe"]
    assert 3 <= len(scripts) <= 6 and all("-File" in e.cmdline for e in scripts)


def test_bob(events):
    resets = [e for e in events["bob"] if e.process == "powershell.exe"]
    assert 4 <= len(resets) <= 12
    assert all(re.fullmatch(r"powershell\.exe -Command Set-ADAccountPassword -Identity \w+", e.cmdline) for e in resets)
    assert all(e.user == "bob" and e.host == "ws-help-01" for e in resets)
    gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(resets, resets[1:]) if (b.ts - a.ts).total_seconds() < 600]
    assert gaps and all(20 <= g <= 61 for g in gaps), "resets inside a burst are 20 to 60 seconds apart"


def test_dave(events):
    reads = [e for e in events["dave"] if e.source == "modbus"]
    assert {e.host for e in reads} == {"plc-1", "plc-2"} and all(e.action == "read" for e in reads)
    assert datetime.time(8) <= min(e.ts for e in reads).time() and max(e.ts for e in reads).time() < datetime.time(17)
    assert 6000 < len(reads) < 7000


def test_svc_backup_stays_in_its_window(events):
    mine = events["svc-backup"]
    runs = [e for e in mine if e.process == "backup.exe"]
    assert len(runs) == 1 and datetime.time(1, 0) <= runs[0].ts.time() <= datetime.time(1, 30)
    for event in mine:
        assert datetime.time(0, 59) <= event.ts.time() <= datetime.time(1, 40), event.raw
    shares = [e for e in mine if e.obj == "C$"]
    assert shares and all(e.host == "file-01" and e.user == "svc-backup" and e.dst_port == 445 for e in shares)
    assert any(e.source == "linux" and e.action == "proc_create" and e.process == "rsync" for e in mine)
    assert any(e.source == "linux" and e.action == "logon" and e.obj == "logon_type:ssh" for e in mine)


def test_background(events):
    mine = events["background"]
    opcua = [e for e in mine if e.source == "opcua"]
    assert 2800 <= len(opcua) <= 2900 and all(e.host == "opc-1" and e.src_ip == "10.0.3.20" for e in opcua)
    proxied = [e for e in mine if e.source == "proxy"]
    assert proxied and all(e.dst_ip == "10.0.9.5" for e in proxied)
    assert {e.host for e in proxied} <= {"ws-admin-01", "ws-help-01"}


def test_users_are_known(all_events):
    allowed = {"alice", "bob", "carol", "dave", "svc-backup", "SYSTEM", None}
    assert {e.user for e in all_events} <= allowed
