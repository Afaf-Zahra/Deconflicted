import contextlib
import io
import json
import shutil
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from deconflicted import adapters
from deconflicted.adapters.hosts import config_dir
from deconflicted.core.baseline import START, Baseline, BaselineError
from deconflicted.core.config import CoreConfigError, ModelSettings, Routine, load_config
from deconflicted.core.entities import actor_of, entities_of, host_entity, role_of
from deconflicted.core.explain import main as explain
from deconflicted.core.invariants import Invariants
from deconflicted.core.routines import RoutineRegistry
from deconflicted.schema import Event
from deconflicted.sim.build import main as build

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}
LOGON, ENC, NLTEST, DECOY, CLEAR, WRITE = ("windows-aa7aa68146c4", "windows-3d9b0caf56b1", "windows-df7e20e82366",
                                           "flow-c7621933881f", "windows-46ff3d489abb", "modbus-06e981d9288c")
CONFIG = load_config()
_numbers = iter(range(1, 10**9))


def fixture(event_id):
    return Event(**{k: v for k, v in FIXTURES[event_id].items() if k != "label"})


def at(day, hour, minute=0):
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc)


def moment(hour, minute=0, second=0):
    return datetime(2026, 3, 4, hour, minute, second, tzinfo=timezone.utc)


def synth(ts, action, host, user=None, process=None, cmdline=None, src_ip=None, obj=None):
    n = next(_numbers)
    return Event(id=f"windows-t{n:08d}", ts=ts, source="windows", host=host, user=user, process=process,
                 cmdline=cmdline, src_ip=src_ip, action=action, obj=obj, raw=f"synthetic {n}")


def normal_day(day):
    return [
        synth(at(day, 8, 45), "logon", "dc-01", "alice", src_ip="10.0.1.10", obj="logon_type:3"),
        synth(at(day, 9, 15), "proc_create", "ws-admin-01", "alice", "nltest.exe", "nltest /dclist:corp"),
        synth(at(day, 9, 30), "proc_create", "ws-admin-01", "alice", "powershell.exe",
              "powershell.exe -File C:/admin/cleanup.ps1"),
        synth(at(day, 10, 15), "proc_create", "ws-help-01", "bob", "powershell.exe",
              "powershell.exe -Command Set-ADAccountPassword -Identity jdoe"),
    ]


TRAIN_DAYS = [date(2026, 3, 1) + timedelta(days=3 * i) for i in range(10)]  # three days apart: no context carries over


def trained():
    model = Baseline(CONFIG)
    assert model.fit([e for d in TRAIN_DAYS for e in normal_day(d)]) == 40
    return model


def quiet(func, argv):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = func(argv)
    return code, buffer.getvalue()


def ot_write(value, client_ip="10.0.3.5", address=40001):
    data = {"ts": "2026-03-04T10:00:00.000Z", "server": "plc-1", "client_ip": client_ip, "func": 6, "address": address}
    if value is not None:
        data["value"] = value
    return adapters.get("modbus").parse_line(json.dumps(data))


# ---------------------------------------------------------------- config and entities
def test_the_config_files_are_read():
    assert CONFIG.user_roles["alice"] == "admin" and CONFIG.host_roles["bak-01"] == "service"
    assert (CONFIG.model.window_hours, CONFIG.model.alpha, CONFIG.model.backoff_n) == (24.0, 1.0, 20.0)
    assert {"helpdesk_password_reset", "ad_health_check", "nightly_backup"} <= {r.id for r in CONFIG.routines}
    backup = next(r for r in CONFIG.routines if r.id == "nightly_backup")
    assert backup.steps == ("proc:backup",) and (backup.window[0].hour, backup.window[1].minute) == (1, 30)
    rules = {r.id: r for r in CONFIG.invariants}
    assert (rules["setpoint_range"].register, rules["setpoint_range"].minimum, rules["setpoint_range"].maximum) == ("40001", 40.0, 60.0)
    assert rules["writer_allowlist"].allowed_sources == ("host:eng-ws-01",)
    assert CONFIG.attack_map["proc:powershell_enc"] == ("Execution", "T1059.001")
    assert "dc-decoy-01" in CONFIG.decoy_hosts and CONFIG.hosts["plc-1"]["kind"] == "plc"


def test_a_broken_config_names_the_file(tmp_path):
    folder = tmp_path / "config"
    shutil.copytree(config_dir(), folder)
    (folder / "routines.yaml").write_text("routines:\n  - id: broken\n", encoding="utf-8")
    with pytest.raises(CoreConfigError, match="routines.yaml"):
        load_config(folder)
    with pytest.raises(CoreConfigError, match="roles.yaml"):
        load_config(tmp_path / "empty")


def test_entities_roles_and_actors_follow_the_conventions():
    logon, clear, write, decoy = fixture(LOGON), fixture(CLEAR), fixture(WRITE), fixture(DECOY)
    assert entities_of(logon, CONFIG) == ["host:ws-help-01", "user:alice"]
    assert entities_of(clear, CONFIG) == ["host:file-01", "user:alice"]
    assert entities_of(write, CONFIG) == ["plc:plc-1", "host:eng-ws-01"]
    assert entities_of(decoy, CONFIG) == ["host:ws-help-01"]
    assert actor_of(logon, CONFIG) == "user:alice" and actor_of(write, CONFIG) == "host:eng-ws-01"
    assert actor_of(decoy, CONFIG) == "host:ws-help-01"
    assert role_of("user:alice", CONFIG) == "admin" and role_of("host:eng-ws-01", CONFIG) == "engineer"


def test_hosts_get_their_entity_prefix_and_strangers_the_role_other():
    assert host_entity("plc-1", CONFIG) == "plc:plc-1"
    assert host_entity("dc-decoy-01", CONFIG) == "decoy:dc-decoy-01"
    assert host_entity("ws-help-01", CONFIG) == "host:ws-help-01"
    assert host_entity("10.0.9.77", CONFIG) == "host:10.0.9.77"
    assert role_of("user:eve", CONFIG) == "other" and role_of("host:plc-1", CONFIG) == "other"


# ---------------------------------------------------------------- the baseline
def test_a_normal_day_scores_low():
    model = trained()
    scores = [model.observe(e).score for e in normal_day(date(2026, 4, 1))]
    assert max(scores) < 0.8, scores


def test_a_behaviour_the_role_never_shows_ranks_at_the_top():
    model, day = trained(), date(2026, 4, 1)
    model.observe(normal_day(day)[0])  # alice logs on as usual
    strange = model.observe(synth(at(day, 9, 5), "proc_create", "ws-admin-01", "alice", "powershell.exe",
                                  "powershell.exe -enc JABzAD0A"))
    assert (strange.token, strange.previous, strange.role) == ("proc:powershell_enc", "auth:logon", "admin")
    assert strange.sequence_score == 1.0 and strange.score == 1.0 and strange.reason == "sequence"


def test_a_logon_at_an_odd_hour_is_caught_by_the_hour_measure():
    model = trained()
    odd = model.observe(synth(at(date(2026, 4, 2), 3, 40), "logon", "dc-01", "alice", src_ip="10.0.1.21", obj="logon_type:3"))
    assert odd.token == "auth:logon"
    assert odd.hour_score >= 0.99 and odd.hour_score > odd.sequence_score and odd.reason == "hour"


def test_an_untrained_baseline_scores_zero():
    event = synth(at(date(2026, 4, 1), 3), "proc_create", "ws-admin-01", "alice", "nltest.exe", "nltest")
    assert Baseline(CONFIG).observe(event).score == 0.0


def test_the_context_expires_after_the_window_and_older_events_are_not_context():
    day = date(2026, 3, 1)

    def nltest(hour, minute=0, days=0):
        return synth(at(day, hour, minute) + timedelta(days=days), "proc_create", "ws-admin-01", "alice", "nltest.exe", "nltest")

    def script(hour, minute=0):
        return synth(at(day, hour, minute), "proc_create", "ws-admin-01", "alice", "powershell.exe", "powershell.exe -File a.ps1")

    model = Baseline(CONFIG)
    assert model.observe(nltest(9)).previous == START
    assert model.observe(script(10)).previous == "proc:nltest"
    assert model.observe(synth(at(day, 10) + timedelta(hours=25), "proc_create", "ws-admin-01", "alice", "nltest.exe", "nltest")).previous == START
    model.reset()
    model.observe(nltest(10))
    assert model.observe(script(9)).previous == START  # older than the last event: no context, and it does not replace it
    assert model.observe(script(10, 5)).previous == "proc:nltest"


def test_a_saved_baseline_scores_exactly_like_the_one_it_came_from(tmp_path):
    model, path = trained(), tmp_path / "model" / "baseline.json"
    model.save(path)
    loaded = Baseline.load(path, CONFIG)
    day = date(2026, 4, 1)
    events = normal_day(day) + [synth(at(day, 11), "proc_create", "ws-admin-01", "alice", "powershell.exe", "powershell.exe -enc AAAA")]
    for event in events:
        assert loaded.observe(event) == model.observe(event)
    assert loaded.trained_events == 40 and loaded.vocab == model.vocab


def test_a_wrong_saved_baseline_is_refused(tmp_path):
    path = tmp_path / "baseline.json"
    trained().save(path)
    with pytest.raises(BaselineError, match="different model settings"):
        Baseline.load(path, replace(CONFIG, model=ModelSettings(24.0, 1.0, 5.0)))
    (tmp_path / "junk.json").write_text("not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        Baseline.load(tmp_path / "junk.json", CONFIG)
    with pytest.raises(BaselineError):
        Baseline.load(tmp_path / "missing.json", CONFIG)


# ---------------------------------------------------------------- routines
def test_routine_steps_match_by_role_host_and_time():
    routines = RoutineRegistry(CONFIG)
    ok = routines.check("proc:nltest", "user:alice", "admin", "ws-admin-01", moment(9, 15))
    assert (ok.status, ok.routine_id) == ("matched", "ad_health_check")
    wrong_host = routines.check("proc:nltest", "user:alice", "admin", "ws-help-01", moment(3, 48))
    assert wrong_host.status == "broken" and "ws-admin-01" in wrong_host.reason
    wrong_role = routines.check("proc:nltest", "user:bob", "helpdesk", "ws-help-01", moment(10))
    assert wrong_role.status == "broken" and "admin role" in wrong_role.reason
    assert routines.check("proc:powershell", "user:bob", "helpdesk", "ws-help-01", moment(10, 15)).status == "matched"
    assert routines.check("proc:powershell_enc", "user:alice", "admin", "ws-help-01", moment(3, 43)).status == "none"
    backup = lambda when: routines.check("proc:backup", "user:svc-backup", "service", "bak-01", when)
    assert backup(moment(1, 10)).status == "matched" and backup(moment(1, 30)).status == "matched"
    late = backup(moment(2, 0))
    assert late.status == "broken" and "01:00 and 01:30" in late.reason
    assert backup(moment(1, 30, 1)).status == "broken"


def test_multi_step_routines_follow_their_order_and_gap():
    pair = Routine(id="pair", role="admin", steps=("proc:nltest", "proc:wmic"), max_gap_seconds=60.0)
    routines = RoutineRegistry(replace(CONFIG, routines=(pair,)))
    start = moment(9)

    def step(token, seconds):
        return routines.check(token, "user:alice", "admin", "ws-admin-01", start + timedelta(seconds=seconds)).status

    assert step("proc:nltest", 0) == "matched"
    assert step("proc:wmic", 30) == "matched"      # the pair is complete
    assert step("proc:wmic", 40) == "broken"       # a second wmic has no nltest before it
    assert step("proc:nltest", 100) == "matched"
    assert step("proc:wmic", 190) == "broken"      # 90 seconds is more than the 60 allowed
    routines.reset()
    assert step("proc:wmic", 300) == "broken"


# ---------------------------------------------------------------- OT invariants
def test_ot_writes_outside_the_range_are_certain_signals():
    invariants = Invariants(CONFIG)
    assert invariants.check(ot_write(50)) is None
    signal = invariants.check(fixture(WRITE))
    assert (signal.kind, signal.score, signal.event_ids) == ("ot_invariant", 1.0, [WRITE])
    assert signal.entity_ids == ["plc:plc-1", "host:eng-ws-01"] and signal.techniques == ["T0836", "T0855"]
    assert signal.detail == {"rule": "setpoint_range", "limit": "40 to 60", "value": 95}
    assert isinstance(signal.detail["value"], int)
    opcua = adapters.get("opcua").parse_line(json.dumps({
        "ts": "2026-03-04T10:00:00.000Z", "server": "opc-1", "client_ip": "10.0.3.5", "service": "Write",
        "node": "ns=2;s=Tank1.Setpoint", "value": 90}))
    alias = invariants.check(opcua)
    assert alias.detail["rule"] == "setpoint_range" and alias.entity_ids == ["host:opc-1", "host:eng-ws-01"]


def test_the_writer_allowlist_and_the_cases_that_are_not_breaks():
    invariants = Invariants(CONFIG)
    stranger = invariants.check(ot_write(50, client_ip="10.0.1.21"))
    assert stranger.detail == {"rule": "writer_allowlist", "source": "host:ws-help-01", "allowed": ["host:eng-ws-01"]}
    assert stranger.techniques == []
    both = invariants.check(ot_write(95, client_ip="10.0.1.21"))
    assert both.detail["rule"] == "setpoint_range" and both.detail["also"] == ["writer_allowlist"]
    assert both.techniques == ["T0836", "T0855"]
    assert invariants.check(ot_write(99, address=40002)) is None                    # another register
    assert invariants.check(ot_write(None)) is None                                 # no number to judge, allowed source
    read = adapters.get("modbus").parse_line(json.dumps({
        "ts": "2026-03-04T10:00:00.000Z", "server": "plc-1", "client_ip": "10.0.3.5", "func": 3, "address": 40001, "value": 95}))
    assert invariants.check(read) is None                                           # only writes are checked


# ---------------------------------------------------------------- the explain tool
def test_the_explain_tool_trains_shows_and_saves(tmp_path):
    assert quiet(build, ["--out", str(tmp_path / "data"), "--benign-days", "3"])[0] == 0
    benign, scenario, model = tmp_path / "data" / "benign", tmp_path / "data" / "demo" / "scenario.jsonl", tmp_path / "model.json"
    code, text = quiet(explain, ["--train", str(benign), "--show", str(scenario), "--save", str(model)])
    assert code == 0 and "learned from" in text and "the attack events" in text and model.exists()
    assert all(f"attack step {n}" in text for n in (1, 2, 3, 7, 9))
    code, again = quiet(explain, ["--model", str(model), "--show", str(scenario)])
    assert code == 0 and "loaded the baseline" in again
    assert quiet(explain, ["--train", str(tmp_path / "missing")])[0] == 1