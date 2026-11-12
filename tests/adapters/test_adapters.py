import json
from pathlib import Path

import pytest

from deconflicted import adapters
from deconflicted.adapters import AdapterError, linux, modbus, opcua, proxy, windows
from deconflicted.schema import Event

FIXTURES = json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f["id"] for f in FIXTURES])
def test_fixture_raw_line_gives_the_same_event(fixture):
    expected = {k: v for k, v in fixture.items() if k != "label"}
    event = adapters.get(fixture["source"]).parse_line(fixture["raw"])
    assert event == Event(**expected), f"adapter output differs for {fixture['id']}"


def test_proxy_sample():
    line = "1772595600.123    142 10.0.1.21 TCP_MISS/200 5120 GET http://10.0.9.5/pkg/update.tar - HIER_DIRECT/10.0.9.5 text/html"
    event = proxy.parse_line(line)
    assert event.ts.isoformat() == "2026-03-04T03:40:00.123000+00:00"
    assert (event.host, event.src_ip, event.dst_ip, event.dst_port) == ("ws-help-01", "10.0.1.21", "10.0.9.5", 80)
    assert (event.action, event.obj, event.value, event.user) == ("http_request", "http://10.0.9.5/pkg/update.tar", 5120.0, None)
    assert event.id.startswith("proxy-") and event.raw == line


def test_proxy_https_port_and_ident():
    line = "1772595600.000 10 10.0.1.10 TCP_MISS/200 99 GET https://10.0.9.5/x alice HIER_DIRECT/10.0.9.5 text/html"
    event = proxy.parse_line(line)
    assert event.dst_port == 443 and event.user == "alice"


def test_linux_samples():
    accepted = linux.parse_line("Mar  4 01:00:03 bak-01 sshd[2211]: Accepted publickey for svc-backup from 10.0.2.10 port 40122 ssh2")
    assert (accepted.action, accepted.user, accepted.src_ip, accepted.obj, accepted.host) == (
        "logon", "svc-backup", "10.0.2.10", "logon_type:ssh", "bak-01")
    assert accepted.ts.isoformat() == "2026-03-04T01:00:03+00:00"
    failed = linux.parse_line("Mar  4 02:10:44 bak-01 sshd[2301]: Failed password for invalid user admin from 10.0.1.21 port 50111 ssh2")
    assert (failed.action, failed.user, failed.src_ip, failed.obj) == ("logon", "admin", "10.0.1.21", "failed")
    sudo = linux.parse_line("Mar  4 09:12:44 bak-01 sudo:  svc-backup : TTY=pts/0 ; PWD=/home/svc-backup ; USER=root ; COMMAND=/usr/bin/rsync -a /srv/share /backup")
    assert (sudo.action, sudo.user, sudo.process, sudo.cmdline) == (
        "proc_create", "svc-backup", "rsync", "/usr/bin/rsync -a /srv/share /backup")


def test_linux_year_parameter_and_unsupported_message():
    event = linux.parse_line("Mar  4 01:00:03 bak-01 sshd[1]: Accepted publickey for a from 10.0.2.10 port 1 ssh2", year=2025)
    assert event.ts.year == 2025
    with pytest.raises(AdapterError):
        linux.parse_line("Mar  4 01:00:03 bak-01 cron[1]: job started")


def test_opcua_samples():
    write = opcua.parse_line('{"ts":"2026-03-04T09:00:05.000Z","server":"opc-1","client_ip":"10.0.3.20","service":"Write","node":"ns=2;s=Tank1.Setpoint","value":55}')
    assert (write.host, write.src_ip, write.dst_port, write.action, write.obj, write.value) == (
        "opc-1", "10.0.3.20", 4840, "write", "ns=2;s=Tank1.Setpoint", 55.0)
    read = opcua.parse_line('{"ts":"2026-03-04T09:00:05.000Z","server":"opc-1","client_ip":"10.0.3.20","service":"Read","node":"ns=2;s=Tank1.Level","value":51.3}')
    assert read.action == "read" and read.value == 51.3


def test_windows_backslash_user_and_domain_host():
    line = json.dumps({"EventID": 1, "UtcTime": "2026-03-04T03:43:02.110Z", "Computer": "WS-HELP-01.corp.local",
                       "User": "CORP\\alice", "Image": "C:\\Windows\\System32\\PowerShell.EXE",
                       "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": "powershell.exe"})
    event = windows.parse_line(line)
    assert (event.user, event.process, event.parent_process, event.host) == ("alice", "powershell.exe", "explorer.exe", "ws-help-01")


def test_windows_failed_logon_and_admin_share():
    failed = windows.parse_line('{"EventID":4625,"UtcTime":"2026-03-04T03:40:00.000Z","Computer":"dc-01","TargetUserName":"bob","IpAddress":"10.0.1.21","LogonType":3}')
    assert failed.obj == "failed"
    share = windows.parse_line('{"EventID":5140,"UtcTime":"2026-03-04T01:10:00.000Z","Computer":"file-01","SubjectUserName":"CORP\\\\svc-backup","IpAddress":"10.0.2.30","ShareName":"\\\\\\\\*\\\\C$"}')
    assert (share.action, share.obj, share.dst_port, share.user) == ("net_conn", "C$", 445, "svc-backup")


@pytest.mark.parametrize("module,line", [
    (windows, "not json"),
    (windows, '{"EventID":9999,"UtcTime":"2026-03-04T03:40:00Z","Computer":"dc-01"}'),
    (windows, '{"EventID":1102,"UtcTime":"2026-03-04 04:20:00","Computer":"file-01"}'),
    (windows, '{"EventID":1102,"UtcTime":"2026-03-04T04:20:00Z"}'),
    (modbus, '{"ts":"2026-03-04T04:50:00Z","server":"plc-1","client_ip":"10.0.3.5","func":99,"address":1}'),
    (modbus, '{"ts":"2026-03-04T04:50:00","server":"plc-1","client_ip":"10.0.3.5","func":6,"address":1,"value":1}'),
    (opcua, '{"ts":"2026-03-04T09:00:05Z","server":"opc-1","service":"Browse","node":"x"}'),
    (proxy, "too short"),
    (adapters.flow, "2026-03-04T03:48:20Z,10.0.1.21,10.0.2.99,445"),
    (adapters.flow, "2026-03-04T03:48:20,10.0.1.21,10.0.2.99,445,tcp,812,9"),
])
def test_bad_lines_raise_adapter_error_with_location(module, line):
    with pytest.raises(AdapterError) as err:
        module.parse_line(line, file="x.log", lineno=7)
    assert "x.log:7" in str(err.value), "error must name the file and line"


def test_parse_file_reports_line_number(tmp_path):
    path = tmp_path / "win.jsonl"
    good = FIXTURES[0]["raw"]
    path.write_text(f"{good}\n\nnot json\n", encoding="utf-8")
    events = windows.parse_file(path)
    assert next(events).id == FIXTURES[0]["id"]
    with pytest.raises(AdapterError) as err:
        next(events)
    assert f"{path}:3" in str(err.value)


def test_same_line_same_id_and_registry():
    raw = FIXTURES[3]["raw"]
    assert adapters.get("flow").parse_line(raw).id == adapters.get("flow").parse_line(raw).id
    with pytest.raises(AdapterError):
        adapters.get("nope")
    assert set(adapters.ADAPTERS) == {"windows", "proxy", "flow", "linux", "modbus", "opcua"}


def test_resolve_ip_known_and_unknown():
    assert adapters.resolve_ip("10.0.1.21") == "ws-help-01"
    assert adapters.resolve_ip("10.0.2.99") == "dc-decoy-01"
    assert adapters.resolve_ip("10.0.9.77") == "ext-host-77"
    assert adapters.resolve_ip("10.9.9.9") == "10.9.9.9"


# Events from the scenario's other incidents. They are written out here so these checks do not depend on
# which events the shared fixture file contains.
EXTRA = [
    ('{"EventID":1,"UtcTime":"2026-03-04T01:30:10.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","ParentImage":"C:/Windows/System32/services.exe","CommandLine":"powershell.exe -File C:/scripts/remote.ps1"}', 'windows-784fdbff4513', {'ts': '2026-03-04T01:30:10Z', 'host': 'file-01', 'user': 'svc-backup', 'process': 'powershell.exe', 'parent_process': 'services.exe', 'cmdline': 'powershell.exe -File C:/scripts/remote.ps1', 'action': 'proc_create'}),
    ('{"EventID":3,"UtcTime":"2026-03-04T01:30:40.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/svchost.exe","SourceIp":"10.0.2.10","DestinationIp":"10.0.3.5","DestinationPort":445}', 'windows-6685e540534d', {'ts': '2026-03-04T01:30:40Z', 'host': 'file-01', 'user': 'svc-backup', 'process': 'svchost.exe', 'src_ip': '10.0.2.10', 'dst_ip': '10.0.3.5', 'dst_port': 445, 'action': 'net_conn'}),
    ('{"EventID":1,"UtcTime":"2026-03-04T01:31:20.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/wbem/WMIC.exe","ParentImage":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","CommandLine":"wmic /node:eng-ws-01 process call create cmd.exe"}', 'windows-5433c7afb25f', {'ts': '2026-03-04T01:31:20Z', 'host': 'file-01', 'user': 'svc-backup', 'process': 'wmic.exe', 'parent_process': 'powershell.exe', 'cmdline': 'wmic /node:eng-ws-01 process call create cmd.exe', 'action': 'proc_create'}),
    ('{"EventID":1,"UtcTime":"2026-03-03T10:15:00.000Z","Computer":"ws-help-01","User":"CORP/bob","Image":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","ParentImage":"C:/Windows/explorer.exe","CommandLine":"powershell.exe -Command Set-ADAccountPassword -Identity jdoe"}', 'windows-bcf7091176b7', {'ts': '2026-03-03T10:15:00Z', 'host': 'ws-help-01', 'user': 'bob', 'process': 'powershell.exe', 'parent_process': 'explorer.exe', 'cmdline': 'powershell.exe -Command Set-ADAccountPassword -Identity jdoe', 'action': 'proc_create'}),
    ('{"EventID":1,"UtcTime":"2026-03-03T10:15:40.000Z","Computer":"ws-help-01","User":"CORP/bob","Image":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","ParentImage":"C:/Windows/explorer.exe","CommandLine":"powershell.exe -Command Set-ADAccountPassword -Identity asmith"}', 'windows-c6fef2e84009', {'ts': '2026-03-03T10:15:40Z', 'host': 'ws-help-01', 'user': 'bob', 'process': 'powershell.exe', 'parent_process': 'explorer.exe', 'cmdline': 'powershell.exe -Command Set-ADAccountPassword -Identity asmith', 'action': 'proc_create'}),
]


@pytest.mark.parametrize("raw,event_id,expected", EXTRA, ids=[c[1] for c in EXTRA])
def test_extra_scenario_events(raw, event_id, expected):
    event = windows.parse_line(raw)
    assert event.id == event_id
    assert Event(**{**expected, "id": event_id, "source": "windows", "raw": raw}) == event


def test_sysmon_time_without_a_zone_is_utc_only_when_asked():
    raw = '{"EventID":1102,"UtcTime":"2026-03-04 04:20:00.250","Computer":"file-01","SubjectUserName":"alice"}'
    with pytest.raises(AdapterError, match="no time zone"):
        windows.parse_line(raw)
    event = windows.parse_line(raw, assume_utc=True)
    assert event.ts.isoformat() == "2026-03-04T04:20:00.250000+00:00" and event.raw == raw
    assert event.id == f"windows-{__import__('hashlib').sha1(raw.encode()).hexdigest()[:12]}", "the id comes from the unchanged line"


def test_parse_file_can_assume_utc(tmp_path):
    path = tmp_path / "sysmon.jsonl"
    path.write_text('{"EventID":1102,"UtcTime":"2026-03-04 04:20:00.000","Computer":"file-01","SubjectUserName":"alice"}\n')
    assert next(windows.parse_file(path, assume_utc=True)).ts.hour == 4
    with pytest.raises(AdapterError):
        next(windows.parse_file(path))


@pytest.mark.parametrize("module,line", [
    (adapters.flow, "2026-03-04 03:48:20,10.0.1.21,10.0.2.99,445,tcp,812,9"),
    (modbus, '{"ts":"2026-03-04 04:50:00.000","server":"plc-1","client_ip":"10.0.3.5","func":6,"address":40001,"value":95}'),
    (opcua, '{"ts":"2026-03-04 09:00:05.000","server":"opc-1","client_ip":"10.0.3.20","service":"Read","node":"ns=2;s=Tank1.Level"}'),
])
def test_assume_utc_covers_every_json_and_csv_adapter(module, line):
    with pytest.raises(AdapterError, match="no time zone"):
        module.parse_line(line)
    assert module.parse_line(line, assume_utc=True).ts.utcoffset().total_seconds() == 0


def test_every_adapter_accepts_assume_utc_so_the_ingest_layer_can_call_them_alike():
    samples = {
        "windows": FIXTURES[0]["raw"], "flow": FIXTURES[3]["raw"], "modbus": FIXTURES[5]["raw"],
        "proxy": "1772595600.123 142 10.0.1.21 TCP_MISS/200 5120 GET http://10.0.9.5/x - HIER_DIRECT/10.0.9.5 text/html",
        "linux": "Mar  4 01:00:03 bak-01 sshd[1]: Accepted publickey for svc-backup from 10.0.2.10 port 1 ssh2",
        "opcua": '{"ts":"2026-03-04T09:00:05.000Z","server":"opc-1","client_ip":"10.0.3.20","service":"Read","node":"n"}',
    }
    assert set(samples) == set(adapters.ADAPTERS)
    for source, raw in samples.items():
        assert adapters.get(source).parse_line(raw, assume_utc=True) == adapters.get(source).parse_line(raw), source
