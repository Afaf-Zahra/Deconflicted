import json
from pathlib import Path

import pytest

from deconflicted import adapters
from deconflicted.ml.tokens import entity_of, event_token
from deconflicted.schema import Event

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}
# Events that are not in the shared fixture file, so these tests do not depend on it having them.
EXTRA_RAW = {
    'windows-784fdbff4513': '{"EventID":1,"UtcTime":"2026-03-04T01:30:10.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","ParentImage":"C:/Windows/System32/services.exe","CommandLine":"powershell.exe -File C:/scripts/remote.ps1"}',
    'windows-6685e540534d': '{"EventID":3,"UtcTime":"2026-03-04T01:30:40.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/svchost.exe","SourceIp":"10.0.2.10","DestinationIp":"10.0.3.5","DestinationPort":445}',
    'windows-5433c7afb25f': '{"EventID":1,"UtcTime":"2026-03-04T01:31:20.000Z","Computer":"file-01","User":"CORP/svc-backup","Image":"C:/Windows/System32/wbem/WMIC.exe","ParentImage":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","CommandLine":"wmic /node:eng-ws-01 process call create cmd.exe"}',
    'windows-bcf7091176b7': '{"EventID":1,"UtcTime":"2026-03-03T10:15:00.000Z","Computer":"ws-help-01","User":"CORP/bob","Image":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","ParentImage":"C:/Windows/explorer.exe","CommandLine":"powershell.exe -Command Set-ADAccountPassword -Identity jdoe"}',
}



@pytest.mark.parametrize("event_id,token", [
    ("windows-3d9b0caf56b1", "proc:powershell_enc"),
    ("windows-784fdbff4513", "proc:powershell_script"),
    ("windows-bcf7091176b7", "proc:powershell"),
    ("windows-df7e20e82366", "proc:nltest"),
    ("windows-5433c7afb25f", "proc:wmic"),
    ("windows-aa7aa68146c4", "auth:logon"),
    ("windows-46ff3d489abb", "log:cleared"),
    ("windows-6685e540534d", "net:smb"),
    ("flow-c7621933881f", "net:decoy_touch"),
    ("modbus-06e981d9288c", "ot:write_setpoint"),
])
def test_fixture_tokens(event_id, token):
    if event_id in EXTRA_RAW:
        event = adapters.get("windows").parse_line(EXTRA_RAW[event_id])
        assert event.id == event_id
    else:
        fixture = FIXTURES[event_id]
        event = Event(**{k: v for k, v in fixture.items() if k != "label"})
    assert event_token(event) == token


def line(source, raw):
    return adapters.get(source).parse_line(raw)


def test_other_table_rows():
    failed = line("windows", '{"EventID":4625,"UtcTime":"2026-03-04T03:40:00.000Z","Computer":"dc-01","TargetUserName":"bob","IpAddress":"10.0.1.21","LogonType":3}')
    assert event_token(failed) == "auth:logon_failed"
    share = line("windows", '{"EventID":5140,"UtcTime":"2026-03-04T01:10:00.000Z","Computer":"file-01","SubjectUserName":"CORP/svc-backup","IpAddress":"10.0.2.30","ShareName":"\\\\\\\\*\\\\C$"}')
    assert event_token(share) == "net:smb_admin"
    assert event_token(line("flow", "2026-03-04T03:48:20Z,10.0.1.21,10.0.2.10,3389,tcp,812,9")) == "net:flow"
    proxy = line("proxy", "1772595600.123 142 10.0.1.21 TCP_MISS/200 5120 GET http://10.0.9.5/x - HIER_DIRECT/10.0.9.5 text/html")
    assert event_token(proxy) == "net:http"
    read = line("modbus", '{"ts":"2026-03-04T04:50:00.000Z","server":"plc-1","client_ip":"10.0.3.5","func":3,"address":40002}')
    assert event_token(read) == "ot:read"
    pump = line("modbus", '{"ts":"2026-03-04T04:50:00.000Z","server":"plc-1","client_ip":"10.0.3.5","func":6,"address":40010,"value":0}')
    assert event_token(pump) == "ot:write_pump"
    other = line("modbus", '{"ts":"2026-03-04T04:50:00.000Z","server":"plc-1","client_ip":"10.0.3.5","func":6,"address":40011,"value":0}')
    assert event_token(other) == "ot:write_other"
    node = line("opcua", '{"ts":"2026-03-04T09:00:05.000Z","server":"opc-1","client_ip":"10.0.3.20","service":"Write","node":"ns=2;s=Tank1.PumpCmd","value":1}')
    assert event_token(node) == "ot:write_pump"
    sudo = line("linux", "Mar  4 09:12:44 bak-01 sudo:  svc-backup : TTY=pts/0 ; PWD=/x ; USER=root ; COMMAND=/usr/bin/rsync -a /a /b")
    assert event_token(sudo) == "proc:rsync"
    net = line("windows", json.dumps({"EventID": 1, "UtcTime": "2026-03-04T03:40:00.000Z", "Computer": "dc-01", "User": "CORP/a",
                                     "Image": "C:/Windows/System32/net1.exe", "CommandLine": "net1 view \\\\dc-01"}))
    assert event_token(net) == "proc:net_view"
    cert = line("windows", json.dumps({"EventID": 1, "UtcTime": "2026-03-04T03:40:00.000Z", "Computer": "dc-01", "User": "CORP/a",
                                      "Image": "C:/Windows/System32/certutil.exe", "CommandLine": "certutil -urlcache -f http://x/a"}))
    assert event_token(cert) == "proc:certutil_download"
    backup = line("windows", json.dumps({"EventID": 1, "UtcTime": "2026-03-04T01:00:00.000Z", "Computer": "bak-01", "User": "CORP/svc-backup",
                                        "Image": "C:/Program Files/Backup/backup.exe", "CommandLine": "backup.exe"}))
    assert event_token(backup) == "proc:backup"


def test_entity_of_prefers_the_user():
    assert entity_of(line("windows", FIXTURES["windows-3d9b0caf56b1"]["raw"])) == "user:alice"
    assert entity_of(line("flow", FIXTURES["flow-c7621933881f"]["raw"])) == "host:ws-help-01"
