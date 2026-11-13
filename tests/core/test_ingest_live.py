import json

import pytest

from deconflicted.adapters.common import AdapterError, make_id
from deconflicted.core.pipeline import Pipeline
from deconflicted.core.service import set_pipeline
from deconflicted.ingest.follow import Follower
from deconflicted.ingest.live import canonical, parse_item
from deconflicted.ingest.mapper import load_mappings
from deconflicted.ledger import service as ledger_service
from deconflicted.ledger.transport import in_process_client

WINDOWS = {"EventID": 4624, "UtcTime": "2026-03-04T03:40:00.000Z", "Computer": "dc-01", "TargetUserName": "alice",
           "IpAddress": "10.0.1.21", "LogonType": 3}
MODBUS = {"ts": "2026-03-04T04:50:00.000Z", "server": "plc-1", "client_ip": "10.0.3.5", "func": 6, "address": 40001, "value": 95}
EDR_MAP = """
name: edr
source: windows
format: json
detect: {has: [event.kind, host.name]}
timestamp: {field: "@timestamp", format: iso}
action:
  field: event.kind
  map: {process_start: proc_create}
fields: {host: host.name, user: user.name, process: process.executable, cmdline: process.command_line}
"""
EDR_RECORD = {"@timestamp": "2026-03-04T05:00:00Z", "event": {"kind": "process_start"}, "host": {"name": "WS-HELP-01"},
              "user": {"name": "CORP\\alice"},
              "process": {"executable": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd /c whoami"}}
WIN = json.dumps(WINDOWS)
FLOW = "2026-03-04T03:48:20Z,10.0.1.21,10.0.2.99,445,tcp,812,9"


# ---------------------------------------------------------------- one JSON object to an event
def test_a_json_record_is_recognized_and_parsed_like_its_log_line():
    event = parse_item(WINDOWS)
    assert (event.source, event.host, event.user, event.action) == ("windows", "dc-01", "alice", "logon")
    assert event.raw == canonical(WINDOWS) and event.id == make_id("windows", canonical(WINDOWS))
    assert parse_item(dict(reversed(list(WINDOWS.items())))).id == event.id  # key order does not change the id
    assert parse_item(MODBUS).source == "modbus"
    assert parse_item({"source": "windows", "raw": WIN}).raw == WIN  # a replay item keeps its own text


def test_unknown_json_and_wrong_choices_are_refused_with_a_reason():
    with pytest.raises(AdapterError, match="cannot tell"):
        parse_item({"hello": "world"})
    with pytest.raises(AdapterError, match="expected a JSON object"):
        parse_item([1, 2])
    assert parse_item(WINDOWS, source="windows").source == "windows"
    with pytest.raises(AdapterError):
        parse_item(WINDOWS, source="modbus")
    with pytest.raises(AdapterError, match="no mapping named"):
        parse_item(WINDOWS, mapping="nope")


def test_a_json_shape_nobody_built_in_is_read_with_a_mapping(tmp_path):
    (tmp_path / "edr.yaml").write_text(EDR_MAP, encoding="utf-8")
    mappings = load_mappings(tmp_path)
    event = parse_item(EDR_RECORD, mappings=mappings)
    assert (event.host, event.user, event.process, event.action) == ("ws-help-01", "alice", "cmd.exe", "proc_create")
    assert parse_item(EDR_RECORD, mapping="edr", mappings=mappings).id == event.id


# ---------------------------------------------------------------- POST /ingest/json
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DECONFLICTED_LEDGER_NODES", raising=False)
    monkeypatch.setenv("DECONFLICTED_LEDGER_EMBEDDED", "1")
    monkeypatch.setenv("DECONFLICTED_LEDGER_DB", str(tmp_path / "client.db"))
    monkeypatch.setattr(ledger_service, "_client", None)
    monkeypatch.setattr(ledger_service, "_integrity", None)
    set_pipeline(Pipeline())
    from deconflicted.api.main import app
    http = in_process_client(app)
    yield http
    http.close()
    if ledger_service._client is not None:
        ledger_service._client.close()
    set_pipeline(None)


def test_json_events_are_taken_in_every_shape(client):
    assert client.post("/ingest/json", json=WINDOWS).json() == {"accepted": 1, "errors": [], "incidents": 0}
    later = WINDOWS | {"UtcTime": "2026-03-04T03:41:00.000Z"}
    assert client.post("/ingest/json", json=[later, MODBUS]).json()["accepted"] == 2
    wrapped = {"events": [{"source": "windows", "raw": json.dumps(WINDOWS | {"UtcTime": "2026-03-04T03:42:00.000Z"})}]}
    assert client.post("/ingest/json", json=wrapped).json()["accepted"] == 1
    records = {"Records": [WINDOWS | {"UtcTime": "2026-03-04T03:45:00.000Z"}]}
    assert client.post("/ingest/json", json=records).json()["accepted"] == 1
    lines = "\n".join(json.dumps(WINDOWS | {"UtcTime": f"2026-03-04T03:4{n}:00.000Z"}) for n in (3, 4)).encode()
    result = client.post("/ingest/json", content=lines, headers={"Content-Type": "application/x-ndjson"}).json()
    assert result["accepted"] == 2


def test_json_errors_are_reported_by_position_and_the_rest_goes_through(client):
    result = client.post("/ingest/json", json=[WINDOWS, {"hello": "world"}, 5]).json()
    assert result["accepted"] == 1 and [e["index"] for e in result["errors"]] == [1, 2]
    assert "cannot tell" in result["errors"][0]["error"]
    assert client.post("/ingest/json", content=b"").status_code == 400
    assert client.post("/ingest/json", content=b"not json at all").status_code == 400


def test_forcing_a_source_and_reading_the_event_back(client):
    assert client.post("/ingest/json", params={"source": "windows"}, json=WINDOWS).json()["accepted"] == 1
    event_id = make_id("windows", canonical(WINDOWS))
    assert [e["id"] for e in client.get("/events", params={"ids": event_id}).json()] == [event_id]
    bad = client.post("/ingest/json", params={"source": "modbus"}, json=WINDOWS).json()
    assert bad["accepted"] == 0 and len(bad["errors"]) == 1


# ---------------------------------------------------------------- following files
class Sink:
    def __init__(self):
        self.batches = []
        self.fail = False

    def __call__(self, items):
        if self.fail:
            raise RuntimeError("api is down")
        self.batches.append(items)
        return 0


def test_new_lines_are_sent_as_they_are_written(tmp_path):
    log = tmp_path / "events.log"
    log.write_text(WIN + "\n", encoding="utf-8")
    sink = Sink()
    follower = Follower(log, sink)  # only lines written from now on
    assert follower.poll() == 0 and sink.batches == []
    new_line = WIN.replace("03:40", "03:41")
    with log.open("a", encoding="utf-8") as handle:
        handle.write(new_line + "\n")
    assert follower.poll() == 1
    assert sink.batches == [[{"source": "windows", "raw": new_line}]]
    assert follower.poll() == 0


def test_a_half_written_line_waits_for_its_end(tmp_path):
    log = tmp_path / "flow.csv"
    log.write_text("", encoding="utf-8")
    sink = Sink()
    follower = Follower(log, sink, from_start=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(FLOW[:20])
    assert follower.poll() == 0
    with log.open("a", encoding="utf-8") as handle:
        handle.write(FLOW[20:] + "\n")
    assert follower.poll() == 1
    assert sink.batches[0] == [{"source": "flow", "raw": FLOW}]


def test_a_file_that_is_cut_shorter_is_read_again_from_its_start(tmp_path):
    log = tmp_path / "flow.csv"
    log.write_text(FLOW + "\n" + FLOW + "\n", encoding="utf-8")
    follower = Follower(log, Sink(), from_start=True)
    assert follower.poll() == 2
    log.write_text(FLOW + "\n", encoding="utf-8")  # rotated: shorter than before
    assert follower.poll() == 1


def test_a_failed_send_is_tried_again_and_nothing_is_lost(tmp_path):
    log = tmp_path / "flow.csv"
    log.write_text(FLOW + "\n", encoding="utf-8")
    sink = Sink()
    sink.fail = True
    follower = Follower(log, sink, from_start=True)
    assert follower.poll() == 0 and "api is down" in follower.error
    sink.fail = False
    assert follower.poll() == 1 and follower.error is None


def test_a_folder_is_followed_including_files_that_appear_later(tmp_path):
    sink = Sink()
    follower = Follower(tmp_path, sink)
    assert follower.poll() == 0
    (tmp_path / "late.log").write_text(WIN + "\n", encoding="utf-8")  # appears after the start: read from its first line
    (tmp_path / "notes.txt").write_text("nothing to see\n", encoding="utf-8")
    (tmp_path / ".hidden").write_text(WIN + "\n", encoding="utf-8")
    assert follower.poll() == 1
    assert sink.batches[0][0]["source"] == "windows"


def test_replay_lines_headers_and_bad_lines(tmp_path):
    (tmp_path / "scenario.jsonl").write_text(json.dumps({"source": "flow", "raw": FLOW}) + "\nnot json\n", encoding="utf-8")
    (tmp_path / "flows.csv").write_text("ts,src_ip,dst_ip,dst_port,proto,bytes,packets\n" + FLOW + "\n", encoding="utf-8")
    sink = Sink()
    follower = Follower(tmp_path, sink, from_start=True)
    assert follower.poll() == 2
    assert sorted(item["source"] for batch in sink.batches for item in batch) == ["flow", "flow"]
    assert len(follower.skipped) == 1


def test_a_file_that_is_only_recognized_when_forced(tmp_path):
    log = tmp_path / "odd.log"
    log.write_text("this is not a known format\n", encoding="utf-8")
    sink = Sink()
    assert Follower(log, sink, from_start=True).poll() == 0
    forced = Follower(log, sink, from_start=True, forced="flow")
    assert forced.poll() == 1 and sink.batches[0] == [{"source": "flow", "raw": "this is not a known format"}]