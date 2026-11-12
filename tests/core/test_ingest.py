import contextlib
import io
import json

import pytest
import yaml

from deconflicted import adapters
from deconflicted.adapters.common import make_id
from deconflicted.ingest.__main__ import main
from deconflicted.ingest.load import read_file, read_path, to_replay_lines
from deconflicted.ingest.mapper import Mapper, MappingError, load_mappings
from deconflicted.ingest.sniff import REPLAY, sniff_file, sniff_line
from deconflicted.sim import replay

WINDOWS = '{"EventID":4624,"UtcTime":"2026-03-04T03:40:00.000Z","Computer":"dc-01","TargetUserName":"alice","IpAddress":"10.0.1.21","LogonType":3}'
FLOW = "2026-03-04T03:48:20Z,10.0.1.21,10.0.2.99,445,tcp,812,9"
MODBUS = '{"ts":"2026-03-04T04:50:00.000Z","server":"plc-1","client_ip":"10.0.3.5","func":6,"address":40001,"value":95}'
OPCUA = '{"ts":"2026-03-04T09:00:05.000Z","server":"opc-1","client_ip":"10.0.3.20","service":"Write","node":"ns=2;s=Tank1.Setpoint","value":55}'
PROXY = "1772595600.123    142 10.0.1.21 TCP_MISS/200 5120 GET http://10.0.9.5/pkg/update.tar - HIER_DIRECT/10.0.9.5 text/html"
LINUX = "Mar  4 01:00:03 bak-01 sshd[2211]: Accepted publickey for svc-backup from 10.0.2.10 port 40122 ssh2"
SAMPLES = {"windows": WINDOWS, "flow": FLOW, "modbus": MODBUS, "opcua": OPCUA, "proxy": PROXY, "linux": LINUX}

EDR_MAP = """
name: edr
source: windows
format: json
detect: {has: [event.kind, host.name]}
timestamp: {field: "@timestamp", format: iso}
action:
  field: event.kind
  map: {process_start: proc_create, login: logon}
fields:
  host: host.name
  user: user.name
  process: process.executable
  cmdline: process.command_line
  src_ip: source.ip
"""
EDR_LINE = json.dumps({"@timestamp": "2026-03-04T05:00:00Z", "event": {"kind": "process_start"},
                       "host": {"name": "WS-HELP-01.corp.local"}, "user": {"name": "CORP\\alice"},
                       "process": {"executable": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd /c whoami"},
                       "source": {"ip": "-"}})
CSV_MAP = """
name: flowcsv
source: flow
format: csv
detect: {has: [start, src, dst, dport]}
timestamp: {field: start, format: epoch}
action: {constant: flow}
fields: {src_ip: src, dst_ip: dst, dst_port: dport, value: bytes}
"""
CSV_LINES = ["start,src,dst,dport,bytes", "1772595600,10.0.1.21,10.0.2.99,445,812"]
REGEX_MAP = r"""
name: fw
source: linux
format: regex
pattern: '^(?P<when>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) (?P<box>\S+) user=(?P<who>\S+) ran (?P<cmd>.+)$'
timestamp: {field: when, format: "%d/%m/%Y %H:%M:%S", assume_utc: true}
action: {constant: proc_create}
fields: {host: box, user: who, cmdline: cmd}
"""


def write(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run(argv):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


def test_every_built_in_format_and_the_replay_format_is_told_apart():
    for source, line in SAMPLES.items():
        assert sniff_line(line) == source, source
    assert sniff_line(json.dumps({"source": "flow", "raw": FLOW})) == REPLAY
    for junk in ("", "   ", "hello world", "{}", "[1,2]", '{"EventID":', "a,b,c", "Mar 4 not syslog"):
        assert sniff_line(junk) is None, junk


def test_sniffing_a_file_survives_a_header_a_bom_and_blank_lines(tmp_path):
    path = tmp_path / "flows.csv"
    path.write_bytes(b"\xef\xbb\xbfts,src_ip,dst_ip,dst_port,proto,bytes,packets\r\n\r\n" + (FLOW + "\r\n").encode() * 3)
    assert sniff_file(path) == "flow"
    other = write(tmp_path / "notes.txt", ["nothing", "to see"])
    assert sniff_file(other) is None


def test_each_format_is_read_with_its_adapter(tmp_path):
    for source, line in SAMPLES.items():
        path = write(tmp_path / f"{source}.log", [line, "", line])
        events, report = read_file(path)
        assert report.format == source and (report.lines, report.accepted, report.errors) == (2, 2, 0), source
        assert events[0] == adapters.get(source).parse_line(line) and events[0].id == make_id(source, line)


def test_bad_lines_are_counted_and_skipped_with_their_position(tmp_path):
    unsupported = '{"EventID":9999,"UtcTime":"2026-03-04T03:40:00Z","Computer":"dc-01"}'
    path = write(tmp_path / "windows.log", [WINDOWS, unsupported, WINDOWS, "{broken"])
    events, report = read_file(path)
    assert (report.lines, report.accepted, report.errors) == (4, 2, 2)
    assert [e.id for e in events] == [make_id("windows", WINDOWS)] * 2
    assert "windows.log:2" in report.examples[0] and "windows.log:4" in report.examples[1]


def test_values_an_adapter_cannot_convert_are_counted_not_fatal(tmp_path):
    dirty = '{"EventID":3,"UtcTime":"2026-03-04T03:40:00Z","Computer":"dc-01","Image":"C:/x.exe","DestinationPort":"abc"}'
    events, report = read_file(write(tmp_path / "w.log", [WINDOWS, dirty]))
    assert len(events) == 1 and report.errors == 1 and "w.log:2" in report.examples[0]


def test_a_time_without_a_zone_is_read_as_utc_unless_strict(tmp_path):
    path = write(tmp_path / "w.log", ['{"EventID":1102,"UtcTime":"2026-03-04 04:20:00","Computer":"file-01"}'])
    events, _ = read_file(path)
    assert events[0].ts.isoformat() == "2026-03-04T04:20:00+00:00"
    events, report = read_file(path, assume_utc=False)
    assert events == [] and report.errors == 1


def test_the_syslog_year_is_a_parameter(tmp_path):
    path = write(tmp_path / "auth.log", [LINUX])
    assert read_file(path, year=2025)[0][0].ts.year == 2025
    assert read_file(path)[0][0].ts.year == 2026


def test_replay_files_give_the_same_ids_as_the_raw_logs(tmp_path):
    path = write(tmp_path / "scenario.jsonl", [json.dumps({"source": s, "raw": r}) for s, r in SAMPLES.items()])
    events, report = read_file(path)
    assert report.format == REPLAY and report.accepted == 6
    assert sorted(e.id for e in events) == sorted(make_id(s, r) for s, r in SAMPLES.items())
    bad = write(tmp_path / "bad.jsonl", [json.dumps({"source": "flow", "raw": FLOW}),
                                         json.dumps({"source": "nope", "raw": "x"}), json.dumps({"source": "flow"})])
    events, report = read_file(bad)
    assert (len(events), report.errors) == (1, 2)


def test_a_folder_is_read_into_one_time_ordered_list(tmp_path):
    for source, line in SAMPLES.items():
        write(tmp_path / f"{source}.log", [line])
    write(tmp_path / ".hidden.log", [WINDOWS])
    write(tmp_path / "labels.jsonl", [json.dumps({"id": "windows-aa7aa68146c4", "attack": True, "step": 1})])
    (tmp_path / "sub").mkdir()
    write(tmp_path / "sub" / "more.log", [FLOW])
    events, report = read_path(tmp_path)
    assert [e.source for e in events] == ["linux", "windows", "proxy", "flow", "flow", "modbus", "opcua"]
    assert len(report.files) == 8 and report.accepted == 7 and report.errors == 0
    assert report.unrecognized == [str(tmp_path / "labels.jsonl")]


def test_a_missing_path_and_an_unknown_forced_format_are_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_path(tmp_path / "nothing")
    with pytest.raises(LookupError):
        read_file(write(tmp_path / "w.log", [WINDOWS]), wanted="nope")


def test_the_command_line_reports_and_writes_replay_lines(tmp_path):
    folder = tmp_path / "in"
    folder.mkdir()
    write(folder / "flow.csv", [FLOW])
    write(folder / "w.log", [WINDOWS, "{broken"])
    out = tmp_path / "out" / "events.jsonl"
    code, text = run([str(folder), "--out", str(out), "--mappings", str(tmp_path / "none")])
    assert code == 0 and "read 2 events from 2 files" in text and "1 skipped" in text and "wrote 2 lines" in text
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert [r["source"] for r in rows] == ["windows", "flow"]
    assert len(replay.load(str(out))) == 2
    assert run([str(tmp_path / "missing")])[0] == 1
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run([str(empty)])[0] == 1


def test_a_json_mapping_builds_events_like_an_adapter():
    mapper = Mapper(yaml.safe_load(EDR_MAP), "edr.yaml")
    event = mapper.parse_line(EDR_LINE, file="edr.log", lineno=3)
    assert (event.source, event.host, event.user, event.process, event.cmdline) == (
        "windows", "ws-help-01", "alice", "cmd.exe", "cmd /c whoami")
    assert (event.action, event.src_ip, event.raw, event.id) == ("proc_create", None, EDR_LINE, make_id("windows", EDR_LINE))
    assert event.ts.isoformat() == "2026-03-04T05:00:00+00:00"
    spec = yaml.safe_load(EDR_MAP)
    other = EDR_LINE.replace("process_start", "something_else")
    with pytest.raises(adapters.AdapterError, match="edr.log:4"):
        mapper.parse_line(other, file="edr.log", lineno=4)
    spec["action"]["default"] = "net_conn"
    assert Mapper(spec, "edr.yaml").parse_line(other).action == "net_conn"


def test_csv_and_regex_mappings_and_the_time_formats():
    flow = Mapper(yaml.safe_load(CSV_MAP), "flowcsv.yaml")
    assert flow.needs_header
    flow.set_header(CSV_LINES[0])
    event = flow.parse_line(CSV_LINES[1])
    assert (event.host, event.dst_port, event.value, event.action) == ("ws-help-01", 445, 812.0, "flow")
    assert event.ts.isoformat() == "2026-03-04T03:40:00+00:00"
    fw = Mapper(yaml.safe_load(REGEX_MAP), "fw.yaml")
    event = fw.parse_line("04/03/2026 06:30:00 bak-01 user=svc-backup ran rsync -a /srv /backup")
    assert (event.host, event.user, event.cmdline, event.ts.isoformat()) == (
        "bak-01", "svc-backup", "rsync -a /srv /backup", "2026-03-04T06:30:00+00:00")
    with pytest.raises(adapters.AdapterError, match="does not match"):
        fw.parse_line("garbage")
    spec = yaml.safe_load(CSV_MAP)
    spec["timestamp"]["format"] = "epoch_ms"
    in_ms = Mapper(spec, "ms.yaml")
    in_ms.set_header(CSV_LINES[0])
    assert in_ms.parse_line("1772595600000,10.0.1.21,10.0.2.99,445,812").ts.isoformat() == "2026-03-04T03:40:00+00:00"
    spec["timestamp"] = {"field": "start", "format": "%d/%m/%Y %H:%M"}
    local = Mapper(spec, "local.yaml")
    local.set_header(CSV_LINES[0])
    with pytest.raises(adapters.AdapterError, match="no time zone"):
        local.parse_line("04/03/2026 03:40,10.0.1.21,10.0.2.99,445,812")
    assert local.parse_line("04/03/2026 03:40,10.0.1.21,10.0.2.99,445,812", assume_utc=True).ts.hour == 3
    spec["fields"] = {"dst_ip": "dst"}
    spec["detect"] = {"has": ["dst"]}
    nohost = Mapper(spec, "nohost.yaml")
    nohost.set_header(CSV_LINES[0])
    with pytest.raises(adapters.AdapterError, match="no host"):
        nohost.parse_line("04/03/2026 03:40,10.0.1.21,10.0.2.99,445,812", assume_utc=True)


def test_a_wrong_mapping_is_refused_with_the_file_name():
    good = yaml.safe_load(EDR_MAP)
    broken = [
        {**good, "source": "email"},
        {**good, "format": "xml"},
        {**good, "colour": "red"},
        {**good, "timestamp": {}},
        {**good, "timestamp": {"field": "t", "format": "garbage"}},
        {**good, "action": {"constant": "explode"}},
        {**good, "action": {"field": "k", "map": {"a": "explode"}}},
        {**good, "action": {"constant": "flow", "field": "k"}},
        {**good, "action": {}},
        {**good, "fields": {"colour": "x"}},
        {**good, "format": "regex", "pattern": "(unclosed"},
        {**good, "format": "regex", "pattern": "no groups"},
        {**good, "format": "regex", "pattern": "(?P<only>x)"},
        "not a mapping",
    ]
    for spec in broken:
        with pytest.raises(MappingError, match="edr.yaml"):
            Mapper(spec, "edr.yaml")


def test_mappings_load_from_a_folder_and_claim_files_by_their_shape(tmp_path):
    folder = tmp_path / "mappings"
    folder.mkdir()
    (folder / "edr.yaml").write_text(EDR_MAP, encoding="utf-8")
    (folder / "flowcsv.yml").write_text(CSV_MAP, encoding="utf-8")
    mappings = load_mappings(folder)
    assert [m.name for m in mappings] == ["edr", "flowcsv"] and load_mappings(tmp_path / "nothing") == []
    logs = tmp_path / "logs"
    logs.mkdir()
    write(logs / "edr.log", [EDR_LINE, EDR_LINE])
    write(logs / "flows.csv", CSV_LINES)
    write(logs / "windows.log", [WINDOWS])
    events, report = read_path(logs, mappings=mappings)
    formats = {item.path.replace("\\", "/").rsplit("/", 1)[-1]: item.format for item in report.files}
    assert formats == {"edr.log": "edr", "flows.csv": "flowcsv", "windows.log": "windows"}
    assert len(events) == 4 and report.errors == 0
    forced, _ = read_file(logs / "edr.log", mappings=mappings, wanted="edr")
    assert len(forced) == 2
    code, text = run([str(logs), "--mappings", str(folder)])
    assert code == 0 and "edr, 2 lines" in text and "flowcsv, 1 lines" in text


def test_a_bad_mapping_file_stops_the_load_and_names_the_file(tmp_path):
    (tmp_path / "bad.yaml").write_text("source: [", encoding="utf-8")
    with pytest.raises(MappingError, match="bad.yaml"):
        load_mappings(tmp_path)
    (tmp_path / "bad.yaml").write_text(EDR_MAP.replace("name: edr", "name: windows"), encoding="utf-8")
    with pytest.raises(MappingError, match="built-in"):
        load_mappings(tmp_path)
    code, text = run([str(tmp_path), "--mappings", str(tmp_path)])
    assert code == 1 and "FAILED" in text