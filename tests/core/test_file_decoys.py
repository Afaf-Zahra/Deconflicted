import pytest

from deconflicted import adapters
from deconflicted.adapters.hosts import config_dir
from deconflicted.core.baseline import Baseline
from deconflicted.core.config import CoreConfigError, load_config
from deconflicted.core.filedecoys import FileDecoys
from deconflicted.core.pipeline import Pipeline
from deconflicted.deception import DecoyRegistry, DecoyTrigger
from deconflicted.ingest.live import parse_item
from deconflicted.ingest.mapper import load_mappings
from deconflicted.ml.tokens import event_token

CONFIG = load_config()
PATH = "/srv/finance/passwords_2026.xlsx"
CLOUD = {"eventTime": "2026-03-04T05:10:00Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
         "userIdentity": {"userName": "mallory"}, "sourceIPAddress": "203.0.113.9",
         "requestParameters": {"bucketName": "acme-prod", "key": "backups/admin-keys.csv"}}
ALLOW = """
files:
  - id: finance-passwords
    path: /srv/finance/passwords_2026.xlsx
allowlist:
  - user: backup-svc
    process: rsync
    hours: ["01:00", "03:00"]
    until: 2026-12-31
    reason: the nightly backup walks the finance share
"""


def touch(path=PATH, user="alice", process="vim", op="open", host="file-01", ts="2026-03-04T05:00:00Z"):
    record = {"ts": ts, "host": host, "user": user, "process": process, "op": op, "path": path}
    return parse_item(record, mappings=load_mappings(config_dir() / "mappings"))


def make():
    return Pipeline(config=CONFIG, baseline=Baseline(CONFIG), decoy_trigger=DecoyTrigger(DecoyRegistry()))


def decoys_with(tmp_path, text):
    (tmp_path / "decoy_files.yaml").write_text(text, encoding="utf-8")
    return FileDecoys(CONFIG, tmp_path)


def test_a_file_record_becomes_a_read_or_a_write_with_its_own_token():
    event = touch()
    assert (event.source, event.action, event.obj, event.user, event.process, event.host) == \
        ("linux", "read", PATH, "alice", "vim", "file-01")
    assert event_token(event) == "file:read"
    changed = touch(op="modify", ts="2026-03-04T05:01:00Z")
    assert (changed.action, event_token(changed)) == ("write", "file:write")
    with pytest.raises(ValueError, match="no action is mapped"):
        touch(op="chmod")


@pytest.mark.parametrize("tool", ["vim", "nano", "cat", "less", "cp"])
def test_any_tool_on_a_decoy_file_is_one_certain_signal(tool):
    (incident,) = make().ingest([touch(process=tool)])
    (signal,) = incident.signals
    assert signal.kind == "decoy_hit" and signal.id.startswith("fdecoy-") and signal.detail["how"] == tool
    assert signal.detail["decoy"] == "finance-passwords" and "decoy:finance-passwords" in signal.entity_ids
    assert incident.title == "alice on file-01 touches the decoy finance-passwords" and incident.severity == "warning"
    assert (incident.chain[0].tactic, incident.chain[0].technique) == ("Collection", "T1005")
    assert incident.chain[0].description == f"alice opened the decoy file {PATH} on file-01 with {tool}"


def test_an_ordinary_file_is_never_judged():
    pipeline = make()
    events = [touch(path="/home/alice/notes.txt"), touch(path="/srv/finance/other.xlsx", op="write", ts="2026-03-04T05:01:00Z"),
              touch(path=PATH, host="bak-01", ts="2026-03-04T05:02:00Z")]  # the decoy path on another host: the entry names file-01
    assert pipeline.ingest(events) == [] and pipeline.status()["held_signals"] == 0


def test_a_cloud_object_is_caught_by_its_key_pattern():
    event = parse_item(CLOUD, mappings=load_mappings(config_dir() / "mappings"))
    assert (event.action, event.obj, event.user) == ("read", "backups/admin-keys.csv", "mallory")
    (incident,) = make().ingest([event])
    assert incident.signals[0].detail["decoy"] == "cloud-admin-keys"
    assert "host:203.0.113.9" in incident.entities and "user:mallory" in incident.entities


def test_only_a_listed_user_job_hour_and_day_may_touch_a_decoy(tmp_path):
    files = decoys_with(tmp_path, ALLOW)
    assert files.signal(touch(user="backup-svc", process="rsync", ts="2026-03-04T02:00:00Z")) is None
    assert files.allowlisted == 1
    for other in (touch(user="backup-svc", process="rsync", ts="2026-03-04T05:00:00Z"),   # the wrong hour
                  touch(user="alice", process="rsync", ts="2026-03-04T02:00:00Z"),        # the wrong user
                  touch(user="backup-svc", process="vim", ts="2026-03-04T02:00:00Z"),     # the wrong program
                  touch(user="backup-svc", process="rsync", ts="2027-01-01T02:00:00Z")):  # after the last day
        assert files.signal(other) is not None
    assert files.allowlisted == 1


def test_a_wrong_decoy_file_is_refused_with_its_name(tmp_path):
    with pytest.raises(CoreConfigError, match="exactly one of path or match"):
        decoys_with(tmp_path, "files:\n  - id: x\n")
    with pytest.raises(CoreConfigError, match="a user and a reason"):
        decoys_with(tmp_path, "files:\n  - {id: x, path: /a}\nallowlist:\n  - {user: bob}\n")
    with pytest.raises(CoreConfigError, match="two quoted UTC times"):
        decoys_with(tmp_path, "files:\n  - {id: x, path: /a}\nallowlist:\n  - {user: bob, reason: r, hours: [10:00, 12:00]}\n")
    assert FileDecoys(CONFIG, tmp_path / "nowhere").decoys == ()  # no file means no file decoys


def test_an_allowlisted_contact_with_a_network_decoy_is_not_judged_by_the_baseline():
    pipeline = make()
    allowed = adapters.get("flow").parse_line("2026-03-04T03:48:20Z,10.0.1.10,10.0.2.99,445,tcp,812,9")  # ws-admin-01
    assert pipeline.ingest([allowed]) == [] and pipeline.decoy_trigger.allowlisted == 1
    assert pipeline.status()["held_signals"] == 0 and not pipeline.decoy_trigger.hits
    stranger = adapters.get("flow").parse_line("2026-03-04T03:49:20Z,10.0.1.21,10.0.2.99,445,tcp,812,9")  # ws-help-01
    assert len(pipeline.ingest([stranger])) == 1


def test_a_file_decoy_hit_shows_on_the_decoys_page_and_in_the_graph():
    pipeline = make()
    (incident,) = pipeline.ingest([touch()])
    (hit,) = list(pipeline.decoy_trigger.hits)
    assert (hit.decoy, hit.source) == ("finance-passwords", "file-01")
    graph = pipeline.graph(incident.id)
    assert {node.id: node for node in graph.nodes}["decoy:finance-passwords"].decoy_hit is True
    edges = {(edge.source, edge.target, edge.token) for edge in graph.edges}
    assert {("host:file-01", "decoy:finance-passwords", "file:read"), ("user:alice", "host:file-01", "file:read")} <= edges


def test_several_touches_by_one_person_stay_one_incident():
    pipeline = make()
    changes = pipeline.ingest([touch(), touch(op="modify", ts="2026-03-04T05:05:00Z")])
    assert [incident.id for incident in changes] == ["INC-0001"]
    assert [signal.kind for signal in pipeline.incident("INC-0001").signals] == ["decoy_hit", "decoy_hit"]