import json
from pathlib import Path

import pytest

from deconflicted.deception import get_service
from deconflicted.ledger import verify_export
from deconflicted.schema import DecoysView, Event, LedgerEntry, NodeStatus, Preview, VerifyReport

from .conftest import build_app

FIXTURES = {e["id"]: e for e in json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())}


def action(kind, target, id="act-001", **params):
    return {"id": id, "kind": kind, "target": target, "params": params}


def preview(api, act, incident="INC-0042", **extra):
    return api.http.post("/response/preview", json={"incident_id": incident, "action": act, **extra})


def kinds(api):
    return [p for p in api.ledger.client.payloads("response_decision", "approval")]


# ---------------------------------------------------------------- response
def test_preview_scenario_results_and_ledger_record(api):
    allowed = preview(api, action("block_write", "eng-ws-01", "act-002", to="plc-1"))
    assert allowed.status_code == 200 and Preview(**allowed.json()).decision == "allow"
    downgraded = preview(api, action("isolate_host", "plc-1", "act-001"))
    body = Preview(**downgraded.json())
    assert body.decision == "downgrade" and body.safer_options[0].kind == "block_write"
    assert len(body.before_trace) == len(body.after_trace) == 31
    records = api.ledger.client.payloads("response_decision")
    assert [r[1]["decision"] for r in records] == ["allow", "downgrade"]
    assert records[1][1]["action_id"] == "act-001" and records[1][1]["incident_id"] == "INC-0042"
    assert len(records[1][1]["preview_hash"]) == 64


def test_preview_accepts_an_explicit_process_state(api):
    state = {"level": 50.0, "setpoint": 50.0, "pump": True, "valve": 50.0, "writers": {"plc-1": []}}
    result = preview(api, action("isolate_host", "plc-1"), process_state=state)
    assert result.status_code == 200 and result.json()["decision"] == "downgrade"
    assert [o["kind"] for o in result.json()["safer_options"]] == ["rate_limit_writes", "reset_setpoint"]
    bad = preview(api, action("disable_account", "alice"), process_state={"level": "high"})
    assert bad.json()["decision"] == "block", "a state the model cannot read blocks"


@pytest.mark.parametrize("body", [
    {"incident_id": "I", "action": {"id": "a", "kind": "launch_missiles", "target": "plc-1"}},
    {"incident_id": "I", "action": {"id": "a", "kind": "isolate_host", "target": "plc-1"}, "extra": 1},
    {"action": {"id": "a", "kind": "isolate_host", "target": "plc-1"}},
])
def test_invalid_requests_are_refused(api, body):
    assert api.http.post("/response/preview", json=body).status_code == 422
    assert api.ledger.client.payloads("response_decision") == []


def test_approving_an_allowed_action_is_signed_into_the_ledger(api):
    preview(api, action("disable_account", "alice", "act-003"))
    response = api.http.post("/response/act-003/approve", json={"analyst": "analyst-1"})
    assert response.status_code == 200
    entry = LedgerEntry(**response.json())
    assert entry.kind == "approval" and len({s.node for s in entry.signatures}) >= 2
    payload = api.ledger.client.payloads("approval")[0][1]
    assert payload["decision"] == "approved" and payload["analyst"] == "analyst-1"
    assert payload["applied_action"]["kind"] == "disable_account"
    assert api.ledger.client.verify().ok


def test_approving_a_downgrade_records_the_safer_action(api):
    preview(api, action("isolate_host", "plc-1", "act-001"))
    assert api.http.post("/response/act-001/approve", json={"analyst": "analyst-2"}).status_code == 200
    applied = api.ledger.client.payloads("approval")[0][1]["applied_action"]
    assert (applied["kind"], applied["target"]) == ("block_write", "eng-ws-01")


def test_a_blocked_action_cannot_be_approved(api):
    blocked = preview(api, action("isolate_host", "plc-2", "act-009"))
    assert blocked.json()["decision"] == "block"
    response = api.http.post("/response/act-009/approve", json={"analyst": "analyst-1"})
    assert response.status_code == 409 and "blocked" in response.json()["detail"]
    assert api.ledger.client.payloads("approval") == []


def test_approval_needs_a_preview_and_a_listed_analyst(api):
    assert api.http.post("/response/act-404/approve", json={"analyst": "analyst-1"}).status_code == 409
    preview(api, action("disable_account", "alice", "act-003"))
    assert api.http.post("/response/act-003/approve", json={"analyst": "mallory"}).status_code == 403
    assert api.http.post("/response/act-003/approve", json={}).status_code == 422
    assert api.ledger.client.payloads("approval") == []


def test_the_latest_decision_decides(api):
    preview(api, action("reset_setpoint", "plc-1", "act-005", value=50))
    assert preview(api, action("reset_setpoint", "plc-1", "act-005", value=70)).json()["decision"] != "allow"
    state = {"level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0}
    preview(api, action("isolate_host", "plc-2", "act-005"), process_state=state)
    assert api.http.post("/response/act-005/approve", json={"analyst": "analyst-1"}).status_code == 409


def test_reject_is_recorded(api):
    preview(api, action("disable_account", "alice", "act-003"))
    assert api.http.post("/response/act-003/reject", json={"analyst": "analyst-1"}).status_code == 200
    assert api.http.post("/response/act-777/reject", json={"analyst": "analyst-2"}).status_code == 200
    payloads = [p for _, p in api.ledger.client.payloads("approval")]
    assert [p["decision"] for p in payloads] == ["rejected", "rejected"] and payloads[1]["preview_hash"] is None
    assert api.http.post("/response/act-003/reject", json={"analyst": "nobody"}).status_code == 403


def test_nothing_goes_ahead_without_a_ledger_quorum(api):
    api.ledger.switches["node-b"].down = api.ledger.switches["node-c"].down = True
    before = api.ledger.client.count()
    assert preview(api, action("disable_account", "alice")).status_code == 503
    assert api.http.post("/response/act-003/reject", json={"analyst": "analyst-1"}).status_code == 503
    assert api.ledger.client.count() == before, "a failed record writes nothing"
    api.ledger.switches["node-b"].down = False
    preview(api, action("disable_account", "alice", "act-003"))
    api.ledger.switches["node-b"].down = True
    assert api.http.post("/response/act-003/approve", json={"analyst": "analyst-1"}).status_code == 503


def test_the_guard_blocks_after_an_unsigned_config_change(api):
    path = api.root / "config" / "safety_rules.yaml"
    path.write_text(path.read_text().replace("max: 80", "max: 100"))
    result = preview(api, action("disable_account", "alice"))
    assert result.status_code == 200 and result.json()["decision"] == "block"
    assert "integrity" in result.json()["reason"]


def test_without_a_ledger_every_route_fails_closed(api, monkeypatch):
    from deconflicted.ledger import service
    for name in ("DECONFLICTED_LEDGER_NODES", "DECONFLICTED_LEDGER_EMBEDDED"):
        monkeypatch.delenv(name, raising=False)
    service.set_client(None)
    http = api.http
    assert http.get("/ledger").status_code == 503
    assert http.get("/ledger/verify").status_code == 503
    assert http.get("/ledger/nodes").status_code == 503
    assert http.get("/audit/export").status_code == 503
    assert http.post("/response/x/approve", json={"analyst": "analyst-1"}).status_code == 503
    assert preview(api, action("disable_account", "alice")).status_code == 503


# ---------------------------------------------------------------- ledger and audit
def test_ledger_listing_and_paging(api):
    for n in range(5):
        api.ledger.client.append("detection", {"n": n})
    everything = api.http.get("/ledger").json()
    assert [e["seq"] for e in everything] == list(range(6)), "the config anchor is entry 0"
    page = api.http.get("/ledger", params={"limit": 2, "offset": 3}).json()
    assert [e["seq"] for e in page] == [3, 4]
    assert [LedgerEntry(**e).kind for e in page] == ["detection", "detection"]
    assert api.http.get("/ledger", params={"limit": 0}).status_code == 422
    assert api.http.get("/ledger", params={"limit": 5000}).status_code == 422
    assert api.http.get("/ledger", params={"offset": -1}).status_code == 422


def test_verify_and_nodes(api):
    report = VerifyReport(**api.http.get("/ledger/verify").json())
    assert report.ok and report.checked == 1 and len(report.heads) == 3
    nodes = [NodeStatus(**n) for n in api.http.get("/ledger/nodes").json()]
    assert [(n.node, n.up) for n in nodes] == [("node-a", True), ("node-b", True), ("node-c", True)]
    api.ledger.switches["node-c"].down = True
    assert [n["up"] for n in api.http.get("/ledger/nodes").json()] == [True, True, False]


def test_verify_records_an_unsigned_config_change_once(api):
    path = api.root / "config" / "decoys.yaml"
    path.write_text(path.read_text() + "\n# edited\n")
    first = api.http.get("/ledger/verify").json()
    assert first["ok"] and api.ledger.client.count() == 2, "a detection entry was added for the violation"
    detection = api.ledger.client.payloads("detection")[0][1]["signal"]
    assert detection["kind"] == "integrity_violation"
    api.http.get("/ledger/verify")
    assert api.ledger.client.count() == 2, "the same violation is not recorded twice"


def test_audit_export_verifies_offline(api):
    api.ledger.client.append("detection", {"n": 1})
    export = api.http.get("/audit/export").json()
    assert verify_export(export).ok and len(export["entries"]) == 2


def test_the_tamper_route_exists_only_in_debug_mode(api, monkeypatch):
    assert api.http.post("/debug/tamper").status_code == 404
    monkeypatch.setenv("DECONFLICTED_DEBUG", "1")
    http = __import__("deconflicted.ledger.transport", fromlist=["x"]).in_process_client(build_app())
    api.ledger.client.append("detection", {"n": 1})
    assert http.post("/debug/tamper").json() == {"tampered_seq": 1}
    report = http.get("/ledger/verify").json()
    assert not report["ok"] and report["errors"] == [{"seq": 1, "reason": "payload_hash_mismatch"}]
    assert http.post("/debug/tamper", json={"seq": 99}).status_code == 404
    assert http.post("/debug/tamper", json={"seq": 0}).json() == {"tampered_seq": 0}
    monkeypatch.delenv("DECONFLICTED_DEBUG")
    build_app()  # reload the routes without the debug route


# ---------------------------------------------------------------- decoys
def test_decoys_route(api):
    empty = DecoysView(**api.http.get("/decoys").json())
    assert [d.id for d in empty.decoys] == ["dc-decoy-01", "plc-decoy-1"] and empty.hits == [] and empty.placements == []
    get_service().trigger(Event(**{k: v for k, v in FIXTURES["flow-c7621933881f"].items() if k != "label"}))
    view = DecoysView(**api.http.get("/decoys", params={"incident_id": "INC-0042"}).json())
    assert [h.decoy for h in view.hits] == ["dc-decoy-01"]
    assert [(p.host, p.address, p.safety_ok) for p in view.placements] == [("dc-01", "10.0.2.90", True), ("file-01", "10.0.2.91", True)]
