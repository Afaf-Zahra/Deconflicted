import json
from pathlib import Path

import pytest

from deconflicted.core.pipeline import Pipeline
from deconflicted.core.service import set_pipeline
from deconflicted.ledger import service as ledger_service
from deconflicted.ledger.transport import in_process_client

EVENTS = json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())
LINES = [{"source": e["source"], "raw": e["raw"]} for e in EVENTS[:6]]


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


def test_health_and_empty_state(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/incidents").json() == []
    assert client.get("/budget").json() == {"budget": 5, "used": 0, "window_hours": 24}


def test_unknown_incident_is_404(client):
    assert client.get("/incidents/INC-1").status_code == 404
    assert client.get("/incidents/INC-1/graph").status_code == 404


def test_ingest_accepts_good_lines_and_reports_bad_ones(client):
    result = client.post("/ingest", json={"events": LINES}).json()
    assert result["accepted"] == 6 and result["errors"] == [] and isinstance(result["incidents"], int)
    mixed = client.post("/ingest", json={"events": [{"source": "nope", "raw": "x"}, {"source": "windows", "raw": "not json"}, LINES[0]]}).json()
    assert mixed["accepted"] == 1 and [e["index"] for e in mixed["errors"]] == [0, 1]


def test_events_by_id_skips_unknown_ids(client):
    client.post("/ingest", json={"events": LINES})
    ids = ",".join(e["id"] for e in EVENTS[:3])
    found = client.get("/events", params={"ids": ids + ",does-not-exist"}).json()
    assert [e["id"] for e in found] == [e["id"] for e in EVENTS[:3]]
    assert client.get("/events").json() == []


def test_a_malformed_ingest_body_is_refused(client):
    assert client.post("/ingest", json={"events": [{"source": "windows"}]}).status_code == 422