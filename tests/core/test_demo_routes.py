import time

import pytest

from deconflicted.core.pipeline import Pipeline
from deconflicted.core.service import set_pipeline
from deconflicted.ledger import service as ledger_service
from deconflicted.ledger.transport import in_process_client


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DECONFLICTED_LEDGER_NODES", raising=False)
    monkeypatch.delenv("DECONFLICTED_DEMO", raising=False)
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


def wait_until_finished(client):
    status = client.get("/demo/status").json()
    for _ in range(100):
        status = client.get("/demo/status").json()
        if not status["running"]:
            break
        time.sleep(0.1)
    return status


def test_the_controls_are_off_unless_switched_on(client):
    assert client.get("/demo/status").json()["enabled"] is False
    assert client.post("/demo/attack", json={"speed": 0}).status_code == 403
    assert client.post("/demo/reset").status_code == 403


def test_the_recorded_attack_replays_and_reset_clears_it(client, monkeypatch):
    monkeypatch.setenv("DECONFLICTED_DEMO", "1")
    assert client.get("/demo/status").json()["enabled"] is True
    assert client.post("/demo/attack", json={"speed": 1000}).status_code == 422
    assert client.post("/demo/attack", json={"speed": 0}).status_code == 200
    status = wait_until_finished(client)
    assert status["running"] is False and status["error"] is None
    assert status["total"] > 0 and status["sent"] == status["total"]
    assert len(client.get("/incidents").json()) >= 1
    after = client.post("/demo/reset").json()
    assert after["sent"] == 0 and after["total"] == 0
    assert client.get("/incidents").json() == []
    assert client.get("/budget").json()["used"] == 0