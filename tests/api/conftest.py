import importlib
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from deconflicted.deception import DecoyService
from deconflicted.deception import service as decoy_service
from deconflicted.ledger import ConfigIntegrity, load_policy
from deconflicted.ledger import service as ledger_service
from deconflicted.ledger.transport import in_process_client
from deconflicted.response import ResponseGuard
from deconflicted.response import service as response_service
from tests.ledger.conftest import make_ledger

CONFIG = Path(__file__).parents[2] / "config"
ROUTES = ("routes_response", "routes_ledger", "routes_audit", "routes_decoys")


def build_app() -> FastAPI:
    app = FastAPI()
    for name in ROUTES:
        app.include_router(importlib.reload(importlib.import_module(f"deconflicted.api.{name}")).router)
    return app


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.delenv("DECONFLICTED_DEBUG", raising=False)
    root = tmp_path / "repo"
    shutil.copytree(CONFIG, root / "config")
    ledger = make_ledger(tmp_path / "nodes", load_policy(root / "config" / "policy.yaml"))
    integrity = ConfigIntegrity(ledger.client, ledger.policy, root=root)
    integrity.ensure_anchor()
    ledger_service.set_client(ledger.client, integrity)
    response_service.set_guard(ResponseGuard(str(root / "config"), integrity_check=integrity.guard_check()))
    decoy_service.reset_service(DecoyService(str(root / "config")))
    yield SimpleNamespace(http=in_process_client(build_app()), ledger=ledger, integrity=integrity, root=root)
    ledger_service.set_client(None)
    response_service.set_guard(None)
    decoy_service.reset_service(None)
