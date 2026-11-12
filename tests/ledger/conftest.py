import itertools
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from deconflicted.ledger import LedgerClient, NodeHandle, load_policy
from deconflicted.ledger.node import create_app
from deconflicted.ledger.transport import in_process_client

CONFIG = Path(__file__).parents[2] / "config"


class Switch:
    """Wraps a node's client so a test can take the node down and record what is sent to it."""

    def __init__(self, client):
        self.client, self.down, self.sent = client, False, []

    def request(self, method, path, **kwargs):
        if self.down:
            raise httpx.ConnectError("node is down")
        if method == "POST":
            self.sent.append((path, kwargs.get("json")))
        return self.client.request(method, path, **kwargs)


def make_ledger(tmp_path, policy=None):
    policy = policy or load_policy(CONFIG / "policy.yaml")
    apps = {n: create_app(n, tmp_path / n) for n in policy.nodes}
    switches = {n: Switch(in_process_client(a)) for n, a in apps.items()}
    nodes = {n: NodeHandle(n, s) for n, s in switches.items()}
    tick = itertools.count()
    start = datetime(2026, 3, 4, tzinfo=timezone.utc)
    client = LedgerClient(tmp_path / "client.db", nodes, policy, clock=lambda: start + timedelta(seconds=next(tick)))
    return SimpleNamespace(client=client, apps=apps, switches=switches, nodes=nodes, policy=policy, path=tmp_path)


@pytest.fixture
def ledger(tmp_path):
    return make_ledger(tmp_path)


@pytest.fixture
def config_copy(tmp_path):
    """A private copy of the repo's config folder, so tests can edit protected files."""
    root = tmp_path / "repo"
    shutil.copytree(CONFIG, root / "config")
    return root
