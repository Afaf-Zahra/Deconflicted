"""The nodes as separate processes over real HTTP, the way Docker runs them."""
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from deconflicted.ledger import LedgerClient, QuorumError, http_node, load_policy

CONFIG = Path(__file__).parents[2] / "config"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Cluster:
    def __init__(self, tmp_path, policy):
        self.tmp_path, self.policy = tmp_path, policy
        self.ports = {name: free_port() for name in policy.nodes}
        self.procs: dict[str, subprocess.Popen] = {}
        self.clients: list[LedgerClient] = []

    def start(self, name):
        self.procs[name] = subprocess.Popen(
            [sys.executable, "-m", "deconflicted.ledger.node", "--id", name, "--port", str(self.ports[name]),
             "--data", str(self.tmp_path / name), "--host", "127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{self.ports[name]}/health", timeout=0.5).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError(f"{name} did not start")

    def stop(self, name):
        proc = self.procs.pop(name, None)
        if proc:
            proc.terminate()
            proc.wait(timeout=10)

    def client(self):
        nodes = {n: http_node(n, f"http://127.0.0.1:{p}", timeout=1.0) for n, p in self.ports.items()}
        client = LedgerClient(self.tmp_path / "client.db", nodes, self.policy)
        self.clients.append(client)
        return client


@pytest.fixture
def cluster(tmp_path):
    cluster = Cluster(tmp_path, load_policy(CONFIG / "policy.yaml"))
    for name in cluster.policy.nodes:
        cluster.start(name)
    yield cluster
    for client in cluster.clients:
        client.close()
    for name in list(cluster.procs):
        cluster.stop(name)


def test_three_real_nodes_sign_verify_and_survive_outages(cluster):
    client = cluster.client()
    first = client.append("response_decision", {"decision": "allow"})
    assert len(first.signatures) == 3 and client.verify().ok
    cluster.stop("node-c")
    assert len(client.append("response_decision", {"decision": "block"}).signatures) == 2
    assert [(n.node, n.up) for n in client.node_status()] == [("node-a", True), ("node-b", True), ("node-c", False)]
    cluster.stop("node-b")
    with pytest.raises(QuorumError):
        client.append("approval", {"x": 1})
    assert client.count() == 2
    cluster.start("node-b")
    cluster.start("node-c")
    entry = client.append("approval", {"x": 2})
    assert entry.seq == 2 and len(entry.signatures) == 3, "restarted nodes caught up from their own database, then signed"
    report = client.verify()
    assert report.ok and len(set(report.heads.values())) == 1
    assert client.sync() == {"node-a": 2, "node-b": 2, "node-c": 2}
