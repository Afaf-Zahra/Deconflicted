"""Builds the shared ledger client for the API and the command line from environment settings.

DECONFLICTED_LEDGER_NODES   node-a=http://ledger-a:9101,node-b=http://ledger-b:9102,node-c=...
DECONFLICTED_LEDGER_DB      path of the client store (default data/ledger/client.db)
DECONFLICTED_LEDGER_EMBEDDED=1   run three nodes inside this process (development and tests only)
"""
from __future__ import annotations

import os
from pathlib import Path

from .client import LedgerClient, NodeHandle, QuorumError, http_node
from .integrity import ConfigIntegrity
from .node import create_app
from .policy import Policy, load_policy
from .transport import in_process_client


class LedgerUnavailable(RuntimeError):
    """No ledger is configured. Callers must fail closed."""


def embedded_nodes(policy: Policy, data_dir: str | Path) -> dict[str, NodeHandle]:
    return {name: NodeHandle(name, in_process_client(create_app(name, Path(data_dir) / name))) for name in policy.nodes}


def build_client(policy: Policy | None = None) -> LedgerClient:
    policy = policy or load_policy()
    db = os.environ.get("DECONFLICTED_LEDGER_DB", "data/ledger/client.db")
    spec = os.environ.get("DECONFLICTED_LEDGER_NODES", "")
    if spec:
        pairs = [item.split("=", 1) for item in spec.split(",") if item.strip()]
        nodes = {name.strip(): http_node(name.strip(), url.strip()) for name, url in pairs}
        if set(nodes) != set(policy.nodes):
            raise LedgerUnavailable("DECONFLICTED_LEDGER_NODES does not match the nodes in policy.yaml")
    elif os.environ.get("DECONFLICTED_LEDGER_EMBEDDED") == "1":
        nodes = embedded_nodes(policy, Path(db).parent / "embedded")
    else:
        raise LedgerUnavailable("no ledger nodes are configured (set DECONFLICTED_LEDGER_NODES)")
    return LedgerClient(db, nodes, policy)


_client: LedgerClient | None = None
_integrity: ConfigIntegrity | None = None


def get_client() -> LedgerClient:
    global _client
    if _client is None:
        _client = build_client()
    return _client


def get_integrity() -> ConfigIntegrity:
    """The shared config-integrity checker. The first call anchors the config if the ledger has no anchor,
    and records any protected file that no longer matches it."""
    global _integrity
    if _integrity is None:
        client = get_client()
        integrity = ConfigIntegrity(client, client.policy)
        try:
            integrity.ensure_anchor()
            integrity.check()  # a file changed while the API was down is recorded at start-up
        except QuorumError as exc:
            raise LedgerUnavailable(f"cannot anchor or check the config: {exc}") from exc
        _integrity = integrity
    return _integrity


def set_client(client: LedgerClient | None, integrity: ConfigIntegrity | None = None) -> None:
    """Replace the shared client (tests, and the API at start-up)."""
    global _client, _integrity
    _client, _integrity = client, integrity
