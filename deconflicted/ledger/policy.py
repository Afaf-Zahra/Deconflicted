"""Ledger policy from config/policy.yaml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import get_args

import yaml

from deconflicted.adapters.hosts import config_dir
from deconflicted.schema import LedgerKind


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    nodes: tuple[str, ...]
    quorum: int
    signatures_required: dict[str, int]
    analysts: tuple[str, ...]
    anchor_interval: int
    protected_files: tuple[str, ...]

    def needed(self, kind: str) -> int:
        """Valid signatures needed to commit an entry: the quorum, or more if the policy asks."""
        return max(self.quorum, self.signatures_required.get(kind, 0))


def load_policy(path: str | Path | None = None) -> Policy:
    path = Path(path) if path else config_dir() / "policy.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read {path.name}: {exc}") from exc
    nodes, quorum = tuple(data.get("nodes") or ()), data.get("quorum")
    if not nodes or isinstance(quorum, bool) or not isinstance(quorum, int) or not 1 <= quorum <= len(nodes):
        raise PolicyError("policy needs nodes and a quorum between 1 and the number of nodes")
    required = dict(data.get("signatures_required") or {})
    valid = set(get_args(LedgerKind))
    for kind, count in required.items():
        if kind not in valid or isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= len(nodes):
            raise PolicyError(f"bad signatures_required entry {kind!r}: {count!r}")
    interval = data.get("anchor_interval_events", 500)
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
        raise PolicyError("anchor_interval_events must be a positive integer")
    return Policy(nodes, quorum, required, tuple(data.get("analysts") or ()), interval,
                  tuple(data.get("protected_files") or ()))
