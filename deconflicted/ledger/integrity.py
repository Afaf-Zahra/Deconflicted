"""Config integrity: protected files are hashed into the ledger, and changes must be signed."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

from deconflicted.adapters.hosts import config_dir
from deconflicted.schema import LedgerEntry, Signal

from .client import LedgerClient
from .policy import Policy

# The files the guard refuses to run without, because they define what is safe.
GUARD_FILES = ("config/safety_rules.yaml", "config/policy.yaml", "config/actions.yaml")


class ConfigIntegrity:
    def __init__(self, client: LedgerClient, policy: Policy, root: str | Path | None = None):
        self.client, self.policy = client, policy
        self.root = Path(root) if root else config_dir().parent
        self._reported: tuple[str, ...] = ()

    def file_hashes(self) -> dict[str, str]:
        hashes = {}
        for rel in self.policy.protected_files:
            try:
                hashes[rel] = hashlib.sha256((self.root / rel).read_bytes()).hexdigest()
            except OSError:
                hashes[rel] = "missing"
        return hashes

    def expected(self) -> dict[str, str] | None:
        """Hashes the ledger says are correct: the latest anchor plus signed policy changes after it."""
        expected = None
        for _, payload in self.client.payloads("config_anchor", "policy_change"):
            if "files" in payload and "file" not in payload:
                expected = dict(payload["files"])
            elif expected is not None and "file" in payload:
                expected[payload["file"]] = payload["hash"]
        return expected

    def problems(self, files: tuple[str, ...] | None = None) -> list[str]:
        expected = self.expected()
        if expected is None:
            return ["no config anchor exists in the ledger yet"]
        current = self.file_hashes()
        return [f"{rel} does not match the ledger" for rel in (files or self.policy.protected_files)
                if current.get(rel) != expected.get(rel)]

    def ensure_anchor(self) -> LedgerEntry | None:
        """Write the first config_anchor if the ledger has none. Returns the entry, or None."""
        if self.expected() is not None:
            return None
        return self.client.append("config_anchor", {"files": self.file_hashes()})

    def check(self) -> list[Signal]:
        """An integrity_violation signal for any unsigned change. Each distinct problem is recorded once."""
        problems = tuple(self.problems())
        if not problems:
            self._reported = ()
            return []
        signal = Signal(id=f"integrity-{hashlib.sha256('|'.join(problems).encode()).hexdigest()[:12]}",
                        ts=self.client._clock(), entity_ids=["host:ledger"], kind="integrity_violation",
                        score=1.0, event_ids=[], techniques=["T1562"],
                        detail={"problems": list(problems)})
        if problems != self._reported:
            self.client.append("detection", {"signal": signal.model_dump(mode="json")})
            self._reported = problems
        return [signal]

    def propose_change(self, rel: str) -> LedgerEntry:
        """Bless the current content of a protected file. Needs the signatures policy_change requires."""
        if rel not in self.policy.protected_files:
            raise ValueError(f"{rel} is not a protected file")
        return self.client.append("policy_change", {"file": rel, "hash": self.file_hashes()[rel]})

    def guard_check(self) -> Callable[[], tuple[bool, str]]:
        """For ResponseGuard(integrity_check=...). Unverifiable safety files mean the guard blocks."""
        def check() -> tuple[bool, str]:
            try:
                found = self.problems(tuple(f for f in GUARD_FILES if f in self.policy.protected_files))
            except Exception as exc:  # cannot verify, so do not trust
                return False, f"cannot verify: {exc}"
            return (not found, "; ".join(found))
        return check
