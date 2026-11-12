"""Stand-ins for every module interface, so teammates can build and test without waiting."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from deconflicted.schema import (
    Action, ChainStep, ChainStop, Decision, Event, Incident, LedgerEntry, LedgerKind,
    Preview, Signal, TracePoint, VerifyReport,
)

GENESIS_HASH = "0" * 64


def _t(h: int, m: int, s: int = 0) -> datetime:
    return datetime(2026, 3, 4, h, m, s, tzinfo=timezone.utc)


def canned_incident() -> Incident:
    sig = Signal(
        id="sig-001", ts=_t(3, 43, 2), entity_ids=["host:ws-help-01", "user:alice"],
        kind="role_deviation", score=0.96, event_ids=["windows-000000000001"],
        techniques=["T1059.001"],
    )
    return Incident(
        id="INC-0042",
        title="Admin credentials used from ws-help-01, ends in a PLC setpoint write",
        status="open", severity="critical",
        first_event_ts=_t(3, 40), first_alert_ts=_t(3, 44, 12),
        entities=["host:ws-help-01", "user:alice", "plc:plc-1"],
        signals=[sig],
        chain=[
            ChainStep(ts=_t(3, 43, 2), tactic="Execution", technique="T1059.001",
                      description="powershell.exe -enc ... on ws-help-01", signal_id="sig-001"),
            ChainStep(ts=_t(4, 50), tactic="Impair Process Control", technique="T0836",
                      description="Out-of-range Modbus write to plc-1", signal_id="sig-001"),
        ],
        chain_stop=ChainStop(index=0, reason="not part of any known admin routine"),
        proposed_actions=[Action(id="act-001", kind="block_write", target="eng-ws-01")],
    )


class FakeEngine:
    def ingest(self, events: list[Event]) -> list[Incident]:
        return [canned_incident()] if events else []


class FakeScorer:
    def score(self, entity_id: str, tokens: list[str]) -> float:
        return 0.0


class FakeLedger:
    """In-memory hash chain with no signatures. Entry hash recipe: see docs/conventions.md."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    def append(self, kind: LedgerKind, payload: dict[str, Any]) -> LedgerEntry:
        payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        prev = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        seq = len(self._entries) + 1
        ts = datetime.now(timezone.utc)
        entry_hash = hashlib.sha256(
            f"{seq}|{ts.isoformat()}|{kind}|{payload_hash}|{prev}".encode()
        ).hexdigest()
        entry = LedgerEntry(seq=seq, ts=ts, kind=kind, payload_hash=payload_hash,
                            prev_hash=prev, entry_hash=entry_hash)
        self._entries.append(entry)
        return entry

    def verify(self) -> VerifyReport:
        head = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        return VerifyReport(ok=True, checked=len(self._entries), heads={"fake": head})


class FakeResponseGuard:
    """Fails closed by default: nothing is verified, so the answer is block."""

    def __init__(self, decision: Decision = "block") -> None:
        self.decision = decision

    def preview(self, action: Action, process_state: dict[str, Any]) -> Preview:
        flat = [TracePoint(t=0, level=50), TracePoint(t=300, level=50)]
        return Preview(action=action, before_trace=flat, after_trace=flat,
                       decision=self.decision, reason="fake guard: nothing was simulated")


class FakeDecoyRegistry:
    def __init__(self, ids: tuple[str, ...] = ("decoy:dc-decoy-01", "decoy:plc-decoy-1")) -> None:
        self.ids = set(ids)

    def is_decoy(self, entity_id: str) -> bool:
        return entity_id in self.ids


class FakeDecoyTrigger:
    def __call__(self, event: Event) -> Optional[Signal]:
        return None