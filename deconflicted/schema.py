"""Shared contracts for Deconflicted.

Conventions (UTC, ids, entity ids, token names): docs/conventions.md
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional, Protocol, runtime_checkable

from pydantic import AfterValidator, BaseModel, ConfigDict


def _utc(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware (UTC)")
    return v.astimezone(timezone.utc)


UtcDatetime = Annotated[datetime, AfterValidator(_utc)]

Source = Literal["windows", "proxy", "flow", "linux", "modbus", "opcua"]
EventAction = Literal[
    "proc_create", "logon", "net_conn", "http_request", "flow", "read", "write", "log_clear"
]
SignalKind = Literal[
    "role_deviation", "routine_break", "ot_invariant", "decoy_hit",
    "log_clear", "scorer_anomaly", "integrity_violation",
]
ActionKind = Literal[
    "isolate_host", "disable_account", "block_write",
    "reset_setpoint", "kill_process", "rate_limit_writes",
]
Decision = Literal["allow", "downgrade", "block"]
Severity = Literal["info", "warning", "critical"]
IncidentStatus = Literal["open", "closed"]
LedgerKind = Literal[
    "detection", "response_decision", "approval",
    "policy_change", "ingest_anchor", "config_anchor",
]
NodeKind = Literal["host", "user", "proc", "plc", "decoy"]


class Model(BaseModel):
    # Unknown fields are rejected so a typo fails loudly instead of being ignored.
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- events
class Label(Model):
    """Ground truth. Only used in evaluation; never present in raw logs."""
    attack: bool
    step: Optional[int] = None


class Event(Model):
    id: str                       # source + first 12 hex chars of SHA-1 of the raw line
    ts: UtcDatetime
    source: Source
    host: str
    user: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    cmdline: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    action: EventAction
    obj: Optional[str] = None     # register, node id, URL or file
    value: Optional[float | str] = None
    raw: str                      # the original log line, unchanged
    label: Optional[Label] = None


# ---------------------------------------------------------------- detection
class Signal(Model):
    id: str
    ts: UtcDatetime
    entity_ids: list[str]
    kind: SignalKind
    score: float                  # 0 to 1
    event_ids: list[str]
    techniques: list[str] = []    # ATT&CK ids
    detail: dict[str, Any] = {}


class ChainStep(Model):
    ts: UtcDatetime
    tactic: str                   # ATT&CK tactic name, e.g. "Lateral Movement"
    technique: str = ""           # e.g. "T1021.002"
    description: str
    signal_id: str
    matched_routine: bool = False


class ChainStop(Model):
    index: int                    # chain index where activity stops matching a routine
    reason: str


class Action(Model):
    id: str
    kind: ActionKind
    target: str
    params: dict[str, Any] = {}


class Incident(Model):
    id: str
    title: str = ""
    status: IncidentStatus
    severity: Severity
    first_event_ts: UtcDatetime
    first_alert_ts: Optional[UtcDatetime] = None
    entities: list[str] = []
    signals: list[Signal] = []
    chain: list[ChainStep] = []
    promoted_held_signal_ids: list[str] = []
    chain_stop: Optional[ChainStop] = None
    proposed_actions: list[Action] = []


# ---------------------------------------------------------------- safety
class TracePoint(Model):
    t: float                      # seconds into the simulation
    level: float                  # tank level, percent


class Violation(Model):
    rule_id: str
    detail: str
    ts: float                     # seconds into the simulation


class Preview(Model):
    action: Action
    before_trace: list[TracePoint]
    after_trace: list[TracePoint]
    violations: list[Violation] = []
    safer_options: list[Action] = []
    decision: Decision
    reason: str


# ---------------------------------------------------------------- ledger
class Signature(Model):
    node: str
    sig: str


class LedgerEntry(Model):
    seq: int
    ts: UtcDatetime
    kind: LedgerKind
    payload_hash: str
    prev_hash: str
    entry_hash: str
    signatures: list[Signature] = []


class NodeStatus(Model):
    node: str
    up: bool
    head: str
    signatures: int


class VerifyError(Model):
    seq: int
    reason: str


class VerifyReport(Model):
    ok: bool
    checked: int
    errors: list[VerifyError] = []
    heads: dict[str, str] = {}


# ---------------------------------------------------------------- UI views
class Budget(Model):
    budget: int
    used: int
    window_hours: int = 24


class GraphNode(Model):
    id: str
    kind: NodeKind
    anchor: bool = False
    decoy_hit: bool = False


class GraphEdge(Model):
    source: str
    target: str
    token: str
    ts: UtcDatetime


class IncidentGraph(Model):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Decoy(Model):
    id: str
    type: str
    address: str


class DecoyHit(Model):
    ts: UtcDatetime
    decoy: str
    source: str


class Placement(Model):
    host: str
    decoy_type: str
    address: str
    reason: str
    safety_ok: bool


class DecoysView(Model):
    decoys: list[Decoy]
    hits: list[DecoyHit] = []
    placements: list[Placement] = []


# ---------------------------------------------------------------- evaluation
class MetricsReport(Model):
    budget: int
    fp_incidents_per_24h: int     # on the held-out normal day
    chain_recall: float           # attack steps found / all attack steps
    time_to_first_alert_s: Optional[float] = None
    safety_violations: int        # executed actions that broke a rule; must be 0
    raw_alerts: int
    incidents: int
    naive_alerts: int             # alerts a plain "every signal over threshold" tool would raise
    events_per_sec: float


# ---------------------------------------------------------------- module interfaces
@runtime_checkable
class Engine(Protocol):
    def ingest(self, events: list[Event]) -> list[Incident]: ...


@runtime_checkable
class Scorer(Protocol):
    def score(self, entity_id: str, tokens: list[str]) -> float: ...


@runtime_checkable
class Ledger(Protocol):
    def append(self, kind: LedgerKind, payload: dict[str, Any]) -> LedgerEntry: ...
    def verify(self) -> VerifyReport: ...


@runtime_checkable
class ResponseGuard(Protocol):
    def preview(self, action: Action, process_state: dict[str, Any]) -> Preview: ...


@runtime_checkable
class DecoyRegistry(Protocol):
    def is_decoy(self, entity_id: str) -> bool: ...


@runtime_checkable
class DecoyTrigger(Protocol):
    def __call__(self, event: Event) -> Optional[Signal]: ...