"""The detection engine: signals from every event, held weak signals, incidents, the graph and the alert budget.

Every event is checked once and makes at most one signal:
  certain   decoy_hit, log_clear, ot_invariant, integrity_violation: opens or joins an incident by itself
  strong    a baseline signal with a score of at least settings.strong: opens or joins an incident too, but only a few
            per rolling window (settings.non_anchor_quota) may be opened by a score alone
  weak      a baseline signal above settings.weak, or a scorer_anomaly from the optional scorer: held, and promoted into
            an incident when it shares a user, a workstation or a PLC with it, inside the time window, within
            settings.hops steps. The scorer never opens an incident by itself.
Servers that everyone talks to (settings.ignore_host_kinds) and decoys never link two incidents.
File and cloud-object access (tokens file:read and file:write) is not judged by the baseline: only a decoy file
(config/decoy_files.yaml) raises a signal, a decoy_hit, whatever tool opened it.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from deconflicted.adapters.hosts import resolve_ip
from deconflicted.deception import get_service
from deconflicted.schema import (Action, Budget, ChainStep, ChainStop, DecoyHit, Event, GraphEdge, GraphNode,
                                 Incident, IncidentGraph, Signal)

from .baseline import START, Baseline
from .config import CoreConfig, load_config
from .entities import OT_SOURCES, acting_host, entities_of, host_entity, token_of
from .filedecoys import FileDecoys
from .invariants import Invariants
from .routines import RoutineCheck, RoutineRegistry
from .settings import Settings, load_settings

CERTAIN = ("decoy_hit", "log_clear", "ot_invariant", "integrity_violation")
BASELINE_KINDS = ("role_deviation", "routine_break")
KIND_TACTIC = {"integrity_violation": "Defense Evasion"}
NODE_KINDS = ("host", "user", "proc", "plc", "decoy")
WINDOW_TOKENS = 20  # recent tokens per actor given to the scorer
PENDING_AT = 30  # seconds into the safety simulation at which a breaching write is assumed to land
# object -> (process field, register number); OPC-UA node names are the same registers (docs/conventions.md)
REGISTERS = {
    "reg:40001": ("setpoint", 40001), "ns=2;s=Tank1.Setpoint": ("setpoint", 40001),
    "reg:40002": ("level", 40002), "ns=2;s=Tank1.Level": ("level", 40002),
    "reg:40010": ("pump", 40010), "ns=2;s=Tank1.PumpCmd": ("pump", 40010),
    "reg:40011": ("valve", 40011),
}


@dataclass
class _Case:
    id: str
    opened_by_score: bool
    signals: dict[str, Signal] = field(default_factory=dict)
    promoted: list[str] = field(default_factory=list)
    anchors: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)


class Pipeline:
    """The detection engine. It implements the Engine protocol from schema.py."""

    def __init__(self, config: CoreConfig | None = None, baseline: Baseline | None = None,
                 settings: Settings | None = None, decoy_trigger: Callable[[Event], Signal | None] | None = None,
                 recorder: Callable[[str, dict], Any] | None = None, scorer: Any | None = None,
                 integrity_check: Callable[[], list[Signal]] | None = None, integrity_interval: float = 1.0,
                 max_events: int = 100_000, file_decoys: FileDecoys | None = None):
        self.lock = threading.RLock()
        self.config = config or load_config()
        self.settings = settings or load_settings()
        self.baseline = baseline or Baseline(self.config)
        self.routines = RoutineRegistry(self.config)
        self.invariants = Invariants(self.config)
        self.decoy_trigger = decoy_trigger if decoy_trigger is not None else get_service().trigger
        self.file_decoys = file_decoys if file_decoys is not None else FileDecoys(self.config)
        self.recorder = recorder
        self.scorer = scorer
        self.integrity_check = integrity_check
        self.integrity_interval = integrity_interval
        self.max_events = max_events
        self.baseline_status = "trained baseline" if self.baseline.trained_events else "no trained baseline"
        self.scorer_status = "on" if scorer is not None else "off"
        self.record_errors: list[str] = []
        self._clear()

    def _clear(self) -> None:
        self._events: dict[str, Event] = {}
        self._evidence: set[str] = set()
        self._meta: dict[str, dict] = {}  # signal id -> token and routine check of its event
        self._cases: dict[str, _Case] = {}
        self._incidents: dict[str, Incident] = {}
        self._held: dict[str, Signal] = {}
        self._held_order: dict[str, deque[str]] = defaultdict(deque)
        self._opened: list[tuple[datetime, str]] = []  # incidents a score alone opened, for the quota
        self._counter = 0
        self._now: datetime | None = None
        self._process = {"level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0}
        self._tokens: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=WINDOW_TOKENS))
        self._integrity_seen: set[str] = set()
        self._integrity_polled: float | None = None
        self.baseline.reset()
        self.routines.reset()

    def reset(self) -> None:
        with self.lock:
            self._clear()

    # ------------------------------------------------------------------ ingest
    def ingest(self, events: list[Event]) -> list[Incident]:
        """Take new events (a repeated event id is ignored) and return the incidents that were created or changed."""
        with self.lock:
            changed: dict[str, _Case] = {}
            for event in sorted(events, key=lambda e: (e.ts, e.id)):
                if event.id in self._events:
                    continue
                self._events[event.id] = event
                if self._now is None or event.ts > self._now:
                    self._now = event.ts
                self._track_process(event)
                for signal, meta in self._detect(event):
                    self._meta[signal.id] = meta
                    self._evidence.update(signal.event_ids)
                    self._handle(signal, changed)
            self._poll_integrity(changed)
            return self._finish(changed)

    def add_signals(self, signals: list[Signal]) -> list[Incident]:
        """Signals that do not come from one event. They are handled at their own time."""
        with self.lock:
            changed: dict[str, _Case] = {}
            for signal in signals:
                self._meta.setdefault(signal.id, {"token": "", "routine": "none", "reason": ""})
                self._evidence.update(signal.event_ids)
                self._handle(signal, changed)
            return self._finish(changed)

    def _poll(self) -> None:
        changed: dict[str, _Case] = {}
        self._poll_integrity(changed)
        if changed:
            self._finish(changed)

    def _poll_integrity(self, changed: dict[str, _Case]) -> None:
        """Signals from the ledger's config check. Each distinct problem is handled once, at the current log time."""
        if self.integrity_check is None:
            return
        now = time.monotonic()
        if self._integrity_polled is not None and now - self._integrity_polled < self.integrity_interval:
            return
        self._integrity_polled = now
        try:
            found = self.integrity_check()
        except Exception as exc:  # the config could not be checked; detection goes on
            self.record_errors.append(f"integrity check failed: {exc}")
            del self.record_errors[:-20]
            return
        fresh = [signal for signal in found if signal.id not in self._integrity_seen]
        self._integrity_seen = {signal.id for signal in found}
        for signal in fresh:
            if self._now is not None:  # the log time, not the clock of this machine, so old data keeps its held signals
                signal = signal.model_copy(update={"ts": self._now})
            self._meta.setdefault(signal.id, {"token": "", "routine": "none", "reason": ""})
            self._handle(signal, changed)

    def _detect(self, event: Event) -> list[tuple[Signal, dict]]:
        token = token_of(event)
        if token.startswith("file:"):
            return self._detect_file(event, token)
        hit = self.decoy_trigger(event)
        if token == "net:decoy_touch" and hit is None:
            return []  # an allowlisted contact with a decoy (a scan, an admin tool) is not judged by the baseline either
        obs = self.baseline.observe(event, token)
        window = self._tokens[obs.actor]
        window.append(token)
        routine = self.routines.check(token, obs.actor, obs.role, acting_host(event), event.ts)
        meta = {"token": token, "routine": routine.status, "reason": routine.reason}
        certain: list[Signal] = []
        if hit is not None:
            certain.append(hit)
        if event.action == "log_clear":
            certain.append(self._log_clear(event, token))
        breach = self.invariants.check(event)
        if breach is not None:
            certain.append(breach)
        if certain:
            return [(signal, meta) for signal in certain]
        if routine.status == "matched":
            return []
        kind = None
        if routine.status == "broken":
            kind = "routine_break"
        elif obs.score >= self.settings.weak:
            kind = "role_deviation"
        if kind is not None:
            return [(self._baseline_signal(event, token, obs, routine, kind), meta)]
        signal = self._scorer_signal(event, token, obs.actor, list(window))
        return [(signal, meta)] if signal is not None else []

    def _detect_file(self, event: Event, token: str) -> list[tuple[Signal, dict]]:
        """Ordinary file access is not judged: nothing is known about what is normal for it. Only a decoy file raises."""
        signal = self.file_decoys.signal(event)
        if signal is None:
            return []
        hits = getattr(self.decoy_trigger, "hits", None)
        if hits is not None:  # so that the Decoys page lists it like any other decoy hit
            hits.append(DecoyHit(ts=event.ts, decoy=signal.detail["decoy"], source=acting_host(event)))
        return [(signal, {"token": token, "routine": "none", "reason": ""})]

    def _technique(self, token: str) -> list[str]:
        technique = self.config.attack_map.get(token, ("", ""))[1]
        return [technique] if technique else []

    def _log_clear(self, event: Event, token: str) -> Signal:
        return Signal(id=f"clr-{event.id}", ts=event.ts, entity_ids=entities_of(event, self.config), kind="log_clear",
                      score=1.0, event_ids=[event.id], techniques=self._technique(token), detail={})

    def _baseline_signal(self, event: Event, token: str, obs, routine: RoutineCheck, kind: str) -> Signal:
        if kind == "routine_break":
            note = routine.reason
        elif obs.reason == "hour":
            note = f"{token} at {event.ts:%H:%M} UTC is unusual for the {obs.role} role"
        elif obs.previous == START:
            note = f"{token} as the first action is unusual for the {obs.role} role"
        else:
            note = f"{token} after {obs.previous} is unusual for the {obs.role} role"
        return Signal(id=f"{'rtn' if kind == 'routine_break' else 'dev'}-{event.id}", ts=event.ts,
                      entity_ids=entities_of(event, self.config), kind=kind, score=obs.score, event_ids=[event.id],
                      techniques=self._technique(token),
                      detail={"token": token, "role": obs.role, "actor": obs.actor, "why": obs.reason, "note": note,
                              "held": obs.score < self.settings.strong})

    def _scorer_signal(self, event: Event, token: str, actor: str, tokens: list[str]) -> Signal | None:
        """A held scorer_anomaly when the optional scorer finds the actor's recent behaviour unusual."""
        if self.scorer is None:
            return None
        try:
            score = min(1.0, max(0.0, float(self.scorer.score(actor, tokens))))
        except Exception as exc:  # a broken scorer is switched off; the baseline carries on
            self.scorer, self.scorer_status = None, f"off: failed ({exc})"
            return None
        if score < self.settings.scorer_weak:
            return None
        return Signal(id=f"ml-{event.id}", ts=event.ts, entity_ids=entities_of(event, self.config), kind="scorer_anomaly",
                      score=score, event_ids=[event.id], techniques=self._technique(token),
                      detail={"token": token, "recent": tokens[-5:], "held": True,
                              "note": f"the scorer finds the recent behaviour of {actor} unusual"})

    def _track_process(self, event: Event) -> None:
        """Keep the latest tank level and the latest allowed setpoint, pump and valve values for the safety guard."""
        value = event.value
        entry = REGISTERS.get(event.obj or "")
        if event.source not in OT_SOURCES or entry is None or isinstance(value, bool) or not isinstance(value, (int, float)):
            return
        name = entry[0]
        if event.action == "read":
            if name == "level":
                self._process["level"] = min(100.0, max(0.0, float(value)))
        elif event.action == "write" and self.invariants.check(event) is None:
            if name == "setpoint":
                self._process["setpoint"] = float(value)
            elif name == "pump":
                self._process["pump"] = value != 0
            elif name == "valve":
                self._process["valve"] = min(100.0, max(0.0, float(value)))

    # ------------------------------------------------------------------ correlation
    def _is_hub(self, entity: str) -> bool:
        kind, _, name = entity.partition(":")
        if kind == "decoy":
            return True
        return kind == "host" and self.config.hosts.get(name, {}).get("kind") in self.settings.ignore_host_kinds

    def _links(self, signal: Signal) -> set[str]:
        """The entities that can join this signal to others: its own, and the machine that logged the event."""
        found = set(signal.entity_ids)
        for event_id in signal.event_ids:
            event = self._events.get(event_id)
            if event is not None:
                found.add(host_entity(event.host, self.config))
        kept = {entity for entity in found if not self._is_hub(entity)}
        return kept or found

    def _window(self, case: _Case) -> tuple[datetime, datetime]:
        times = [case.signals[signal_id].ts for signal_id in case.anchors]
        return (min(times) - timedelta(hours=self.settings.hours_before),
                max(times) + timedelta(hours=self.settings.hours_after))

    def _matching(self, links: set[str], ts: datetime) -> list[_Case]:
        """Open incidents an anchor with these links can join, lowest id first."""
        limit = timedelta(hours=self.settings.join_hours)
        found = []
        for case in self._cases.values():
            if links & case.links:
                times = [signal.ts for signal in case.signals.values()]
                if min(times) - limit <= ts <= max(times) + limit:
                    found.append(case)
        return sorted(found, key=lambda case: case.id)

    def _weak_target(self, links: set[str], ts: datetime) -> _Case | None:
        for case in sorted(self._cases.values(), key=lambda case: case.id):
            low, high = self._window(case)
            if low <= ts <= high and links & case.links:
                return case
        return None

    def _quota_ok(self, ts: datetime) -> bool:
        start = ts - timedelta(hours=self.settings.window_hours)
        return sum(1 for opened, _ in self._opened if opened > start) < self.settings.non_anchor_quota

    def _hold(self, signal: Signal) -> None:
        self._held[signal.id] = signal
        for entity in signal.entity_ids:
            queue = self._held_order[entity]
            queue.append(signal.id)
            while len(queue) > self.settings.held_per_entity:
                self._held.pop(queue.popleft(), None)

    def _add(self, case: _Case, signal: Signal, links: set[str], promoted: bool, anchor: bool = False) -> None:
        case.signals[signal.id] = signal
        case.links |= links
        if anchor:
            case.anchors.add(signal.id)
        if promoted and signal.id not in case.promoted:
            case.promoted.append(signal.id)
        self._held.pop(signal.id, None)

    def _new_case(self, signal: Signal, certain: bool) -> _Case:
        self._counter += 1
        case = _Case(id=f"INC-{self._counter:04d}", opened_by_score=not certain)
        self._cases[case.id] = case
        if not certain:
            self._opened.append((signal.ts, case.id))
        return case

    def _merge(self, keep: _Case, other: _Case, changed: dict[str, _Case]) -> None:
        keep.signals.update(other.signals)
        keep.links |= other.links
        keep.anchors |= other.anchors
        keep.promoted += [signal_id for signal_id in other.promoted if signal_id not in keep.promoted]
        keep.opened_by_score = keep.opened_by_score and other.opened_by_score
        self._cases.pop(other.id, None)
        self._incidents.pop(other.id, None)
        changed.pop(other.id, None)
        self._opened = [(opened, case_id) for opened, case_id in self._opened if case_id != other.id]

    def _expand(self, case: _Case, changed: dict[str, _Case]) -> None:
        """Promote held signals that share an entity with the incident, then those that share one with those, and so on."""
        for _ in range(self.settings.hops):
            low, high = self._window(case)
            picked = [signal for signal in self._held.values() if low <= signal.ts <= high and self._links(signal) & case.links]
            if not picked:
                return
            for signal in sorted(picked, key=lambda s: (s.ts, s.id)):
                self._add(case, signal, self._links(signal), promoted=True)
            changed[case.id] = case

    def _handle(self, signal: Signal, changed: dict[str, _Case]) -> None:
        certain = signal.kind in CERTAIN
        anchor = certain or (signal.kind in BASELINE_KINDS and signal.score >= self.settings.strong)
        links = self._links(signal)
        if not anchor:
            case = self._weak_target(links, signal.ts)
            if case is None:
                self._hold(signal)
            else:
                self._add(case, signal, links, promoted=True)
                changed[case.id] = case
            return
        matches = self._matching(links, signal.ts)
        if matches:
            case = matches[0]
            for other in matches[1:]:
                self._merge(case, other, changed)
        else:
            if not certain and not self._quota_ok(signal.ts):
                self._hold(signal)
                return
            case = self._new_case(signal, certain)
        self._add(case, signal, links, promoted=False, anchor=True)
        changed[case.id] = case
        self._expand(case, changed)

    def _finish(self, changed: dict[str, _Case]) -> list[Incident]:
        if self._now is not None:
            limit = self._now - timedelta(hours=self.settings.held_hours)
            for signal_id in [key for key, signal in self._held.items() if signal.ts < limit]:
                del self._held[signal_id]
        overflow = len(self._events) - self.max_events
        if overflow > 0:
            for event_id in [key for key in self._events if key not in self._evidence][:overflow]:
                del self._events[event_id]
        result = []
        for case_id in sorted(changed):
            if case_id in self._cases:
                incident = self._build(self._cases[case_id])
                self._incidents[case_id] = incident
                result.append(incident)
        self._record(result)
        return result

    def _record(self, incidents: list[Incident]) -> None:
        if self.recorder is None:
            return
        for incident in incidents:
            payload = {"incident_id": incident.id, "severity": incident.severity, "title": incident.title,
                       "first_event_ts": incident.first_event_ts.isoformat(),
                       "first_alert_ts": incident.first_alert_ts.isoformat() if incident.first_alert_ts else None,
                       "signal_ids": [signal.id for signal in incident.signals], "entities": incident.entities}
            try:
                self.recorder("detection", payload)
            except Exception as exc:  # a ledger problem must not stop detection; it is listed in status()
                self.record_errors.append(f"{incident.id}: {exc}")
                del self.record_errors[:-20]

    # ------------------------------------------------------------------ building an incident
    def _build(self, case: _Case) -> Incident:
        signals = sorted(case.signals.values(), key=lambda s: (s.ts, s.id))
        chain = [self._step(signal) for signal in signals]
        stop = None
        for index, step in enumerate(chain):
            if index >= 1 and not step.matched_routine:
                stop = ChainStop(index=index, reason=self._stop_reason(signals[index]))
                break
        kinds = {signal.kind for signal in signals}
        critical = bool({"ot_invariant", "integrity_violation"} & kinds) or len(kinds & set(CERTAIN)) >= 2
        return Incident(
            id=case.id, title=self._title(signals), status="open", severity="critical" if critical else "warning",
            first_event_ts=signals[0].ts, first_alert_ts=min(case.signals[a].ts for a in case.anchors),
            entities=self._entities(signals), signals=signals, chain=chain,
            promoted_held_signal_ids=[signal_id for signal_id in case.promoted if signal_id in case.signals],
            chain_stop=stop, proposed_actions=self._actions(case.id, signals))

    def _entities(self, signals: list[Signal]) -> list[str]:
        seen: dict[str, None] = {}
        for signal in signals:
            for entity in signal.entity_ids:
                seen.setdefault(entity)
            for event_id in signal.event_ids:
                event = self._events.get(event_id)
                if event is not None:
                    seen.setdefault(host_entity(event.host, self.config))
        return list(seen)

    def _step(self, signal: Signal) -> ChainStep:
        meta = self._meta.get(signal.id, {})
        event = self._events.get(signal.event_ids[0]) if signal.event_ids else None
        token = meta.get("token") or (token_of(event) if event is not None else "")
        fallback = (KIND_TACTIC.get(signal.kind, "Unclassified"), signal.techniques[0] if signal.techniques else "")
        tactic, technique = self.config.attack_map.get(token, fallback)
        routine = meta.get("routine")
        matched = routine == "matched" or (routine == "none" and signal.kind in BASELINE_KINDS
                                           and token in self.settings.ordinary_tokens)
        return ChainStep(ts=signal.ts, tactic=tactic, technique=technique, signal_id=signal.id,
                         description=self._describe(signal, token, event), matched_routine=matched)

    def _stop_reason(self, signal: Signal) -> str:
        meta = self._meta.get(signal.id, {})
        if meta.get("routine") == "broken" and meta.get("reason"):
            return meta["reason"]
        return f"{meta.get('token') or signal.kind} is not part of any known admin routine"

    def _describe(self, signal: Signal, token: str, event: Event | None) -> str:
        if signal.kind == "integrity_violation":
            return "; ".join(signal.detail.get("problems", [])) or "Protected configuration changed"
        if event is None:
            return signal.kind.replace("_", " ")
        where = event.host
        if signal.kind == "decoy_hit" and "path" in signal.detail:
            verb = "changed" if event.action == "write" else "opened"
            return f"{event.user or 'someone'} {verb} the decoy file {signal.detail['path']} on {where} with {signal.detail['how']}"
        if signal.kind == "decoy_hit":
            return f"Connection to decoy {signal.detail.get('decoy', event.dst_ip)} ({event.dst_ip}:{event.dst_port})"
        if signal.kind == "log_clear":
            return f"Audit log cleared on {where}"
        if signal.kind == "ot_invariant":
            detail = signal.detail
            if "limit" in detail:
                return f"Out-of-range write {detail['value']} to {where} {event.obj} (limit {detail['limit']})"
            return f"Write to {where} {event.obj} from {detail.get('source', 'an unlisted source')}"
        if event.action == "logon":
            return f"Logon as {event.user} on {where} from {acting_host(event)}"
        if event.action == "proc_create":
            command = event.cmdline or event.process or token
            return f"{command if len(command) <= 70 else command[:67] + '...'} on {where}"
        origin = acting_host(event)
        return f"{token} on {where}" if origin == where else f"{token} from {origin} to {where}"

    def _title(self, signals: list[Signal]) -> str:
        def first(prefix: str) -> str | None:
            return next((e.split(":", 1)[1] for s in signals for e in s.entity_ids if e.startswith(prefix)), None)

        user, host = first("user:"), first("host:")
        subject = f"{user} on {host}" if user and host else user or host or "Unusual activity"
        last = next((s for s in reversed(signals) if s.kind in CERTAIN), None)
        if last is None:
            return f"{subject}: behaviour that is unusual for its role"
        if last.kind == "integrity_violation":
            problems = last.detail.get("problems") or ["a protected file changed"]
            return f"Protected configuration changed: {problems[0]}"
        if last.kind == "ot_invariant":
            plc = last.entity_ids[0].split(":", 1)[1] if last.entity_ids else "the process"
            what = "an out-of-range write to" if "limit" in last.detail else "a write from an unlisted source to"
            return f"{subject} ends in {what} {plc}"
        if last.kind == "decoy_hit":
            return f"{subject} touches the decoy {last.detail.get('decoy', '')}".rstrip()
        if last.kind == "log_clear":
            return f"{subject} clears an audit log"
        return f"{subject}: a protected file or log was tampered with"

    def _actions(self, case_id: str, signals: list[Signal]) -> list[Action]:
        """Isolate the PLC, block the writer, disable the account. Ids are unique across incidents."""
        targets = [signal for signal in signals if signal.kind != "integrity_violation"]
        wanted: list[tuple[str, str, dict]] = []
        for signal in targets:
            if signal.kind == "ot_invariant" and signal.entity_ids:
                target = signal.entity_ids[0].split(":", 1)[1]
                writer = next((e.split(":", 1)[1] for e in signal.entity_ids[1:] if e.startswith("host:")), None)
                wanted.append(("isolate_host", target, {}))
                if writer:
                    wanted.append(("block_write", writer, {"to": target}))
        user = next((e.split(":", 1)[1] for s in targets for e in s.entity_ids if e.startswith("user:")), None)
        if user:
            wanted.append(("disable_account", user, {}))
        if not any(kind == "isolate_host" for kind, _, _ in wanted):
            host = next((e.split(":", 1)[1] for s in targets for e in s.entity_ids
                         if e.startswith("host:") and not self._is_hub(e)), None)
            if host:
                wanted.append(("isolate_host", host, {}))
        seen: set[tuple] = set()
        actions: list[Action] = []
        for kind, target, params in wanted:
            key = (kind, target, params.get("to"))
            if key not in seen:
                seen.add(key)
                actions.append(Action(id=f"act-{case_id}-{len(actions) + 1}", kind=kind, target=target, params=params))
        return actions

    # ------------------------------------------------------------------ what the API and the other services read
    def incidents(self) -> list[Incident]:
        with self.lock:
            self._poll()
            return sorted(self._incidents.values(), key=lambda incident: incident.id)

    def incident(self, incident_id: str) -> Incident | None:
        with self.lock:
            self._poll()
            return self._incidents.get(incident_id)

    def events(self, ids: list[str]) -> list[Event]:
        with self.lock:
            return [self._events[event_id] for event_id in ids if event_id in self._events]

    def budget(self) -> Budget:
        with self.lock:
            self._poll()
            reference = self._now or max((i.first_alert_ts for i in self._incidents.values() if i.first_alert_ts is not None),
                                         default=None)
            used = 0
            if reference is not None:
                start = reference - timedelta(hours=self.settings.window_hours)
                used = sum(1 for i in self._incidents.values() if i.first_alert_ts is not None and i.first_alert_ts > start)
            return Budget(budget=self.settings.budget, used=used, window_hours=self.settings.window_hours)

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {"baseline": self.baseline_status, "trained_events": self.baseline.trained_events,
                    "scorer": self.scorer_status,
                    "thresholds": {"weak": self.settings.weak, "strong": self.settings.strong},
                    "events_seen": len(self._events), "held_signals": len(self._held),
                    "incidents": len(self._incidents), "record_errors": list(self.record_errors)}

    def _edges(self, event: Event) -> list[tuple[str, str, str]]:
        token = token_of(event)
        origin = host_entity(acting_host(event), self.config)
        target = host_entity(event.host, self.config)
        user = f"user:{event.user.lower()}" if event.user else None
        decoy_file = self.file_decoys.match(event) if token.startswith("file:") else None
        if decoy_file is not None:
            edges = [(origin, f"decoy:{decoy_file.id}", token)]
            if user:
                edges.insert(0, (user, origin, token))
            return [edge for edge in edges if edge[0] != edge[1]]
        if event.action == "proc_create":
            edges = [(origin, f"proc:{event.process or 'unknown'}", token)]
        elif event.action == "logon":
            edges = [(user, target, token)] if user else []
            if origin != target:
                edges.append((origin, target, token))
        elif event.action == "log_clear":
            edges = [(user, target, token)] if user else []
        else:
            if event.dst_ip:
                target = host_entity(resolve_ip(event.dst_ip), self.config)
            edges = [(origin, target, token)]
        return [edge for edge in edges if edge[0] != edge[1]]

    def graph(self, incident_id: str) -> IncidentGraph | None:
        with self.lock:
            case = self._cases.get(incident_id)
            if case is None:
                return None
            nodes: dict[str, GraphNode] = {}
            edges: dict[tuple[str, str, str], GraphEdge] = {}

            def node(entity: str) -> GraphNode:
                if entity not in nodes:
                    kind = entity.split(":", 1)[0]
                    nodes[entity] = GraphNode(id=entity, kind=kind if kind in NODE_KINDS else "host")
                return nodes[entity]

            for signal in sorted(case.signals.values(), key=lambda s: (s.ts, s.id)):
                for entity in signal.entity_ids:
                    node(entity)
                if signal.kind == "decoy_hit":
                    for entity in signal.entity_ids:
                        if entity.startswith("decoy:"):
                            node(entity).decoy_hit = True
                elif signal.id in case.anchors and signal.entity_ids:
                    node(signal.entity_ids[0]).anchor = True
                for event_id in signal.event_ids:
                    event = self._events.get(event_id)
                    if event is None:
                        continue
                    for source, target, token in self._edges(event):
                        node(source), node(target)
                        edges.setdefault((source, target, token), GraphEdge(source=source, target=target, token=token, ts=event.ts))
            return IncidentGraph(nodes=list(nodes.values()), edges=list(edges.values()))

    def process_state(self, incident_id: str | None) -> dict[str, Any]:
        """The tank state for the safety guard: the latest level and allowed settings, and the incident's breaching writes."""
        with self.lock:
            plcs = [name for name, info in self.config.hosts.items() if info.get("kind") == "plc"]
            allowed = [source.split(":", 1)[1] for rule in self.config.invariants for source in rule.allowed_sources]
            pending = []
            case = self._cases.get(incident_id or "")
            for signal in sorted(case.signals.values(), key=lambda s: (s.ts, s.id)) if case else []:
                event = self._events.get(signal.event_ids[0]) if signal.event_ids else None
                entry = REGISTERS.get(event.obj or "") if event is not None else None
                if signal.kind != "ot_invariant" or entry is None or isinstance(event.value, bool) \
                        or not isinstance(event.value, (int, float)):
                    continue
                writer = next((e.split(":", 1)[1] for e in signal.entity_ids[1:] if e.startswith("host:")), None)
                pending.append({"t": PENDING_AT + len(pending), "plc": signal.entity_ids[0].split(":", 1)[1],
                                "register": entry[1], "value": float(event.value), "source": writer})
            return {"t": 0, **self._process, "plc_online": {name: True for name in plcs},
                    "writers": {name: list(allowed) for name in plcs}, "pending_writes": pending}

    def incident_hosts(self, incident_id: str | None) -> list[str]:
        """The host names of one incident (or of all of them) for Trail Ahead."""
        with self.lock:
            incident = self._incidents.get(incident_id) if incident_id else None
            found = [incident] if incident is not None else list(self._incidents.values())
            return sorted({e.split(":", 1)[1] for item in found for e in item.entities
                           if e.startswith(("host:", "plc:")) and e != "host:ledger"})