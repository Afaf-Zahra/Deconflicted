"""OT rules that must always hold (config/invariants.yaml). A break is certain: an ot_invariant signal, whatever the baseline says."""
from __future__ import annotations

from typing import Any

from deconflicted.adapters.hosts import resolve_ip
from deconflicted.schema import Event, Signal

from .config import CoreConfig, Invariant
from .entities import OT_SOURCES, entities_of, host_entity

# The same register is also reachable over OPC-UA under another name (docs/conventions.md).
ALIASES = {"40001": ("ns=2;s=Tank1.Setpoint",), "40010": ("ns=2;s=Tank1.PumpCmd",)}


def objects_for(register: str) -> set[str]:
    return {f"reg:{register}", *ALIASES.get(register, ())}


def _plain(value: Any) -> Any:
    return int(value) if isinstance(value, float) and value.is_integer() else value


def _limit(rule: Invariant) -> str:
    low, high = rule.minimum, rule.maximum
    if low is not None and high is not None:
        return f"{low:g} to {high:g}"
    return f"at least {low:g}" if low is not None else f"at most {high:g}"


class Invariants:
    def __init__(self, config: CoreConfig) -> None:
        self.config = config
        self._rules = [(rule, objects_for(rule.register)) for rule in config.invariants]

    def _breach(self, rule: Invariant, event: Event, source: str | None) -> dict | None:
        if rule.allowed_sources and source is not None and source not in rule.allowed_sources:
            return {"source": source, "allowed": list(rule.allowed_sources)}
        if rule.minimum is None and rule.maximum is None:
            return None
        value = event.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None  # without a number the range cannot be judged
        if (rule.minimum is not None and value < rule.minimum) or (rule.maximum is not None and value > rule.maximum):
            return {"limit": _limit(rule), "value": _plain(value)}
        return None

    def check(self, event: Event) -> Signal | None:
        """An ot_invariant signal when the write breaks a rule, otherwise None."""
        if event.source not in OT_SOURCES or event.action != "write":
            return None
        source = host_entity(resolve_ip(event.src_ip), self.config) if event.src_ip else None
        broken: list[tuple[Invariant, dict]] = []
        for rule, objects in self._rules:
            if event.obj in objects:
                detail = self._breach(rule, event, source)
                if detail is not None:
                    broken.append((rule, detail))
        if not broken:
            return None
        detail = {"rule": broken[0][0].id, **broken[0][1]}
        if len(broken) > 1:
            detail["also"] = [rule.id for rule, _ in broken[1:]]
        techniques = list(dict.fromkeys(t for rule, _ in broken for t in rule.techniques))
        return Signal(id=f"ot-{event.id}", ts=event.ts, entity_ids=entities_of(event, self.config), kind="ot_invariant",
                      score=1.0, event_ids=[event.id], techniques=techniques, detail=detail)