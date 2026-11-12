"""The decoy trigger: any contact with a decoy is a certain signal, unless the source is allowlisted."""
from __future__ import annotations

from collections import deque
from typing import Optional

from deconflicted.adapters.hosts import resolve_ip
from deconflicted.schema import DecoyHit, Event, Signal

from .registry import DecoyRegistry


MAX_HITS = 1000  # the decoys view shows the most recent hits; older ones stay in the ledger and the logs


class DecoyTrigger:
    """A callable with the DecoyTrigger shape: trigger(event) -> Signal or None."""

    def __init__(self, registry: DecoyRegistry, max_hits: int = MAX_HITS):
        self.registry = registry
        self.hits: deque[DecoyHit] = deque(maxlen=max_hits)
        self.allowlisted = 0

    def _source(self, event: Event) -> str:
        return resolve_ip(event.src_ip) if event.src_ip else event.host

    def _allowed(self, source: str, port: int | None) -> bool:
        for entry in self.registry.allowlist:
            ports = entry.get("ports")
            if entry.get("host") == source and (not ports or port in ports):
                return True
        return False

    def __call__(self, event: Event) -> Optional[Signal]:
        decoy = self.registry.by_address(event.dst_ip) or self.registry.by_name(event.host)
        if decoy is None:
            return None
        source = self._source(event)
        if self._allowed(source, event.dst_port):
            self.allowlisted += 1
            return None
        self.hits.append(DecoyHit(ts=event.ts, decoy=decoy.id, source=source))
        kind = self.registry.hosts.get(source, {}).get("kind")
        source_entity = f"plc:{source}" if kind == "plc" else f"host:{source}"
        return Signal(id=f"decoy-{event.id}", ts=event.ts, entity_ids=[source_entity, f"decoy:{decoy.id}"],
                      kind="decoy_hit", score=1.0, event_ids=[event.id], techniques=["T1018"],
                      detail={"decoy": decoy.id, "allowlisted": False})
