"""One shared decoy service for the API: registry, trigger, recorded hits and placements."""
from __future__ import annotations

from typing import Callable

from deconflicted.schema import DecoysView

from .registry import DecoyRegistry
from .trail_ahead import trail_ahead
from .trigger import DecoyTrigger


class DecoyService:
    def __init__(self, directory: str | None = None):
        self.registry = DecoyRegistry(directory)
        self.trigger = DecoyTrigger(self.registry)
        # Atif's pipeline can replace this to return the hosts of an incident.
        self.incident_hosts: Callable[[str | None], list[str]] = self._hosts_from_hits

    def _hosts_from_hits(self, _incident_id: str | None) -> list[str]:
        return sorted({hit.source for hit in self.trigger.hits})

    def view(self, incident_id: str | None = None) -> DecoysView:
        return DecoysView(decoys=list(self.registry.decoys.values()), hits=list(self.trigger.hits),
                          placements=trail_ahead(self.registry, self.incident_hosts(incident_id)))


_service: DecoyService | None = None


def get_service() -> DecoyService:
    global _service
    if _service is None:
        _service = DecoyService()
    return _service


def reset_service(service: DecoyService | None = None) -> None:
    global _service
    _service = service
