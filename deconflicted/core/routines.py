"""Known admin routines (config/routines.yaml). A step that fits a routine is normal work.

A token that belongs to a routine but is used by another role, on another host, outside the routine's window or out of
order is "broken": a known tool in the wrong place. A token that is in no routine is "none".
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time

from .config import CoreConfig, Routine


@dataclass(frozen=True)
class RoutineCheck:
    status: str  # "matched", "broken" or "none"
    routine_id: str | None = None
    reason: str = ""


def _inside(moment: time, window: tuple[time, time]) -> bool:
    start, end = window
    return start <= moment <= end if start <= end else moment >= start or moment <= end


class RoutineRegistry:
    def __init__(self, config: CoreConfig) -> None:
        self.config = config
        self._by_token: dict[str, list[Routine]] = {}
        for routine in config.routines:
            for token in dict.fromkeys(routine.steps):
                self._by_token.setdefault(token, []).append(routine)
        self._role_hosts: dict[str, set[str]] = {}
        for host, role in config.host_roles.items():
            self._role_hosts.setdefault(role, set()).add(host)
        self._progress: dict[tuple[str, str], tuple[int, datetime]] = {}

    def reset(self) -> None:
        self._progress = {}

    def check(self, token: str, actor: str, role: str, host: str, ts: datetime) -> RoutineCheck:
        """Does this token, done by this actor (of this role) on this host at this time, fit a routine?"""
        candidates = self._by_token.get(token)
        if not candidates:
            return RoutineCheck("none")
        reasons = []
        for routine in candidates:
            problem = self._problem(routine, token, actor, role, host, ts)
            if problem is None:
                return RoutineCheck("matched", routine.id)
            reasons.append(f"{routine.id}: {problem}")
        return RoutineCheck("broken", candidates[0].id, "; ".join(reasons))

    def _problem(self, routine: Routine, token: str, actor: str, role: str, host: str, ts: datetime) -> str | None:
        if routine.role != role:
            return f"it belongs to the {routine.role} role, not {role}"
        hosts = self._role_hosts.get(role)
        if hosts and host not in hosts:
            return f"it runs on {', '.join(sorted(hosts))}, not {host}"
        if routine.window and not _inside(ts.time(), routine.window):
            return f"it runs between {routine.window[0]:%H:%M} and {routine.window[1]:%H:%M} UTC"
        return self._order_problem(routine, token, actor, ts)

    def _order_problem(self, routine: Routine, token: str, actor: str, ts: datetime) -> str | None:
        """Routines with several steps must run in order, each within max_gap_seconds of the one before."""
        if len(routine.steps) == 1:
            return None
        key = (actor, routine.id)
        index, last = self._progress.get(key, (0, ts))
        started = index > 0
        if started and routine.max_gap_seconds is not None and (ts - last).total_seconds() > routine.max_gap_seconds:
            index, started = 0, False
        if started and routine.steps[index] == token:
            index += 1
        elif routine.steps[0] == token:
            index = 1
        else:
            self._progress.pop(key, None)
            return f"{token} is out of order"
        self._progress[key] = (0, ts) if index >= len(routine.steps) else (index, ts)
        return None