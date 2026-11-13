"""File and cloud-object decoys: a file nobody has a reason to open. Any touch is a certain signal, whatever tool was used.

The collector (auditd, inotify, a cloud trail) says who touched which path. The path decides, not the command: vim,
nano, cat, less, cp and a script all look the same. config/decoy_files.yaml lists the decoys, and the few people or jobs
that may touch them. Ordinary files are never judged here.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from datetime import date, datetime, time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from deconflicted.adapters.hosts import config_dir
from deconflicted.schema import Event, Signal

from .config import CoreConfig, CoreConfigError
from .entities import OT_SOURCES, entities_of

FILE = "decoy_files.yaml"
TOUCH = ("read", "write")


def _norm(path: str) -> str:
    """One spelling of a path: forward slashes, no repeated slashes or dots, lower case."""
    text = re.sub(r"/{2,}", "/", path.strip().replace("\\", "/"))
    return posixpath.normpath(text).casefold() if text else ""


@dataclass(frozen=True)
class FileDecoy:
    id: str
    path: str | None = None      # an exact path
    pattern: str | None = None   # or a glob, such as "*backups/admin-keys.csv"
    host: str | None = None      # only on this host, when set


@dataclass(frozen=True)
class Allowed:
    user: str
    reason: str
    process: str | None = None
    hours: tuple[time, time] | None = None  # UTC, inclusive; may wrap past midnight
    until: date | None = None               # the last day the entry counts
    decoy: str | None = None                # only for this decoy, when set


def _load(base: Path) -> tuple[tuple[FileDecoy, ...], tuple[Allowed, ...]]:
    file = base / FILE
    if not file.is_file():
        return (), ()

    def bad(message: str) -> CoreConfigError:
        return CoreConfigError(f"{file}: {message}")

    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CoreConfigError(f"cannot read {file}: {exc}") from exc
    if not isinstance(data, dict):
        raise bad("expected a YAML mapping")
    decoys: list[FileDecoy] = []
    for item in data.get("files") or []:
        if not isinstance(item, dict) or not item.get("id") or bool(item.get("path")) == bool(item.get("match")):
            raise bad(f"each decoy file needs an id and exactly one of path or match: {item!r}")
        if any(other.id == str(item["id"]) for other in decoys):
            raise bad(f"the decoy id {item['id']!r} is used twice")
        decoys.append(FileDecoy(id=str(item["id"]), path=_norm(str(item["path"])) if item.get("path") else None,
                                pattern=_norm(str(item["match"])) if item.get("match") else None,
                                host=str(item["host"]).lower() if item.get("host") else None))
    allowed: list[Allowed] = []
    for item in data.get("allowlist") or []:
        if not isinstance(item, dict) or not item.get("user") or not item.get("reason"):
            raise bad(f"each allowlist entry needs a user and a reason: {item!r}")
        hours = item.get("hours")
        window = None
        if hours is not None:
            try:
                window = (time.fromisoformat(str(hours[0])), time.fromisoformat(str(hours[1])))
            except (TypeError, ValueError, IndexError, KeyError) as exc:
                raise bad(f'hours must be two quoted UTC times, like ["01:00", "03:00"]: {item!r}') from exc
        until = item.get("until")
        if until is not None:
            try:
                until = until.date() if isinstance(until, datetime) else until if isinstance(until, date) \
                    else date.fromisoformat(str(until))
            except ValueError as exc:
                raise bad(f"until must be a date like 2026-12-31: {item!r}") from exc
        allowed.append(Allowed(user=str(item["user"]).lower(), reason=str(item["reason"]),
                               process=str(item["process"]).lower() if item.get("process") else None, hours=window,
                               until=until, decoy=str(item["decoy"]) if item.get("decoy") else None))
    return tuple(decoys), tuple(allowed)


class FileDecoys:
    """match(event) finds the decoy an event touches. signal(event) makes a decoy_hit unless the touch is allowlisted."""

    def __init__(self, config: CoreConfig, directory: str | Path | None = None):
        self.config = config
        self.decoys, self.allowlist = _load(Path(directory) if directory else config_dir())
        self.allowlisted = 0

    def match(self, event: Event) -> FileDecoy | None:
        if event.action not in TOUCH or event.source in OT_SOURCES or not event.obj:
            return None
        path, host = _norm(event.obj), event.host.lower()
        for decoy in self.decoys:
            if decoy.host and decoy.host != host:
                continue
            if (decoy.path is not None and path == decoy.path) or (decoy.pattern is not None and fnmatchcase(path, decoy.pattern)):
                return decoy
        return None

    def allowed(self, decoy: FileDecoy, event: Event) -> bool:
        """True when a listed user (and process, hours, last day and decoy, where the entry names them) touched it."""
        user, process, clock = (event.user or "").lower(), (event.process or "").lower(), event.ts.time()
        for entry in self.allowlist:
            if entry.user != user or (entry.process and entry.process != process) or (entry.decoy and entry.decoy != decoy.id):
                continue
            if entry.until is not None and event.ts.date() > entry.until:
                continue
            if entry.hours is not None:
                start, end = entry.hours
                inside = start <= clock <= end if start <= end else clock >= start or clock <= end
                if not inside:
                    continue
            return True
        return False

    def signal(self, event: Event) -> Signal | None:
        decoy = self.match(event)
        if decoy is None:
            return None
        if self.allowed(decoy, event):
            self.allowlisted += 1
            return None
        how = event.process or "an unknown program"
        who = event.user or "someone"
        detail: dict[str, Any] = {"decoy": decoy.id, "path": event.obj, "process": event.process, "how": how,
                                  "allowlisted": False,
                                  "note": f"{who} used {how} on the decoy file {event.obj}"}
        return Signal(id=f"fdecoy-{event.id}", ts=event.ts, entity_ids=[*entities_of(event, self.config), f"decoy:{decoy.id}"],
                      kind="decoy_hit", score=1.0, event_ids=[event.id], techniques=["T1005"], detail=detail)