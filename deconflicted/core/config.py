"""Loads the detection settings: roles.yaml, routines.yaml, invariants.yaml, attack_map.yaml and hosts.yaml."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import time
from pathlib import Path
from typing import Any

import yaml

from deconflicted.adapters.hosts import config_dir, load_hosts

ROLE_NONE = "other"  # entities that roles.yaml does not list


class CoreConfigError(ValueError):
    """A detection config file is missing or wrong. The message names the file."""


@dataclass(frozen=True)
class ModelSettings:
    window_hours: float = 24.0
    alpha: float = 1.0
    backoff_n: float = 20.0


@dataclass(frozen=True)
class Routine:
    id: str
    role: str
    steps: tuple[str, ...]
    max_gap_seconds: float | None = None
    window: tuple[time, time] | None = None  # UTC, inclusive; may wrap past midnight


@dataclass(frozen=True)
class Invariant:
    id: str
    register: str
    minimum: float | None = None
    maximum: float | None = None
    allowed_sources: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class CoreConfig:
    model: ModelSettings
    user_roles: dict[str, str]
    host_roles: dict[str, str]
    routines: tuple[Routine, ...]
    invariants: tuple[Invariant, ...]
    attack_map: dict[str, tuple[str, str]]  # behaviour token -> (tactic, technique)
    hosts: dict[str, dict]  # hosts.yaml "hosts": name -> {ip, kind, zone}
    decoy_hosts: frozenset[str]


def _read(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise CoreConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CoreConfigError(f"{path}: expected a YAML mapping")
    return data


def _number(value: Any) -> float | None:
    return None if value is None else float(value)


def _clock(text: Any) -> time:
    return time.fromisoformat(str(text))


def load_config(directory: str | Path | None = None) -> CoreConfig:
    base = Path(directory) if directory else config_dir()

    roles = _read(base / "roles.yaml")
    settings = roles.get("model") or {}
    try:
        model = ModelSettings(float(settings.get("window_hours", 24)), float(settings.get("laplace_alpha", 1)),
                              float(settings.get("peer_backoff_n", 20)))
    except (TypeError, ValueError) as exc:
        raise CoreConfigError(f"{base / 'roles.yaml'}: bad model settings ({exc})") from exc
    if model.window_hours <= 0 or model.alpha <= 0 or model.backoff_n < 0:
        raise CoreConfigError(f"{base / 'roles.yaml'}: window_hours and laplace_alpha must be above 0 and peer_backoff_n at least 0")
    user_roles: dict[str, str] = {}
    host_roles: dict[str, str] = {}
    for role, spec in (roles.get("roles") or {}).items():
        for user in (spec or {}).get("users") or []:
            user_roles[str(user).lower()] = str(role)
        for host in (spec or {}).get("hosts") or []:
            host_roles[str(host).lower()] = str(role)

    routines: list[Routine] = []
    for item in _read(base / "routines.yaml").get("routines") or []:
        try:
            window = item.get("window_utc")
            steps = tuple(str(step) for step in item["steps"])
            if not steps:
                raise ValueError("no steps")
            routines.append(Routine(
                id=str(item["id"]), role=str(item["role"]), steps=steps,
                max_gap_seconds=_number(item.get("max_gap_seconds")),
                window=(_clock(window[0]), _clock(window[1])) if window else None))
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
            raise CoreConfigError(f"{base / 'routines.yaml'}: bad routine {item!r} ({exc})") from exc

    invariants: list[Invariant] = []
    for item in _read(base / "invariants.yaml").get("invariants") or []:
        try:
            invariants.append(Invariant(
                id=str(item["id"]), register=str(item["register"]),
                minimum=_number(item.get("min")), maximum=_number(item.get("max")),
                allowed_sources=tuple(str(source) for source in item.get("allowed_sources") or ()),
                techniques=tuple(str(technique) for technique in item.get("techniques") or ()),
                note=str(item.get("note", ""))))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise CoreConfigError(f"{base / 'invariants.yaml'}: bad invariant {item!r} ({exc})") from exc

    attack_map: dict[str, tuple[str, str]] = {}
    for token, spec in (_read(base / "attack_map.yaml").get("map") or {}).items():
        try:
            attack_map[str(token)] = (str(spec["tactic"]), str(spec["technique"]))
        except (KeyError, TypeError) as exc:
            raise CoreConfigError(f"{base / 'attack_map.yaml'}: bad entry for {token!r} ({exc})") from exc

    try:
        raw_hosts = load_hosts(base / "hosts.yaml")
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise CoreConfigError(f"cannot read {base / 'hosts.yaml'}: {exc}") from exc
    hosts = {str(name): dict(info) for name, info in (raw_hosts.get("hosts") or {}).items()}
    decoys = frozenset(str(name) for name in (raw_hosts.get("decoys") or {}))

    return CoreConfig(model=model, user_roles=user_roles, host_roles=host_roles, routines=tuple(routines),
                      invariants=tuple(invariants), attack_map=attack_map, hosts=hosts, decoy_hosts=decoys)