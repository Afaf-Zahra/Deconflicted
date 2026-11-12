"""Load and validate the guard's configuration. Anything invalid raises ConfigError."""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import yaml

from deconflicted.adapters.hosts import config_dir
from deconflicted.sim.process import REG_LEVEL, REG_SETPOINT

SERIES = {REG_LEVEL: "level", REG_SETPOINT: "setpoint"}
EFFECTS = {"none", "plc_offline", "block_writes", "set_setpoint"}
TARGETS = {"host", "plc", "user"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    register: int
    min: float | None
    max: float | None

    @property
    def series(self) -> str:
        return SERIES[self.register]


@dataclass(frozen=True)
class ActionSpec:
    kind: str
    target: str
    params: tuple[str, ...]
    effect: str
    downgrade_to: str | None


@dataclass(frozen=True)
class GuardConfig:
    horizon: int
    rules: tuple[Rule, ...]
    rules_only: tuple[dict, ...]
    actions: dict[str, ActionSpec]
    hosts: dict[str, str]        # name -> kind
    users: frozenset[str]


def _read(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} must be a mapping")
    return data


def _bound(entry: dict, key: str, rule_id: str) -> float | None:
    if key not in entry:
        return None
    value = entry[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ConfigError(f"rule {rule_id}: {key} must be a finite number")
    return float(value)


def load_config(directory: str | Path | None = None) -> GuardConfig:
    base = Path(directory) if directory else config_dir()
    rules_file = _read(base / "safety_rules.yaml")
    horizon = rules_file.get("horizon_seconds")
    if isinstance(horizon, bool) or not isinstance(horizon, int) or horizon <= 0:
        raise ConfigError("horizon_seconds must be a positive integer")
    rules = []
    for entry in rules_file.get("rules") or []:
        rule_id, register = entry.get("id"), entry.get("register")
        if not rule_id or register not in SERIES:
            raise ConfigError(f"rule {rule_id!r}: unknown register {register!r}")
        low, high = _bound(entry, "min", rule_id), _bound(entry, "max", rule_id)
        if low is None and high is None:
            raise ConfigError(f"rule {rule_id}: needs min or max")
        rules.append(Rule(rule_id, register, low, high))
    if not rules:
        raise ConfigError("safety_rules.yaml has no rules")
    rules_only = []
    for entry in rules_file.get("rules_only") or []:
        if entry.get("decision") != "block" or not entry.get("action") or not entry.get("id"):
            raise ConfigError(f"bad rules_only entry {entry!r}")
        rules_only.append(dict(entry))
    actions = {}
    for kind, spec in (_read(base / "actions.yaml").get("actions") or {}).items():
        effect, target = spec.get("process_effect"), spec.get("target")
        if effect not in EFFECTS or target not in TARGETS:
            raise ConfigError(f"action {kind}: bad target or process_effect")
        actions[kind] = ActionSpec(kind, target, tuple(spec.get("params") or ()), effect, spec.get("downgrade_to"))
    if not actions:
        raise ConfigError("actions.yaml has no actions")
    hosts_file = _read(base / "hosts.yaml")
    hosts = {name: str(info.get("kind", "")) for name, info in (hosts_file.get("hosts") or {}).items()}
    try:
        roles = _read(base / "roles.yaml").get("roles") or {}
    except ConfigError:
        roles = {}
    users = frozenset(u for role in roles.values() for u in role.get("users", []))
    return GuardConfig(horizon, tuple(rules), tuple(rules_only), actions, hosts, users)
