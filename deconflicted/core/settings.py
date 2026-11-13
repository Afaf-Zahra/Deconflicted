"""Detection settings from config/detection.yaml. A missing file means the defaults below.

make calibrate writes config/calibration.yaml next to it. Its "strong" value replaces thresholds.strong.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from deconflicted.adapters.hosts import config_dir


class SettingsError(ValueError):
    """detection.yaml is unreadable or has a value that makes no sense."""


@dataclass(frozen=True)
class Settings:
    budget: int = 5
    window_hours: int = 24
    weak: float = 0.99
    strong: float = 0.9999
    non_anchor_quota: int = 3
    hops: int = 2
    hours_before: float = 24.0
    hours_after: float = 1.0
    join_hours: float = 24.0
    held_per_entity: int = 200
    held_hours: float = 24.0
    ignore_host_kinds: tuple[str, ...] = ("domain-controller", "file-server", "proxy")
    ordinary_tokens: tuple[str, ...] = ("auth:logon",)
    scorer_enabled: bool = False
    scorer_weak: float = 0.99


def _calibrated_strong(path: Path) -> float | None:
    """The strong threshold that make calibrate wrote to calibration.yaml, if there is one."""
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return float(data["strong"])
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from exc


def load_settings(directory: str | Path | None = None) -> Settings:
    path = (Path(directory) if directory else config_dir()) / "detection.yaml"
    if not path.is_file():
        return Settings()
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SettingsError(f"{path}: expected a YAML mapping")
    calibrated = _calibrated_strong(path.with_name("calibration.yaml"))
    base = Settings()
    thresholds, link, chain = data.get("thresholds") or {}, data.get("correlation") or {}, data.get("chain") or {}
    scorer = data.get("scorer") or {}
    try:
        settings = Settings(
            budget=int(data.get("budget", base.budget)),
            window_hours=int(data.get("window_hours", base.window_hours)),
            weak=float(thresholds.get("weak", base.weak)),
            strong=float(thresholds.get("strong", base.strong) if calibrated is None else calibrated),
            non_anchor_quota=int(data.get("non_anchor_quota", base.non_anchor_quota)),
            hops=int(link.get("hops", base.hops)),
            hours_before=float(link.get("hours_before", base.hours_before)),
            hours_after=float(link.get("hours_after", base.hours_after)),
            join_hours=float(link.get("join_hours", base.join_hours)),
            held_per_entity=int(link.get("held_per_entity", base.held_per_entity)),
            held_hours=float(link.get("held_hours", base.held_hours)),
            ignore_host_kinds=tuple(str(kind) for kind in link.get("ignore_host_kinds", base.ignore_host_kinds)),
            ordinary_tokens=tuple(str(token) for token in chain.get("ordinary_tokens", base.ordinary_tokens)),
            scorer_enabled=bool(scorer.get("enabled", base.scorer_enabled)),
            scorer_weak=float(scorer.get("weak", base.scorer_weak)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise SettingsError(f"{path}: bad value ({exc})") from exc
    if not 0.0 <= settings.weak <= settings.strong <= 1.0:
        raise SettingsError(f"{path}: thresholds must satisfy 0 <= weak <= strong <= 1")
    if not 0.0 <= settings.scorer_weak <= 1.0:
        raise SettingsError(f"{path}: scorer.weak must be between 0 and 1")
    if min(settings.budget, settings.window_hours, settings.hops, settings.held_per_entity) < 1 or settings.non_anchor_quota < 0:
        raise SettingsError(f"{path}: budget, window_hours, hops and held_per_entity must be at least 1")
    return settings