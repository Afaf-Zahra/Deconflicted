"""Look up hosts by IP using config/hosts.yaml (loaded once and cached)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def config_dir() -> Path:
    return Path(os.environ.get("DECONFLICTED_CONFIG_DIR", DEFAULT_CONFIG_DIR))


@lru_cache(maxsize=8)
def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    by_ip = {}
    for section in ("hosts", "decoys", "external"):
        for name, info in (data.get(section) or {}).items():
            by_ip[info["ip"]] = name
    return {"raw": data, "by_ip": by_ip}


def load_hosts(path: str | Path | None = None) -> dict:
    """The parsed hosts.yaml (sections: hosts, decoys, external)."""
    return _load(str(path or config_dir() / "hosts.yaml"))["raw"]


def resolve_ip(ip: str, path: str | Path | None = None) -> str:
    """The host name for an IP, or the IP itself when it is not in hosts.yaml."""
    by_ip = _load(str(path or config_dir() / "hosts.yaml"))["by_ip"]
    return by_ip.get(ip, ip)
