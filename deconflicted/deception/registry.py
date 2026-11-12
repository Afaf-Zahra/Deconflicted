"""Decoys: the registry of virtual decoy hosts and the rules around them."""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from deconflicted.adapters.hosts import config_dir, load_hosts
from deconflicted.schema import Decoy

RESERVED = (("10.0.2.90", "10.0.2.99"), ("10.0.4.90", "10.0.4.99"))


class DecoyConfigError(ValueError):
    """The decoy configuration is not safe to start with."""


def in_reserved(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ipaddress.ip_address(a) <= ip <= ipaddress.ip_address(b) for a, b in RESERVED)


def decoy_type_for(kind: str) -> str:
    """The default: a PLC decoy speaks Modbus (fake_plc), every other decoy is an SMB server (fake_dc).

    A type in decoys.yaml can claim host kinds with `kinds: [...]`, which takes priority over this default.
    """
    return "fake_plc" if kind == "plc" else "fake_dc"


class DecoyRegistry:
    """Implements the DecoyRegistry protocol and holds the decoy settings."""

    def __init__(self, directory: str | Path | None = None):
        base = Path(directory) if directory else config_dir()
        hosts = load_hosts(base / "hosts.yaml")
        try:
            with open(base / "decoys.yaml", encoding="utf-8") as handle:
                settings = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise DecoyConfigError(f"cannot read decoys.yaml: {exc}") from exc
        self.types: dict = settings.get("types") or {}
        self.allowlist: list[dict] = settings.get("allowlist") or []
        trail = settings.get("trail_ahead") or {}
        self.next_hops: dict = trail.get("next_hops") or {}
        self.placement_rules: list[str] = [r["id"] for r in trail.get("placement_rules") or []]
        self.hosts: dict = hosts.get("hosts") or {}
        self.decoys: dict[str, Decoy] = {}
        by_kind = {k: name for name, spec in self.types.items() for k in (spec.get("kinds") or [])}
        real = {info["ip"] for info in self.hosts.values()}
        seen: set[str] = set()
        for name, info in (hosts.get("decoys") or {}).items():
            address, kind = info["ip"], str(info.get("kind", ""))
            if not in_reserved(address):
                raise DecoyConfigError(f"decoy {name} at {address} is outside the reserved ranges")
            if address in real or address in seen:
                raise DecoyConfigError(f"decoy {name} at {address} reuses an address")
            dtype = by_kind.get(kind) or decoy_type_for(kind)
            if dtype not in self.types:
                raise DecoyConfigError(f"decoy {name} needs the type {dtype!r}, which decoys.yaml does not define")
            seen.add(address)
            self.decoys[name] = Decoy(id=name, type=dtype, address=address)
        self._by_address = {d.address: d for d in self.decoys.values()}

    def by_address(self, ip: str | None) -> Decoy | None:
        return self._by_address.get(ip or "")

    def by_name(self, name: str | None) -> Decoy | None:
        return self.decoys.get(name or "")

    def is_decoy(self, entity_id: str) -> bool:
        """Accepts decoy:<id>, host:<id>, plc:<id> and host:<ip>."""
        _, _, rest = entity_id.partition(":")
        rest = rest or entity_id
        return rest in self.decoys or rest in self._by_address

    def used_addresses(self) -> set[str]:
        return set(self._by_address) | {info["ip"] for info in self.hosts.values()}
