"""Trail Ahead: suggest where to place decoys on the attacker's likely next hops."""
from __future__ import annotations

from deconflicted.schema import Placement

from .registry import DecoyRegistry, in_reserved

ZONE_NAMES = {2: "server", 4: "OT"}
ZONE_TYPES = {2: "fake_dc", 4: "fake_plc"}
RESERVED_TAIL = range(90, 100)


def zone_of(ip: str) -> int:
    return int(ip.split(".")[2])


def reachable(zone_a: int, zone_b: int) -> bool:
    """Zones are the third octet. Adjacent zones can reach each other. Zone 9 is outside."""
    return 9 not in (zone_a, zone_b) and abs(zone_a - zone_b) <= 1


def _bare(name: str) -> str:
    return name.partition(":")[2] or name


def _rule_results(registry: DecoyRegistry, dtype: str, address: str, taken: set[str]) -> dict[str, bool]:
    return {
        "reserved_range_only": in_reserved(address) and address not in taken,
        # Decoys are virtual and passive: they never send traffic. A fake PLC never accepts writes either.
        "no_traffic_to_real_plc": dtype in registry.types and registry.types[dtype].get("service") in ("smb", "modbus"),
    }


def safety_ok(registry: DecoyRegistry, dtype: str, address: str, taken: set[str]) -> bool:
    """True only when every configured placement rule holds. An unknown rule fails closed."""
    results = _rule_results(registry, dtype, address, taken)
    rules = registry.placement_rules
    return bool(rules) and all(results.get(rule, False) for rule in rules)


def trail_ahead(registry: DecoyRegistry, hosts: list[str]) -> list[Placement]:
    """Placements for the next hops of the given hosts (names or host:<name> entity ids)."""
    taken = set(registry.used_addresses())
    placements: list[Placement] = []
    done: set[tuple[str, str]] = set()
    for entity in hosts:
        source = _bare(entity)
        info = registry.hosts.get(source)
        if info is None:
            continue
        for hop_entity in registry.next_hops.get(f"host:{source}", []):
            hop = _bare(hop_entity)
            hop_info = registry.hosts.get(hop)
            if hop_info is None or (source, hop) in done:
                continue
            done.add((source, hop))
            zone = zone_of(hop_info["ip"])
            dtype = ZONE_TYPES.get(zone)
            if dtype is None or not reachable(zone_of(info["ip"]), zone):
                continue  # no decoy type for this zone, or the hop is not reachable
            address = next((f"10.0.{zone}.{n}" for n in RESERVED_TAIL if f"10.0.{zone}.{n}" not in taken), None)
            if address is None:
                continue
            ok = safety_ok(registry, dtype, address, taken)
            taken.add(address)
            placements.append(Placement(
                host=hop, decoy_type=dtype, address=address, safety_ok=ok,
                reason=f"likely next hop from {source}, reachable, in the {ZONE_NAMES[zone]} zone"))
    return placements
