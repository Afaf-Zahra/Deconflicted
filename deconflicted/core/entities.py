"""Who did what: the entities of an event, the role of its actor and its behaviour token.

The token table is Ayaz's (deconflicted/ml/tokens.py), so the core and the scorer always agree.
"""
from __future__ import annotations

from deconflicted.adapters.hosts import resolve_ip
from deconflicted.ml.tokens import event_token
from deconflicted.schema import Event

from .config import ROLE_NONE, CoreConfig

OT_SOURCES = ("modbus", "opcua")
token_of = event_token


def acting_host(event: Event) -> str:
    """The host the activity came from: the source address when the event has one, otherwise the host that logged it."""
    if event.src_ip:
        return resolve_ip(event.src_ip)
    return event.host


def host_entity(name: str, config: CoreConfig) -> str:
    """decoy:<name>, plc:<name> or host:<name>. A host that is not in hosts.yaml keeps its IP: host:10.0.9.77."""
    if name in config.decoy_hosts:
        return f"decoy:{name}"
    if config.hosts.get(name, {}).get("kind") == "plc":
        return f"plc:{name}"
    return f"host:{name}"


def actor_of(event: Event, config: CoreConfig) -> str:
    """The entity whose behaviour is followed: the user when the event has one, otherwise the acting host."""
    if event.user:
        return f"user:{event.user.lower()}"
    return host_entity(acting_host(event), config)


def role_of(entity_id: str, config: CoreConfig) -> str:
    """The role from roles.yaml, or "other" for anyone it does not list."""
    kind, _, name = entity_id.partition(":")
    table = config.user_roles if kind == "user" else config.host_roles
    return table.get(name, ROLE_NONE)


def entities_of(event: Event, config: CoreConfig) -> list[str]:
    """Every entity the event concerns: the target PLC (OT events), the acting host, then the user."""
    found: list[str] = []
    if event.source in OT_SOURCES:
        found.append(host_entity(event.host, config))
    found.append(host_entity(acting_host(event), config))
    if event.user:
        found.append(f"user:{event.user.lower()}")
    return list(dict.fromkeys(found))