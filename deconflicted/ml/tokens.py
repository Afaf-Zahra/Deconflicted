"""Behaviour tokens from the table in docs/conventions.md (format category:detail, lower case).

The scorer needs tokens to train on benign days. The detection core derives the same tokens
for live events; if the table changes, change it in both places.
"""
from __future__ import annotations

from deconflicted.deception.registry import DecoyRegistry
from deconflicted.schema import Event

OT_SOURCES = ("modbus", "opcua")
_registry: DecoyRegistry | None = None


def _decoy_addresses() -> set[str]:
    global _registry
    if _registry is None:
        _registry = DecoyRegistry()
    return set(_registry._by_address)


def _process_token(event: Event) -> str:
    name = (event.process or "unknown").lower()
    cmd = (event.cmdline or "").lower()
    if name == "powershell.exe":
        if "-enc" in cmd or "-encodedcommand" in cmd:
            return "proc:powershell_enc"
        return "proc:powershell_script" if "-file" in cmd else "proc:powershell"
    if name == "nltest.exe":
        return "proc:nltest"
    if name in ("net.exe", "net1.exe"):
        words = cmd.split()
        for word, token in (("view", "proc:net_view"), ("user", "proc:net_user")):
            if word in words:
                return token
    if name == "certutil.exe" and "-urlcache" in cmd:
        return "proc:certutil_download"
    if name == "backup.exe":
        return "proc:backup"
    return f"proc:{name.removesuffix('.exe')}"


def event_token(event: Event) -> str:
    """The behaviour token for one event."""
    if event.dst_ip in _decoy_addresses():
        return "net:decoy_touch"
    action = event.action
    if action == "proc_create":
        return _process_token(event)
    if action == "logon":
        return "auth:logon_failed" if event.obj == "failed" else "auth:logon"
    if action == "log_clear":
        return "log:cleared"
    if action in ("net_conn", "flow"):
        if event.dst_port == 445:
            return "net:smb_admin" if (event.obj or "").endswith("$") else "net:smb"
        return "net:flow"
    if action == "http_request":
        return "net:http"
    if action in ("read", "write") and event.source not in OT_SOURCES:
        return f"file:{action}"
    if action == "read":
        return "ot:read"
    obj = event.obj or ""
    if obj in ("reg:40001", "ns=2;s=Tank1.Setpoint"):
        return "ot:write_setpoint"
    if obj in ("reg:40010", "ns=2;s=Tank1.PumpCmd"):
        return "ot:write_pump"
    return "ot:write_other"


def entity_of(event: Event) -> str:
    """Sequences are kept per user when the event has one, otherwise per host."""
    return f"user:{event.user.lower()}" if event.user else f"host:{event.host}"