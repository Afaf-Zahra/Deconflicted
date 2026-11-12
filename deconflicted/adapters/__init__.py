"""The six log adapters. Each module has parse_line(line, *, file, lineno) and parse_file(path)."""
from . import flow, linux, modbus, opcua, proxy, windows
from .common import AdapterError
from .hosts import resolve_ip

ADAPTERS = {
    "windows": windows,
    "proxy": proxy,
    "flow": flow,
    "linux": linux,
    "modbus": modbus,
    "opcua": opcua,
}


def get(source: str):
    """The adapter module for a source name."""
    try:
        return ADAPTERS[source]
    except KeyError:
        raise AdapterError(f"no adapter for source {source!r}") from None


__all__ = ["ADAPTERS", "AdapterError", "get", "resolve_ip"]
