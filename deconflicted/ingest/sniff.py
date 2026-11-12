"""Tells which log format a line or a file is. The six built-in formats are told apart by their shape."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPLAY = "replay"  # {"source": ..., "raw": ...} per line, the file format of sim/build.py
_SYSLOG = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S+\s+[\w.\-/]+(\[\d+\])?:")
_SQUID = re.compile(r"^\d{9,11}(\.\d+)?\s+\d+\s+\d{1,3}(\.\d{1,3}){3}\s+\S+/\d{3}\s")
_DATE = re.compile(r"^\d{4}-\d\d-\d\d")


def sniff_line(line: str) -> str | None:
    """The format of one line: a source name, REPLAY, or None when it is none of the known formats."""
    text = line.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        if set(data) == {"source", "raw"}:
            return REPLAY
        if "EventID" in data:
            return "windows"
        if "func" in data and "server" in data:
            return "modbus"
        if "service" in data and "node" in data:
            return "opcua"
        return None
    if _SQUID.match(text):
        return "proxy"
    if _SYSLOG.match(text):
        return "linux"
    parts = text.split(",")
    if len(parts) == 7 and _DATE.match(parts[0].strip()):
        return "flow"
    return None


def read_sample(path: str | Path, size: int = 50) -> list[str]:
    """The first non-empty lines of a file. A byte order mark is ignored and bad bytes never raise."""
    lines: list[str] = []
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if line.strip():
                lines.append(line)
                if len(lines) >= size:
                    break
    return lines


def sniff_lines(lines: list[str]) -> str | None:
    """The format at least half of the lines have. A header line or a few bad lines do not change the answer."""
    counts = Counter(found for found in map(sniff_line, lines) if found)
    if not counts:
        return None
    name, hits = counts.most_common(1)[0]
    return name if hits * 2 >= len(lines) else None


def sniff_file(path: str | Path, size: int = 50) -> str | None:
    return sniff_lines(read_sample(path, size))