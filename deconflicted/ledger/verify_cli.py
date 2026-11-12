"""Verify an audit export offline.   python -m deconflicted.ledger.verify_cli export.json

Prints "OK checked=<n>" and exits 0 when the export is intact. Otherwise prints the first broken
sequence number and the reason and exits 1. An unreadable file also exits 1 (fail closed).
"""
from __future__ import annotations

import json
import sys

from .verify import verify_export


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m deconflicted.ledger.verify_cli <export.json>")
        return 1
    try:
        with open(args[0], encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAILED cannot read {args[0]}: {exc}")
        return 1
    report = verify_export(data)
    if report.ok:
        print(f"OK checked={report.checked}")
        return 0
    first = min(report.errors, key=lambda e: e.seq)
    print(f"FAILED first broken seq={first.seq} reason={first.reason} errors={len(report.errors)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
