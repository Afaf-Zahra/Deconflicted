"""Ledger command line.   python -m deconflicted.ledger.cli <command>

  status                 show the nodes and the verify result
  anchor-config          write the first config_anchor (only if there is none)
  check                  report any protected file that does not match the ledger
  propose-change <file>  record a signed policy_change for a protected file you edited on purpose
"""
from __future__ import annotations

import sys

from .client import QuorumError
from .service import LedgerUnavailable, get_client, get_integrity


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print(__doc__)
        return 1
    try:
        client, integrity = get_client(), get_integrity()
        if args[0] == "status":
            report = client.verify()
            for node in client.node_status():
                print(f"{node.node} up={node.up} head={node.head[:12]} signed={node.signatures}")
            print(f"verify ok={report.ok} checked={report.checked}")
            return 0 if report.ok else 1
        if args[0] == "anchor-config":
            entry = integrity.ensure_anchor()
            print("config anchored" if entry else "a config anchor already exists")
            return 0
        if args[0] == "check":
            problems = integrity.problems()
            print("\n".join(problems) if problems else "protected files match the ledger")
            return 1 if problems else 0
        if args[0] == "propose-change" and len(args) == 2:
            entry = integrity.propose_change(args[1])
            print(f"policy_change recorded at seq {entry.seq} with {len(entry.signatures)} signatures")
            return 0
    except (LedgerUnavailable, QuorumError, ValueError) as exc:
        print(f"FAILED {exc}")
        return 1
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
