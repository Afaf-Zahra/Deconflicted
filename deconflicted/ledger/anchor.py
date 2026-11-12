"""Merkle anchoring of ingested event ids, so deleted or changed logs show up."""
from __future__ import annotations

import hashlib


def merkle_root(event_ids: list[str]) -> str:
    """SHA-256 Merkle root. Neighbours are paired; the last one is repeated when the count is odd."""
    if not event_ids:
        raise ValueError("cannot anchor an empty list of events")
    level = [hashlib.sha256(i.encode("utf-8")).digest() for i in event_ids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def verify_ingest(event_ids: list[str], source) -> list[dict]:
    """Compare the anchored ranges with the events you actually have. Returns the problems found.

    `source` is a LedgerClient, or a list of ingest_anchor payloads. Events after the last anchor are not covered.
    """
    anchors = source.ingest_anchors() if hasattr(source, "ingest_anchors") else source
    problems = []
    for anchor in anchors:
        start, end = anchor["from_index"], anchor["to_index"]
        chunk = event_ids[start:end + 1]
        if len(chunk) != anchor["count"]:
            problems.append({"from_index": start, "to_index": end, "reason": "events_missing"})
        elif merkle_root(chunk) != anchor["root"]:
            problems.append({"from_index": start, "to_index": end, "reason": "root_mismatch"})
    return problems
