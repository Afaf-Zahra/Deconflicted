"""Hash recipes from docs/conventions.md. Use these everywhere; never rebuild them by hand."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

GENESIS = "0" * 64


def payload_hash(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def entry_hash(seq: int, ts: datetime | str, kind: str, payload_hash_: str, prev_hash: str) -> str:
    """ts is hashed in its isoformat() form. A string is parsed and re-formatted so both agree."""
    stamp = datetime.fromisoformat(ts).isoformat() if isinstance(ts, str) else ts.isoformat()
    return hashlib.sha256(f"{seq}|{stamp}|{kind}|{payload_hash_}|{prev_hash}".encode("utf-8")).hexdigest()
