"""GET /audit/export, and POST /debug/tamper when DECONFLICTED_DEBUG=1."""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, HTTPException

from deconflicted.ledger.service import LedgerUnavailable, get_client
from deconflicted.schema import Model

router = APIRouter()


def _client():
    try:
        return get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc


@router.get("/audit/export")
def export() -> dict:
    """The whole ledger with payloads and signatures. `python -m deconflicted.ledger.verify_cli` checks it."""
    return _client().export()


if os.environ.get("DECONFLICTED_DEBUG") == "1":
    class TamperRequest(Model):
        seq: Optional[int] = None

    @router.post("/debug/tamper")
    def tamper(body: TamperRequest | None = None) -> dict:
        """Debug only. Changes one stored payload without fixing its hash, so verify fails."""
        try:
            return {"tampered_seq": _client().tamper(body.seq if body else None)}
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
