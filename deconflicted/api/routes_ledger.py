"""GET /ledger, /ledger/verify and /ledger/nodes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from deconflicted.ledger.client import QuorumError
from deconflicted.ledger.service import LedgerUnavailable, get_client, get_integrity
from deconflicted.schema import LedgerEntry, NodeStatus, VerifyReport

router = APIRouter()


def _client():
    try:
        return get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc


@router.get("/ledger", response_model=list[LedgerEntry])
def list_entries(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[LedgerEntry]:
    return _client().entries(limit=limit, offset=offset)


@router.get("/ledger/verify", response_model=VerifyReport)
def verify() -> VerifyReport:
    client = _client()
    try:
        get_integrity().check()  # an unsigned config change is recorded before the chain is verified
    except (LedgerUnavailable, QuorumError) as exc:
        raise HTTPException(503, f"cannot check the config against the ledger: {exc}") from exc
    return client.verify()


@router.get("/ledger/nodes", response_model=list[NodeStatus])
def nodes() -> list[NodeStatus]:
    return _client().node_status()
