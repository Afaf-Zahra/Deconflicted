"""POST /response/preview, /response/{action_id}/approve and /reject.

Every decision and every approval is written to the ledger. If the ledger cannot record it,
nothing goes ahead (503).
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from deconflicted.ledger.chain import payload_hash
from deconflicted.ledger.client import QuorumError
from deconflicted.ledger.service import LedgerUnavailable, get_client
from deconflicted.response import service
from deconflicted.schema import Action, LedgerEntry, Model, Preview

router = APIRouter()


class PreviewRequest(Model):
    incident_id: str
    action: Action
    process_state: Optional[dict[str, Any]] = None


class Analyst(Model):
    analyst: str


def _ledger():
    try:
        return get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc


def _record(client, kind: str, payload: dict) -> LedgerEntry:
    try:
        return client.append(kind, payload)
    except (QuorumError, LedgerUnavailable) as exc:
        raise HTTPException(503, f"could not record this in the ledger, so nothing was done: {exc}") from exc


def _latest_decision(client, action_id: str) -> dict | None:
    found = [p for _, p in client.payloads("response_decision") if p.get("action_id") == action_id]
    return found[-1] if found else None


def _check_analyst(client, name: str) -> None:
    if name not in client.policy.analysts:
        raise HTTPException(403, f"{name!r} is not a listed analyst")


@router.post("/response/preview", response_model=Preview)
def preview(request: PreviewRequest) -> Preview:
    client = _ledger()
    try:
        guard = service.get_guard()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc
    state = request.process_state if request.process_state is not None else service.state_provider(request.incident_id)
    result = guard.preview(request.action, state)
    _record(client, "response_decision", {
        "incident_id": request.incident_id, "action_id": request.action.id,
        "action": request.action.model_dump(mode="json"), "decision": result.decision,
        "reason": result.reason, "safer_options": [o.model_dump(mode="json") for o in result.safer_options],
        "preview_hash": payload_hash(result.model_dump(mode="json"))})
    return result


@router.post("/response/{action_id}/approve", response_model=LedgerEntry)
def approve(action_id: str, body: Analyst) -> LedgerEntry:
    client = _ledger()
    _check_analyst(client, body.analyst)
    decision = _latest_decision(client, action_id)
    if decision is None:
        raise HTTPException(409, f"action {action_id!r} has no safety preview, so it cannot be approved")
    if decision["decision"] == "block":
        raise HTTPException(409, f"action {action_id!r} was blocked by the safety check: {decision['reason']}")
    applied = decision["safer_options"][0] if decision["decision"] == "downgrade" and decision["safer_options"] \
        else decision["action"]
    return _record(client, "approval", {"action_id": action_id, "analyst": body.analyst, "decision": "approved",
                                        "preview_hash": decision["preview_hash"], "applied_action": applied})


@router.post("/response/{action_id}/reject", response_model=LedgerEntry)
def reject(action_id: str, body: Analyst) -> LedgerEntry:
    client = _ledger()
    _check_analyst(client, body.analyst)
    decision = _latest_decision(client, action_id)
    return _record(client, "approval", {"action_id": action_id, "analyst": body.analyst, "decision": "rejected",
                                        "preview_hash": decision["preview_hash"] if decision else None})
