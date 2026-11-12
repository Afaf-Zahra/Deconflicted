"""GET /decoys."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from deconflicted.deception import get_service
from deconflicted.schema import DecoysView

router = APIRouter()


@router.get("/decoys", response_model=DecoysView)
def decoys(incident_id: Optional[str] = None) -> DecoysView:
    """All decoys, the hits so far, and Trail Ahead placements for the incident's hosts."""
    return get_service().view(incident_id)
