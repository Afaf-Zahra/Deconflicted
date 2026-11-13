"""The API app. Run it with: uvicorn deconflicted.api.main:app --reload

Every routes_*.py file in this folder is loaded and its `router` is included, so a new route file needs no change here.
"""
from __future__ import annotations

import importlib
import pkgutil

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

import deconflicted.api as api_package
from deconflicted import adapters
from deconflicted.core.service import get_pipeline
from deconflicted.ledger.service import LedgerUnavailable, get_client

app = FastAPI(title="Deconflicted")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in sorted(pkgutil.iter_modules(api_package.__path__), key=lambda m: m.name):
    if module.name.startswith("routes_"):
        app.include_router(importlib.import_module(f"deconflicted.api.{module.name}").router)


class RawEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    raw: str


class IngestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[RawEvent]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/ingest")
def ingest(body: IngestBody) -> dict:
    """Parse raw lines, count them for ledger anchoring, and give them to the detection pipeline."""
    try:
        ledger = get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc
    events, errors = [], []
    for number, item in enumerate(body.events):
        try:
            event = adapters.get(item.source).parse_line(item.raw, assume_utc=True)
        except adapters.AdapterError as exc:
            errors.append({"index": number, "error": str(exc)})
            continue
        ledger.note_event(event.id)
        events.append(event)
    incidents = get_pipeline().ingest(events)
    return {"accepted": len(events), "errors": errors, "incidents": len(incidents)}