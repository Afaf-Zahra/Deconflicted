"""POST /ingest/json: events as JSON, as they happen.

The body can be one JSON object, an array of objects, {"events": [...]}, {"Records": [...]} (the CloudTrail wrapper) or
one object per line (NDJSON). Each object is either {"source": ..., "raw": ...} (what /ingest takes) or a log record
itself, such as a Sysmon event. ?source=windows forces a built-in format for every object. ?mapping=edr forces a mapping
from config/mappings.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool

from deconflicted.adapters.hosts import config_dir
from deconflicted.core.service import get_pipeline
from deconflicted.ingest.live import parse_item
from deconflicted.ingest.mapper import MappingError, load_mappings
from deconflicted.ledger.service import LedgerUnavailable, get_client

router = APIRouter()
MAX_ITEMS = 5000


def _items(body: bytes) -> list[Any]:
    """The objects in the body: one object, an array, a wrapped array, or one object per line."""
    text = body.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise HTTPException(400, "the body is empty")
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise HTTPException(400, f"line {number} is not valid JSON ({exc.msg})") from exc
    if isinstance(data, dict) and len(data) == 1:
        (only,) = data
        if only in ("events", "Records") and isinstance(data[only], list):
            data = data[only]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise HTTPException(400, "expected a JSON object, an array of objects or one object per line")
    if len(data) > MAX_ITEMS:
        raise HTTPException(413, f"at most {MAX_ITEMS} events per request")
    return data


def _process(items: list[Any], source: str | None, mapping: str | None) -> dict:
    try:
        ledger = get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc
    try:
        mappings = load_mappings(config_dir() / "mappings")
    except MappingError as exc:
        raise HTTPException(503, f"a mapping file is wrong: {exc}") from exc
    events, errors = [], []
    for number, item in enumerate(items):
        try:
            events.append(parse_item(item, source=source, mapping=mapping, mappings=mappings))
        except (ValueError, TypeError) as exc:
            errors.append({"index": number, "error": str(exc)})
    for event in events:
        ledger.note_event(event.id)
    incidents = get_pipeline().ingest(events)
    return {"accepted": len(events), "errors": errors, "incidents": len(incidents)}


@router.post("/ingest/json")
async def ingest_json(request: Request, source: str | None = Query(None), mapping: str | None = Query(None)) -> dict:
    items = _items(await request.body())
    return await run_in_threadpool(_process, items, source, mapping)