"""The demo controls: replay the recorded attack, reset, and read the state. Switched on with DECONFLICTED_DEMO=1.

POST /demo/attack {"speed": 40} streams data/demo/scenario.jsonl into the pipeline in the background (0 sends it all at
once). POST /demo/reset stops a run and clears the incidents, the events and the decoy hits; the ledger keeps its
history. GET /demo/status says whether the controls are on and how far a run is.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from deconflicted import adapters
from deconflicted.core.service import get_pipeline
from deconflicted.deception import get_service
from deconflicted.ledger.service import LedgerUnavailable, get_client
from deconflicted.schema import Model
from deconflicted.sim import replay as replay_tool

router = APIRouter()
DEFAULT_FILE = Path(__file__).resolve().parents[2] / "data" / "demo" / "scenario.jsonl"
MAX_SPEED = 600.0

_lock = threading.Lock()
_state: dict[str, Any] = {"running": False, "sent": 0, "total": 0, "speed": 0.0, "error": None, "stop": None, "thread": None}


class _Stopped(Exception):
    """The run was stopped by a reset."""


class AttackRequest(Model):
    speed: float = 40.0


def _enabled() -> bool:
    return os.environ.get("DECONFLICTED_DEMO") == "1"


def _require() -> None:
    if not _enabled():
        raise HTTPException(403, "the demo controls are off: start the API with DECONFLICTED_DEMO=1")


def _status() -> dict[str, Any]:
    return {"enabled": _enabled(), "running": _state["running"], "sent": _state["sent"], "total": _state["total"],
            "speed": _state["speed"], "error": _state["error"]}


def _feed(items: list[dict]) -> None:
    """The same steps as POST /ingest: parse, count for the ledger, give to the pipeline."""
    ledger = get_client()
    events = []
    for item in items:
        event = adapters.get(item["source"]).parse_line(item["raw"], assume_utc=True)
        ledger.note_event(event.id)
        events.append(event)
    get_pipeline().ingest(events)


def _work(events: list, speed: float, stop: threading.Event) -> None:
    def post(group: list[dict]) -> None:
        if stop.is_set():
            raise _Stopped()
        _feed(group)
        _state["sent"] += len(group)

    try:
        replay_tool.replay(events, post, speed, sleep=lambda seconds: stop.wait(seconds))
    except _Stopped:
        pass
    except Exception as exc:  # shown in the UI
        _state["error"] = str(exc)
    finally:
        _state["running"] = False


@router.get("/demo/status")
def status() -> dict[str, Any]:
    return _status()


@router.post("/demo/attack")
def start(body: AttackRequest | None = None) -> dict[str, Any]:
    _require()
    speed = body.speed if body else 40.0
    if not 0 <= speed <= MAX_SPEED:
        raise HTTPException(422, f"speed must be between 0 and {MAX_SPEED:g}")
    try:
        get_client()
    except LedgerUnavailable as exc:
        raise HTTPException(503, f"ledger unavailable: {exc}") from exc
    path = Path(os.environ.get("DECONFLICTED_DEMO_FILE", DEFAULT_FILE))
    with _lock:
        if _state["running"]:
            raise HTTPException(409, "an attack replay is already running")
        try:
            events = replay_tool.load(str(path))
        except (replay_tool.ReplayError, OSError) as exc:
            raise HTTPException(404, f"cannot read the recorded attack: {exc}") from exc
        stop = threading.Event()
        thread = threading.Thread(target=_work, args=(events, speed, stop), daemon=True)
        _state.update(running=True, sent=0, total=len(events), speed=speed, error=None, stop=stop, thread=thread)
        thread.start()
    return _status()


@router.post("/demo/reset")
def reset() -> dict[str, Any]:
    _require()
    stop, thread = _state.get("stop"), _state.get("thread")
    if stop is not None:
        stop.set()
    if thread is not None and thread.is_alive():
        thread.join(timeout=3)
    get_pipeline().reset()
    trigger = get_service().trigger
    trigger.hits.clear()
    trigger.allowlisted = 0
    _state.update(running=False, sent=0, total=0, error=None)
    return _status()