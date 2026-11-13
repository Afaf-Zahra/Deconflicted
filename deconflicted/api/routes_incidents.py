"""GET /incidents, /incidents/{id}, /incidents/{id}/graph, /events and /budget."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from deconflicted.core.service import get_pipeline
from deconflicted.schema import Budget, Event, Incident, IncidentGraph

router = APIRouter()
MAX_EVENT_IDS = 500


@router.get("/incidents", response_model=list[Incident], response_model_exclude_none=True)
def list_incidents() -> list[Incident]:
    return get_pipeline().incidents()


@router.get("/incidents/{incident_id}", response_model=Incident, response_model_exclude_none=True)
def get_incident(incident_id: str) -> Incident:
    incident = get_pipeline().incident(incident_id)
    if incident is None:
        raise HTTPException(404, f"no incident {incident_id!r}")
    return incident


@router.get("/incidents/{incident_id}/graph", response_model=IncidentGraph)
def get_graph(incident_id: str) -> IncidentGraph:
    graph = get_pipeline().graph(incident_id)
    if graph is None:
        raise HTTPException(404, f"no incident {incident_id!r}")
    return graph


@router.get("/events", response_model=list[Event], response_model_exclude_none=True)
def get_events(ids: str = Query("", description="comma-separated event ids")) -> list[Event]:
    wanted = [i for i in ids.split(",") if i][:MAX_EVENT_IDS]
    return get_pipeline().events(wanted)


@router.get("/budget", response_model=Budget)
def get_budget() -> Budget:
    return get_pipeline().budget()


@router.get("/detection/status")
def detection_status() -> dict:
    """What the detection engine is running with: the baseline, the thresholds and the counts."""
    return get_pipeline().status()