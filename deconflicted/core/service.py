"""The one shared pipeline the API uses, built with the saved baseline and wired to the ledger, the decoys and the guard."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from deconflicted.schema import Signal

from .baseline import Baseline, BaselineError
from .config import CoreConfig, load_config
from .pipeline import Pipeline
from .settings import Settings, load_settings

LOG = logging.getLogger("deconflicted.core")
DEFAULT_MODEL = Path(__file__).parent / "model" / "baseline.json"
_pipeline: Pipeline | None = None


def load_baseline(config: CoreConfig) -> tuple[Baseline, str]:
    """The saved baseline (DECONFLICTED_BASELINE or core/model/baseline.json), or an untrained one and why."""
    path = Path(os.environ.get("DECONFLICTED_BASELINE", DEFAULT_MODEL))
    if not path.is_file():
        return Baseline(config), f"no baseline file at {path}: only certain signals and routine breaks can fire"
    try:
        baseline = Baseline.load(path, config)
    except BaselineError as exc:
        return Baseline(config), f"{exc}: running without a baseline"
    return baseline, f"baseline loaded from {path} ({baseline.trained_events} training events)"


def load_scorer(settings: Settings):
    """The PyTorch scorer when detection.yaml turns it on and its files load. Otherwise None, and why."""
    if not settings.scorer_enabled:
        return None, "off"
    try:
        from deconflicted.ml.scorer import GRUScorer

        return GRUScorer.load(), "on"
    except Exception as exc:  # torch missing or weights unusable: the baseline carries on alone
        return None, f"off: {exc}"


def _record(kind: str, payload: dict) -> None:
    from deconflicted.ledger.service import get_client

    get_client().append(kind, payload)


def _integrity() -> list[Signal]:
    """integrity_violation signals for protected config files that no longer match the ledger."""
    from deconflicted.ledger.client import QuorumError
    from deconflicted.ledger.service import LedgerUnavailable, get_integrity

    try:
        return get_integrity().check()
    except (LedgerUnavailable, QuorumError):
        return []


def install(pipeline: Pipeline) -> None:
    """Give the decoy view and the safety guard their live data from the pipeline."""
    from deconflicted.deception import get_service
    from deconflicted.response import service as response

    get_service().incident_hosts = pipeline.incident_hosts
    response.set_state_provider(pipeline.process_state)


def get_pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is None:
        config, settings = load_config(), load_settings()
        baseline, status = load_baseline(config)
        scorer, scorer_status = load_scorer(settings)
        (LOG.info if baseline.trained_events else LOG.warning)(status)
        pipeline = Pipeline(config=config, baseline=baseline, settings=settings, scorer=scorer,
                            recorder=_record, integrity_check=_integrity)
        pipeline.baseline_status, pipeline.scorer_status = status, scorer_status
        install(pipeline)
        _pipeline = pipeline
    return _pipeline


def set_pipeline(pipeline: Pipeline | None) -> None:
    """Replace the shared pipeline (tests, and a fresh start)."""
    global _pipeline
    _pipeline = pipeline