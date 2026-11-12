"""The per-role Markov baseline: how unusual is this event for the entity that did it, and for its peers?

Each event gets two measures. Both become a score between 0 and 1: the share of the benign training events that were
less surprising, so 0.999 means "rarer than 99.9% of normal".

  sequence  how unlikely is this behaviour token after the actor's previous one? The entity's own history is blended
            with its role's history, weighted n / (n + peer_backoff_n), so an entity with little history leans on its
            peers. Laplace smoothing (laplace_alpha) gives unseen behaviour a small, non-zero probability.
  hour      how unlikely is this token at this UTC hour for the role? This catches a normal action at an odd time.

The previous token only counts when it is no older than window_hours. The score of an event is the larger of the two.
The training events are scored as if each had been left out, so the reference matches what a new day will look like.
"""
from __future__ import annotations

import json
import math
from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from deconflicted.schema import Event

from .config import CoreConfig
from .entities import actor_of, role_of, token_of

START = "<start>"  # the context of an actor's first event, or one after the window has passed
REFERENCE_LIMIT = 5000  # values kept per reference when a baseline is saved
VERSION = 1


class BaselineError(RuntimeError):
    """A saved baseline cannot be used."""


class _Counts:
    """How often each token followed each context for each key, with the totals the probabilities need."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, int]] = {}
        self.totals: dict[tuple[str, str], int] = {}

    def add(self, key: str, context: str, token: str, n: int = 1) -> None:
        slot = (key, context)
        row = self.rows.setdefault(slot, {})
        row[token] = row.get(token, 0) + n
        self.totals[slot] = self.totals.get(slot, 0) + n

    def get(self, key: str, context: str, token: str) -> tuple[int, int]:
        slot = (key, context)
        row = self.rows.get(slot)
        return (row.get(token, 0), self.totals[slot]) if row else (0, 0)

    def dump(self) -> list[list]:
        return [[key, context, token, n] for (key, context), row in sorted(self.rows.items())
                for token, n in sorted(row.items())]


@dataclass(frozen=True)
class Observation:
    actor: str
    role: str
    token: str
    previous: str  # the context token, START when there is none
    sequence_bits: float
    hour_bits: float
    sequence_score: float
    hour_score: float

    @property
    def score(self) -> float:
        return max(self.sequence_score, self.hour_score)

    @property
    def reason(self) -> str:
        return "hour" if self.hour_score > self.sequence_score else "sequence"


def _rank(reference: list[float], bits: float) -> float:
    """The share of reference values that are less surprising. 0 without a reference."""
    return bisect_left(reference, bits) / len(reference) if reference else 0.0


def _thin(values: list[float], limit: int = REFERENCE_LIMIT) -> list[float]:
    if len(values) <= limit:
        return list(values)
    return [values[round(i * (len(values) - 1) / (limit - 1))] for i in range(limit)]


class Baseline:
    def __init__(self, config: CoreConfig) -> None:
        self.config = config
        self.trained_events = 0
        self._clear()

    def _clear(self) -> None:
        self._entity, self._role, self._hours = _Counts(), _Counts(), _Counts()
        self._vocab: set[str] = set()
        self._sequence_reference: list[float] = []
        self._hour_reference: list[float] = []
        self._last: dict[str, tuple[str, datetime]] = {}
        self.trained_events = 0

    @property
    def vocab(self) -> list[str]:
        return sorted(self._vocab)

    def reset(self) -> None:
        """Forget what each actor did last. The learned counts stay."""
        self._last = {}

    def _context(self, last: dict[str, tuple[str, datetime]], actor: str, ts: datetime) -> str:
        seen = last.get(actor)
        if seen is None:
            return START
        token, when = seen
        gap = (ts - when).total_seconds()
        return token if 0 <= gap <= self.config.model.window_hours * 3600 else START

    def _bits(self, actor: str, role: str, token: str, previous: str, hour: int, leave_out: bool = False) -> tuple[float, float]:
        model, drop = self.config.model, 1 if leave_out else 0
        v = len(self._vocab) + 1  # every known token, and one slot for any token never seen
        own, own_total = self._entity.get(actor, previous, token)
        peer, peer_total = self._role.get(role, previous, token)
        p_own = (own - drop + model.alpha) / (own_total - drop + model.alpha * v)
        p_peer = (peer - drop + model.alpha) / (peer_total - drop + model.alpha * v)
        spread = own_total - drop + model.backoff_n
        weight = (own_total - drop) / spread if spread > 0 else 0.0
        p = weight * p_own + (1 - weight) * p_peer
        seen, seen_total = self._hours.get(role, token, str(hour))
        p_hour = (seen - drop + model.alpha) / (seen_total - drop + model.alpha * 24)
        return -math.log2(p), -math.log2(p_hour)

    def fit(self, events: Iterable[Event]) -> int:
        """Learn from benign events (sorted by time here). Returns how many were used."""
        ordered = sorted(events, key=lambda event: (event.ts, event.id))
        self._clear()
        steps: list[tuple[str, str, str, str, int]] = []
        last: dict[str, tuple[str, datetime]] = {}
        for event in ordered:
            actor = actor_of(event, self.config)
            role = role_of(actor, self.config)
            token = token_of(event)
            previous = self._context(last, actor, event.ts)
            last[actor] = (token, event.ts)
            self._entity.add(actor, previous, token)
            self._role.add(role, previous, token)
            self._hours.add(role, token, str(event.ts.hour))
            self._vocab.add(token)
            steps.append((actor, role, token, previous, event.ts.hour))
        for actor, role, token, previous, hour in steps:
            sequence_bits, hour_bits = self._bits(actor, role, token, previous, hour, leave_out=True)
            self._sequence_reference.append(sequence_bits)
            self._hour_reference.append(hour_bits)
        self._sequence_reference.sort()
        self._hour_reference.sort()
        self.trained_events = len(ordered)
        return len(ordered)

    def observe(self, event: Event, token: str | None = None) -> Observation:
        """Score one event and remember it as its actor's latest. Events should arrive in time order."""
        actor = actor_of(event, self.config)
        role = role_of(actor, self.config)
        token = token or token_of(event)
        previous = self._context(self._last, actor, event.ts)
        seen = self._last.get(actor)
        if seen is None or event.ts >= seen[1]:  # an older event never becomes the context
            self._last[actor] = (token, event.ts)
        sequence_bits, hour_bits = self._bits(actor, role, token, previous, event.ts.hour)
        return Observation(actor, role, token, previous, sequence_bits, hour_bits,
                           _rank(self._sequence_reference, sequence_bits), _rank(self._hour_reference, hour_bits))

    # ---- saving, so the API can start without the benign days
    def _settings(self) -> dict:
        model = self.config.model
        return {"window_hours": model.window_hours, "alpha": model.alpha, "backoff_n": model.backoff_n}

    def save(self, path: str | Path) -> None:
        data = {"version": VERSION, "settings": self._settings(), "trained_events": self.trained_events,
                "vocab": self.vocab, "entity": self._entity.dump(), "role": self._role.dump(),
                "hours": self._hours.dump(), "sequence_reference": _thin(self._sequence_reference),
                "hour_reference": _thin(self._hour_reference)}
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")

    @classmethod
    def load(cls, path: str | Path, config: CoreConfig) -> "Baseline":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"cannot read the baseline {path}: {exc}") from exc
        model = cls(config)
        try:
            if data["version"] != VERSION:
                raise BaselineError(f"{path} has version {data['version']}, this code reads version {VERSION}")
            if data["settings"] != model._settings():
                raise BaselineError(f"{path} was trained with different model settings; train it again")
            for key, context, token, n in data["entity"]:
                model._entity.add(key, context, token, int(n))
            for key, context, token, n in data["role"]:
                model._role.add(key, context, token, int(n))
            for key, context, token, n in data["hours"]:
                model._hours.add(key, context, token, int(n))
            model._vocab = set(data["vocab"])
            model._sequence_reference = [float(value) for value in data["sequence_reference"]]
            model._hour_reference = [float(value) for value in data["hour_reference"]]
            model.trained_events = int(data["trained_events"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BaselineError(f"{path} is not a baseline file ({exc})") from exc
        return model