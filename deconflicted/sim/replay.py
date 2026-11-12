"""Replay a scenario file into the API at a chosen speed.

  python -m deconflicted.sim.replay --file data/demo/scenario.jsonl --speed 60 --url http://localhost:8000

The file has one {"source": ..., "raw": ...} object per line, in time order (sim/build.py makes it).
Batches go to POST /ingest with the body {"events": [{"source": ..., "raw": ...}, ...]}.
--speed 60 means one real second is one minute of log time. --speed 0 sends everything at once.
--dry-run prints each batch as one JSON line and sends nothing.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from datetime import datetime
from typing import Callable, Iterable

import httpx

from deconflicted import adapters

Item = dict   # {"source": str, "raw": str}


class ReplayError(RuntimeError):
    pass


def load(path: str) -> list[tuple[datetime, Item]]:
    """Read the file, parse every line for its time, and require time order."""
    events: list[tuple[datetime, Item]] = []
    with open(path, encoding="utf-8") as handle:
        for number, text in enumerate(handle, start=1):
            if not text.strip():
                continue
            try:
                item = json.loads(text)
                source, raw = item["source"], item["raw"]
                ts = adapters.get(source).parse_line(raw, file=path, lineno=number).ts
            except (json.JSONDecodeError, KeyError, adapters.AdapterError) as exc:
                raise ReplayError(f"{path}:{number}: {exc}") from exc
            if events and ts < events[-1][0]:
                raise ReplayError(f"{path}:{number}: events must be in time order")
            events.append((ts, {"source": source, "raw": raw}))
    return events


def batches(events: list[tuple[datetime, Item]], speed: float, batch_seconds: float = 1.0,
            batch_size: int = 500) -> Iterable[tuple[float, list[Item]]]:
    """Group events. Yields (real seconds after the start at which to send, the batch)."""
    if not events:
        return
    first = events[0][0]
    group: list[Item] = []
    current, last_time = None, 0.0
    for ts, item in events:
        if speed > 0:
            when = (ts - first).total_seconds() / speed
            window = math.floor(when / batch_seconds)
            full = group and window != current
        else:
            when, window = 0.0, 0
            full = len(group) >= batch_size
        if full:
            yield last_time, group
            group = []
        group.append(item)
        current, last_time = window, when
    if group:
        yield last_time, group


def replay(events: list[tuple[datetime, Item]], post: Callable[[list[Item]], None], speed: float,
           batch_seconds: float = 1.0, batch_size: int = 500,
           sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> int:
    """Send the events in batches, waiting so that real time follows log time / speed. Returns the batch count."""
    started, sent = clock(), 0
    for when, group in batches(events, speed, batch_seconds, batch_size):
        wait = when - (clock() - started)
        if wait > 0:
            sleep(wait)
        post(group)
        sent += 1
    return sent


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a scenario into the API")
    parser.add_argument("--file", required=True)
    parser.add_argument("--speed", type=float, default=60.0)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--batch-seconds", type=float, default=1.0)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        events = load(args.file)
    except (ReplayError, OSError) as exc:
        print(f"FAILED {exc}")
        return 1
    http = client or httpx.Client(timeout=10.0)

    def post(group: list[Item]) -> None:
        body = {"events": group}
        if args.dry_run:
            print(json.dumps(body, separators=(",", ":")))
            return
        response = http.post(args.url.rstrip("/") + "/ingest", json=body)
        if response.status_code >= 300:
            raise ReplayError(f"POST /ingest returned {response.status_code}: {response.text[:200]}")

    try:
        count = replay(events, post, args.speed, args.batch_seconds, args.batch_size,
                       sleep=(lambda s: None) if args.dry_run else time.sleep)
    except (ReplayError, httpx.HTTPError) as exc:
        print(f"FAILED {exc}")
        return 1
    print(f"replayed {len(events)} events in {count} batches", file=sys.stderr if args.dry_run else sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
