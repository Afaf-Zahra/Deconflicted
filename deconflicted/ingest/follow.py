"""Follow log files as they grow and send every new line to the API.   python -m deconflicted.ingest.follow <file or folder>

  --url URL         the API (default http://localhost:8000)
  --from-start      also send what the files already hold (default: only lines written from now on)
  --format NAME     a built-in source or replay for every file, when the content cannot be recognized
  --interval 0.5    seconds between checks
  --batch 200       lines per request
  --once            check once and stop

Only complete lines are sent. A file that is cut shorter (rotated) is read again from its start. A file that appears
after the start is read from its first line. When the API cannot be reached nothing is marked as sent, and the lines
go again at the next check (the pipeline ignores an event it already has). Built-in formats and replay files are
followed. For a format that a mapping describes, post JSON to /ingest/json instead (docs/ingest.md).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable

import httpx

from deconflicted import adapters

from .sniff import REPLAY, _DATE, read_sample, sniff_lines

Post = Callable[[list[dict]], "int | None"]  # sends a batch; returns how many lines the API rejected


class Follower:
    def __init__(self, path: str | Path, post: Post, *, from_start: bool = False, forced: str | None = None,
                 batch: int = 200) -> None:
        self.root = Path(path)
        self.post = post
        self.from_start = from_start
        self.forced = forced
        self.batch = max(1, batch)
        self.offsets: dict[Path, int] = {}
        self.formats: dict[Path, str] = {}
        self.unknown: dict[Path, int] = {}  # files that are not recognized, and their size when we last looked
        self.error: str | None = None
        self.rejected = 0
        self.skipped: list[str] = []
        self._baseline: set[Path] | None = None

    def _files(self) -> list[Path]:
        if self.root.is_dir():
            return sorted(p for p in self.root.rglob("*")
                          if p.is_file() and not any(part.startswith(".") for part in p.relative_to(self.root).parts))
        return [self.root] if self.root.is_file() else []

    @staticmethod
    def _end_of_last_line(path: Path, size: int) -> int:
        """Where the last complete line ends, so that a line still being written is not cut in two."""
        with open(path, "rb") as handle:
            start = max(0, size - 65536)
            handle.seek(start)
            tail = handle.read()
        cut = tail.rfind(b"\n")
        if cut >= 0:
            return start + cut + 1
        return 0 if start == 0 else size

    def poll(self) -> int:
        """Send the new complete lines of every file. Returns how many lines were sent."""
        files = self._files()
        if self._baseline is None:
            self._baseline = set(files)
        sent, self.error = 0, None
        for path in files:
            try:
                sent += self._follow(path)
            except OSError as exc:
                self.error = f"{path}: {exc}"
            except Exception as exc:  # the API could not take the lines: they are not marked as sent
                self.error = str(exc)
        return sent

    def _items(self, fmt: str, lines: list[str], path: Path, at_start: bool) -> list[dict]:
        items: list[dict] = []
        for number, line in enumerate(lines):
            if fmt == "flow" and at_start and number == 0:
                parts = line.split(",")
                if len(parts) == 7 and not _DATE.match(parts[0].strip()):
                    continue  # a header row
            if fmt == REPLAY:
                try:
                    item = json.loads(line)
                    if not (isinstance(item, dict) and isinstance(item.get("source"), str) and isinstance(item.get("raw"), str)):
                        raise ValueError("not a replay line")
                except ValueError:
                    self.skipped.append(f"{path.name}: {line[:60]}")
                    del self.skipped[:-50]
                    continue
                items.append({"source": item["source"], "raw": item["raw"]})
            else:
                items.append({"source": fmt, "raw": line})
        return items

    def _follow(self, path: Path) -> int:
        size = path.stat().st_size
        fmt = self.formats.get(path)
        if fmt is None:
            if self.unknown.get(path) == size:
                return 0
            fmt = self.forced or sniff_lines(read_sample(path))
            if fmt is None:
                self.unknown[path] = size
                return 0
            self.formats[path] = fmt
            self.unknown.pop(path, None)
        if path not in self.offsets:
            known_at_start = self._baseline is not None and path in self._baseline
            self.offsets[path] = 0 if (self.from_start or not known_at_start) else self._end_of_last_line(path, size)
        if size < self.offsets[path]:
            self.offsets[path] = 0
        with open(path, "rb") as handle:
            handle.seek(self.offsets[path])
            chunk = handle.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return 0
        complete = chunk[: end + 1]
        text = complete.decode("utf-8", errors="replace")
        at_start = self.offsets[path] == 0
        if at_start:
            text = text.lstrip("\ufeff")
        lines = [line.rstrip("\r") for line in text.split("\n") if line.strip()]
        items = self._items(fmt, lines, path, at_start)
        for first in range(0, len(items), self.batch):
            self.rejected += self.post(items[first:first + self.batch]) or 0
        self.offsets[path] += len(complete)
        return len(items)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deconflicted.ingest.follow",
                                     description="Follow log files and send new lines to the API")
    parser.add_argument("path", help="a log file or a folder of log files")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--format", dest="forced")
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--batch", type=int, default=200)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not Path(args.path).exists():
        print(f"FAILED {args.path} does not exist")
        return 1
    if args.forced and args.forced != REPLAY and args.forced not in adapters.ADAPTERS:
        print(f"FAILED unknown format {args.forced!r}; use replay or one of {', '.join(adapters.ADAPTERS)}")
        return 1
    client = httpx.Client(timeout=10.0)

    def post(items: list[dict]) -> int:
        response = client.post(args.url.rstrip("/") + "/ingest", json={"events": items})
        if response.status_code >= 300:
            raise RuntimeError(f"POST /ingest returned {response.status_code}: {response.text[:200]}")
        try:
            return len(response.json().get("errors", []))
        except ValueError:
            return 0

    follower = Follower(args.path, post, from_start=args.from_start, forced=args.forced, batch=args.batch)
    announced: set[Path] = set()
    shown_error: str | None = None
    print(f"following {args.path} and sending to {args.url}; press Ctrl+C to stop")
    try:
        while True:
            sent = follower.poll()
            for path, fmt in follower.formats.items():
                if path not in announced:
                    announced.add(path)
                    print(f"{path}: {fmt}")
            if sent:
                extra = f" ({follower.rejected} rejected by the API so far)" if follower.rejected else ""
                print(f"sent {sent} lines{extra}")
            if follower.error != shown_error:
                if follower.error:
                    print(f"waiting: {follower.error}")
                shown_error = follower.error
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopped")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())