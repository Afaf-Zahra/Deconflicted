"""Benign-day scripts. Each actor module has lines_for_day(day, seed) -> [(source, raw_line)], sorted by time."""
from datetime import date

from deconflicted import adapters

from . import alice, background, bob, carol, dave, svc_backup

ACTORS = {m.ACTOR: m for m in (alice, bob, carol, dave, svc_backup, background)}


def day_lines(day: date, seed: int) -> list[tuple[str, str]]:
    """Every actor's lines for one day, merged and sorted by event time."""
    merged = []
    for module in ACTORS.values():
        for source, raw in module.lines_for_day(day, seed):
            merged.append((adapters.get(source).parse_line(raw).ts, source, raw))
    merged.sort(key=lambda item: (item[0], item[1], item[2]))
    return [(source, raw) for _, source, raw in merged]


__all__ = ["ACTORS", "day_lines"]
