"""Zero-disruption property check.

For many seeds and starting states, ask the guard about every kind of action, apply only what it
allows (or the first safer option when it downgrades), then run the tank for the full horizon and
count any rule break the action caused. The count must be 0.

The check does its own effect mapping and rule test on purpose, so it does not just repeat the
guard's code.   Run:  python -m deconflicted.response.zero_disruption --cases 1000
"""
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field

from deconflicted.schema import Action
from deconflicted.sim.process import Effect, parse_state, simulate

from .config import load_config
from .guard import TOLERANCE, ResponseGuard


@dataclass
class Report:
    cases: int = 0
    actions: int = 0
    allowed: int = 0
    downgraded: int = 0
    blocked: int = 0
    violations: int = 0
    examples: list = field(default_factory=list)


def random_state(rng: random.Random, unsafe_start: bool) -> dict:
    writes = []
    for _ in range(rng.randint(0, 3)):
        register = rng.choice([40001, 40001, 40010, 40011])
        if register == 40001:
            value = rng.choice([rng.uniform(61, 100), rng.uniform(0, 39)])
        elif register == 40010:
            value = rng.choice([0, 1])
        else:
            value = rng.uniform(0, 100)
        write = {"t": rng.randint(0, 250), "plc": "plc-1", "register": register, "value": round(value, 2)}
        if rng.random() < 0.5:
            write["source"] = "eng-ws-01"
        writes.append(write)
    return {
        "t": 0,
        "level": round(rng.uniform(5, 95) if unsafe_start else rng.uniform(30, 70), 2),
        "setpoint": round(rng.uniform(30, 70) if unsafe_start else rng.uniform(40, 60), 2),
        "pump": rng.random() < 0.5,
        "valve": round(rng.uniform(20, 80), 2),
        "plc_online": {"plc-1": True},
        "writers": {"plc-1": ["eng-ws-01"]},
        "pending_writes": writes,
    }


def candidate_actions(rng: random.Random) -> list[Action]:
    specs = [
        ("isolate_host", "plc-1", {}), ("isolate_host", "ws-help-01", {}), ("isolate_host", "plc-2", {}),
        ("block_write", "eng-ws-01", {"to": "plc-1"}), ("block_write", "ws-help-01", {"to": "plc-1"}),
        ("disable_account", "alice", {}), ("kill_process", "file-01", {"process": "powershell.exe"}),
        ("reset_setpoint", "plc-1", {"value": round(rng.uniform(0, 100), 1)}),
        ("rate_limit_writes", "plc-1", {"max_per_minute": 6}),
    ]
    return [Action(id=f"act-{i}", kind=k, target=t, params=p) for i, (k, t, p) in enumerate(specs)]


def _effect(action: Action) -> Effect:
    """Effect of an applied action. Written separately from the guard."""
    if action.kind == "isolate_host" and action.target == "plc-1":
        return Effect("plc_offline")
    if action.kind == "block_write":
        return Effect("block_writes", source=action.target, plc=action.params["to"])
    if action.kind == "reset_setpoint":
        return Effect("set_setpoint", value=float(action.params["value"]))
    return Effect()


def _breaks(rules, before, after) -> list[str]:
    broken = []
    for rule in rules:
        for b, a in zip(before, after):
            vb = b.level if rule.series == "level" else b.setpoint
            va = a.level if rule.series == "level" else a.setpoint
            eb = max(0.0, (rule.min - vb) if rule.min is not None else 0.0, (vb - rule.max) if rule.max is not None else 0.0)
            ea = max(0.0, (rule.min - va) if rule.min is not None else 0.0, (va - rule.max) if rule.max is not None else 0.0)
            if ea > 0 and (eb == 0 or ea > eb + TOLERANCE):
                broken.append(rule.id)
                break
    return broken


def run(cases: int = 1000, seed: int = 0, config_dir: str | None = None, unsafe_share: float = 0.2,
        guard: ResponseGuard | None = None) -> Report:
    config = load_config(config_dir)
    guard = guard or ResponseGuard(config_dir)
    rng = random.Random(seed)
    report = Report()
    for _ in range(cases):
        state_data = random_state(rng, rng.random() < unsafe_share)
        state = parse_state(state_data, config.horizon)
        baseline = simulate(state, config.horizon)
        report.cases += 1
        for action in candidate_actions(rng):
            report.actions += 1
            preview = guard.preview(action, state_data)
            if preview.decision == "allow":
                applied = action
                report.allowed += 1
            elif preview.decision == "downgrade" and preview.safer_options:
                applied = preview.safer_options[0]
                report.downgraded += 1
            else:
                report.blocked += 1
                continue
            broken = _breaks(config.rules, baseline, simulate(state, config.horizon, _effect(applied)))
            if broken:
                report.violations += len(broken)
                if len(report.examples) < 5:
                    report.examples.append({"state": state_data, "action": applied.model_dump(), "broken": broken})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    report = run(args.cases, args.seed)
    print(f"cases={report.cases} actions={report.actions} allowed={report.allowed} "
          f"downgraded={report.downgraded} blocked={report.blocked} violations={report.violations}")
    for example in report.examples:
        print("VIOLATION", example)
    return 1 if report.violations else 0


if __name__ == "__main__":
    sys.exit(main())
