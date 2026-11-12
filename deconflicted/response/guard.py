"""The response safety guard. Every answer fails closed: any doubt means block."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Callable, Optional

from deconflicted.schema import Action, Preview, TracePoint, Violation
from deconflicted.sim.process import MODELLED_PLC, Effect, Sample, State, parse_state, simulate

from .config import ConfigError, GuardConfig, Rule, load_config

TRACE_STEP = 10          # seconds between the points returned in a Preview
TOLERANCE = 0.5          # an action is blamed only if it makes things worse by more than this
RATE_LIMIT = 6           # writes per minute offered by the rate_limit_writes option
MAX_OPTIONS = 3


class Reject(Exception):
    """The action itself is not acceptable (unknown, wrong target, bad parameter)."""


@dataclass(frozen=True)
class Resolved:
    action: Action
    kind: str
    target: str
    effect: Effect
    effect_name: str
    plc: Optional[str]       # the PLC this action concerns, if any
    target_kind: str         # plc, host or user


def _strip(name: Any) -> str:
    text = str(name)
    for prefix in ("host:", "plc:", "user:"):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def _excursion(rule: Rule, value: float) -> float:
    below = rule.min - value if rule.min is not None else 0.0
    above = value - rule.max if rule.max is not None else 0.0
    return max(0.0, below, above)


def _value(sample: Sample, rule: Rule) -> float:
    return sample.level if rule.series == "level" else sample.setpoint


def find_violations(rules: tuple[Rule, ...], before: list[Sample], after: list[Sample]) -> list[Violation]:
    """Rule breaks the action causes: new ones, or ones it makes worse by more than the tolerance."""
    found = []
    for rule in rules:
        for b, a in zip(before, after):
            exc_before, exc_after = _excursion(rule, _value(b, rule)), _excursion(rule, _value(a, rule))
            if exc_after > 0 and (exc_before == 0 or exc_after > exc_before + TOLERANCE):
                value = _value(a, rule)
                found.append(Violation(rule_id=rule.id, ts=float(a.t),
                                       detail=f"{rule.series} reaches {value:.1f} at {a.t} s "
                                              f"(allowed {rule.min if rule.min is not None else '-'} "
                                              f"to {rule.max if rule.max is not None else '-'})"))
                break
    return found


def _trace(samples: list[Sample]) -> list[TracePoint]:
    return [TracePoint(t=float(s.t), level=round(s.level, 3)) for s in samples if s.t % TRACE_STEP == 0]


class ResponseGuard:
    """preview(action, process_state) -> Preview.

    A guard never raises from preview(). A broken configuration, a failed integrity check or any
    exception produces decision "block". With no process state (or rules_only=True) only the
    rules_only entries of safety_rules.yaml are checked.
    """

    def __init__(self, config_dir: str | None = None, *, rules_only: bool = False,
                 integrity_check: Callable[[], tuple[bool, str]] | None = None):
        self.rules_only = rules_only
        self._integrity_check = integrity_check
        self._error = ""
        self._config: GuardConfig | None = None
        try:
            self._config = load_config(config_dir)
        except Exception as exc:  # a guard with bad config still answers, with "block"
            self._error = f"safety configuration is not usable: {exc}"

    # ------------------------------------------------------------------ public
    def preview(self, action: Action, process_state: dict[str, Any] | None = None) -> Preview:
        try:
            return self._preview(action, process_state)
        except Reject as exc:
            return self._blocked(action, str(exc))
        except Exception as exc:
            return self._blocked(action, f"safety check failed: {exc}")

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _blocked(action: Any, reason: str) -> Preview:
        if not isinstance(action, Action):
            try:
                action = Action.model_validate(action)
            except Exception:
                action = Action.model_construct(id=str(getattr(action, "id", "invalid")),
                                                kind="isolate_host", target="unknown", params={})
        return Preview(action=action, before_trace=[], after_trace=[], violations=[],
                       safer_options=[], decision="block", reason=reason)

    def _preview(self, action: Action, process_state: dict[str, Any] | None) -> Preview:
        cfg = self._config
        if cfg is None:
            raise Reject(self._error)
        if self._integrity_check is not None:
            ok, why = self._integrity_check()
            if not ok:
                raise Reject(f"protected configuration failed its integrity check: {why}")
        resolved = self._resolve(cfg, action)
        if process_state is None or self.rules_only:
            return self._rules_only(cfg, resolved)
        state = parse_state(process_state, cfg.horizon)
        before = simulate(state, cfg.horizon)
        after = simulate(state, cfg.horizon, resolved.effect)
        violations = find_violations(cfg.rules, before, after)
        if not violations:
            return Preview(action=action, before_trace=_trace(before), after_trace=_trace(after),
                           violations=[], safer_options=[], decision="allow",
                           reason=f"no safety rule is broken within {cfg.horizon} seconds")
        options = self._safer_options(cfg, resolved, state, before)
        first = violations[0]
        what = f"{resolved.kind} on {resolved.target} would break {first.rule_id} ({first.detail})"
        if options:
            names = ", ".join(f"{o.kind} on {o.target}" for o in options)
            return Preview(action=action, before_trace=_trace(before), after_trace=_trace(after),
                           violations=violations, safer_options=options, decision="downgrade",
                           reason=f"{what}; safer option: {names}")
        return Preview(action=action, before_trace=_trace(before), after_trace=_trace(after),
                       violations=violations, safer_options=[], decision="block",
                       reason=f"{what}; no safer option keeps the process safe")

    def _resolve(self, cfg: GuardConfig, action: Action) -> Resolved:
        kind = str(action.kind)
        spec = cfg.actions.get(kind)
        if spec is None:
            raise Reject(f"action {kind!r} is not listed in actions.yaml")
        target = _strip(action.target)
        kind_of = cfg.hosts.get(target)
        if spec.target == "user":
            if target not in cfg.users:
                raise Reject(f"unknown user {target!r}")
            target_kind = "user"
        else:
            if kind_of is None:
                raise Reject(f"unknown target {target!r}")
            if spec.target == "plc" and kind_of != "plc":
                raise Reject(f"{kind} needs a PLC target, {target!r} is not a PLC")
            target_kind = "plc" if kind_of == "plc" else "host"
        params = action.params or {}
        for name in spec.params:
            if name not in params:
                raise Reject(f"{kind} is missing the parameter {name!r}")
        plc = target if target_kind == "plc" else None
        if plc and plc != MODELLED_PLC:
            raise Reject(f"there is no process model for {plc!r}")
        effect = Effect()
        if spec.effect == "plc_offline" and plc:
            effect = Effect("plc_offline")
        elif spec.effect == "block_writes":
            plc = _strip(params.get("to", ""))
            if cfg.hosts.get(plc) != "plc" or plc != MODELLED_PLC:
                raise Reject(f"there is no process model for {plc!r}")
            effect = Effect("block_writes", source=target, plc=plc)
        elif spec.effect == "set_setpoint":
            value = params.get("value")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise Reject("reset_setpoint needs a finite numeric value")
            effect = Effect("set_setpoint", value=float(value))
        if kind == "kill_process" and not str(params.get("process", "")).strip():
            raise Reject("kill_process needs a process name")
        if kind == "rate_limit_writes":
            limit = params.get("max_per_minute")
            if isinstance(limit, bool) or not isinstance(limit, (int, float)) or not math.isfinite(limit) or limit <= 0:
                raise Reject("rate_limit_writes needs a positive max_per_minute")
        return Resolved(action, kind, target, effect, spec.effect, plc, target_kind)

    def _rules_only(self, cfg: GuardConfig, resolved: Resolved) -> Preview:
        for entry in cfg.rules_only:
            if entry["action"] == resolved.kind and entry.get("target_kind") in (None, resolved.target_kind):
                return self._blocked(resolved.action, f"rules-only mode: {entry.get('reason') or entry['id']}")
        if resolved.effect.kind != "none":
            return self._blocked(resolved.action, f"rules-only mode: the effect {resolved.effect.kind} "
                                                  "cannot be checked without the process model")
        return Preview(action=resolved.action, before_trace=[], after_trace=[], violations=[],
                       safer_options=[], decision="allow", reason="rules-only mode: no rule blocks this action")

    def _candidates(self, cfg: GuardConfig, resolved: Resolved, state: State) -> list[tuple[Action, bool]]:
        """Possible safer actions, each flagged True when it comes from downgrade_to."""
        plc = resolved.plc or _strip(resolved.action.params.get("to", "")) or None
        if plc is None:
            return []
        base, found = resolved.action.id, []
        spec = cfg.actions[resolved.kind]
        down = cfg.actions.get(spec.downgrade_to or "")
        if down and down.target == "host" and down.params == ("to",):
            for writer in state.writers.get(plc, []):
                found.append((Action(id=f"{base}-opt{len(found) + 1}", kind=down.kind, target=writer,
                                     params={"to": plc}), True))
        setpoint_rules = [r for r in cfg.rules if r.series == "setpoint" and r.min is not None and r.max is not None]
        if "reset_setpoint" in cfg.actions and setpoint_rules:
            mid = (setpoint_rules[0].min + setpoint_rules[0].max) / 2
            found.append((Action(id=f"{base}-opt{len(found) + 1}", kind="reset_setpoint", target=plc,
                                 params={"value": mid}), False))
        if "rate_limit_writes" in cfg.actions:
            found.append((Action(id=f"{base}-opt{len(found) + 1}", kind="rate_limit_writes", target=plc,
                                 params={"max_per_minute": RATE_LIMIT}), False))
        return [(a, d) for a, d in found
                if not (a.kind == resolved.kind and a.target == resolved.action.target and a.params == resolved.action.params)]

    def _safer_options(self, cfg: GuardConfig, resolved: Resolved, state: State, before: list[Sample]) -> list[Action]:
        safe = []
        for candidate, from_downgrade in self._candidates(cfg, resolved, state):
            try:
                inner = self._resolve(cfg, candidate)
            except Reject:
                continue
            after = simulate(state, cfg.horizon, inner.effect)
            if not find_violations(cfg.rules, before, after):
                safe.append((candidate, from_downgrade, inner.effect.kind == "none", len(candidate.params)))
        # The configured downgrade_to fallback comes first, in order. The rest are ranked by how little
        # they touch the process: no effect before any effect, then fewer parameters.
        safe.sort(key=lambda item: (0, 0, 0) if item[1] else (1, 0 if item[2] else 1, item[3]))
        return [item[0] for item in safe][:MAX_OPTIONS]
