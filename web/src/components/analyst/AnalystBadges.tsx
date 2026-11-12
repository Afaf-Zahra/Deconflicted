
import { Badge } from "../primitives/Badge"
import { incidentSeveritySignal } from "./severity"
import type { Signal } from "../../lib/severity"

type BadgeValue = string | null | undefined

function displayValue(value: BadgeValue): string {
  return value?.trim() || "Unknown"
}

export function SeverityBadge({
  severity,
}: {
  severity?: BadgeValue
}) {
  return (
    <Badge signal={incidentSeveritySignal(severity)}>
      {displayValue(severity)}
    </Badge>
  )
}

export function StatusBadge({
  status,
}: {
  status?: BadgeValue
}) {
  const signal: Signal =
    status === "open" ? "warning" : "info"

  return (
    <Badge signal={signal}>
      {displayValue(status)}
    </Badge>
  )
}

export function SignalKindBadge({
  kind,
}: {
  kind?: BadgeValue
}) {
  const signal: Signal =
    kind === "decoy_hit" || kind === "ot_invariant"
      ? "critical"
      : kind === "log_clear"
        ? "warning"
        : "info"

  return (
    <Badge signal={signal}>
      {displayValue(kind).replaceAll("_", " ")}
    </Badge>
  )
}
