
import type { Signal } from "../../lib/severity"

export function incidentSeveritySignal(
  severity: string | null | undefined,
): Signal {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "critical"
    case "warning":
      return "warning"
    case "info":
    default:
      return "info"
  }
}


