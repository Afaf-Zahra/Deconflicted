

import { BudgetMeter } from "../../components/analyst/BudgetMeter"
import {
  SeverityBadge,
  StatusBadge,
} from "../../components/analyst/AnalystBadges"
import { AttackTimeline } from "../../components/analyst/AttackTimeline"
import { FirstAlertBanner } from "../../components/analyst/FirstAlertBanner"
import { EvidencePanel } from "../../components/analyst/EvidencePanel"
import { useAnalystData } from "../../components/analyst/data"
import type { Incident } from "../../components/analyst/types"

type AnalystPageProps = {
  selectedIncidentId: string | null
  onSelectIncident: (id: string) => void
  onOpenResponse: (id: string) => void
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  warning: 1,
  info: 2,
}

function sortIncidents(incidents: Incident[]): Incident[] {
  return [...incidents].sort((a, b) => {
    const severityDifference =
      (SEVERITY_ORDER[a.severity] ?? 3) -
      (SEVERITY_ORDER[b.severity] ?? 3)

    if (severityDifference !== 0) {
      return severityDifference
    }

    return (
      Date.parse(b.first_event_ts) -
      Date.parse(a.first_event_ts)
    )
  })
}

export function AnalystPage({
  selectedIncidentId,
  onSelectIncident,
  onOpenResponse,
}: AnalystPageProps) {
  const { data, loading, error, updatedAt } = useAnalystData()


  const incidents = sortIncidents(data.incidents)
  const selectedIncident = incidents.find(
    (incident) => incident.id === selectedIncidentId,
  )

  if (loading) {
    return (
      <p className="p-6 text-on-surface-variant">
        Loading incidents...
      </p>
    )
  }

  return (
    <div className="space-y-5 p-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-on-surface">
            Incident Analyst
          </h1>
          <p className="text-sm text-on-surface-variant">
            Review detected incidents and supporting evidence.
          </p>
        </div>

        <span className="font-mono text-xs text-on-surface-variant">
          {updatedAt
            ? `Updated ${new Date(updatedAt).toLocaleTimeString("en-GB", {
                timeZone: "UTC",
              })} UTC`
            : "Not updated"}
        </span>
      </header>

      {error && (
        <div
          role="alert"
          className="border border-error p-3 text-sm text-error"
        >
          Unable to refresh incidents: {error}
        </div>
      )}

      {data.budget && (
        <div className="border border-outline-variant p-4">
          <BudgetMeter
            budget={data.budget.budget}
            used={data.budget.used}
            windowHours={data.budget.window_hours}
          />
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <section className="space-y-3 lg:col-span-1">
          <h2 className="font-semibold text-on-surface">
            Incidents
          </h2>

          {incidents.length === 0 ? (
            <p className="text-sm text-on-surface-variant">
              No incidents available.
            </p>
          ) : (
            incidents.map((incident) => (
              <button
                key={incident.id}
                type="button"
                onClick={() => {
                    onSelectIncident(incident.id)
                }}
                className={`w-full border p-3 text-left ${
                  selectedIncidentId === incident.id
                    ? "border-primary bg-surface-container"
                    : "border-outline-variant bg-surface-container-low"
                }`}
              >
                <div className="flex flex-wrap gap-2">
                  <SeverityBadge severity={incident.severity} />
                  <StatusBadge status={incident.status} />
                </div>

                <p className="mt-2 font-mono text-xs text-on-surface">
                  {incident.id}
                </p>

                <p className="mt-1 text-sm text-on-surface">
                  {incident.title || "Untitled incident"}
                </p>
              </button>
            ))
          )}
        </section>

        <section className="space-y-4 lg:col-span-2">
          <h2 className="font-semibold text-on-surface">
            Incident Details
          </h2>

          {!selectedIncident ? (
            <p className="text-sm text-on-surface-variant">
              Select an incident to view its details.
            </p>
          ) : (
            <>
              <div className="border border-outline-variant p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-mono font-semibold text-on-surface">
                    {selectedIncident.id}
                  </h3>
                  <SeverityBadge severity={selectedIncident.severity} />
                  <StatusBadge status={selectedIncident.status} />
                </div>

                <p className="mt-2 text-sm text-on-surface">
                  {selectedIncident.title || "Untitled incident"}
                </p>
              </div>

              <FirstAlertBanner
                firstEventTs={selectedIncident.first_event_ts}
                firstAlertTs={selectedIncident.first_alert_ts}
              />

              <AttackTimeline
                chain={selectedIncident.chain}
                chainStop={selectedIncident.chain_stop}
                promotedHeldSignalIds={
                  selectedIncident.promoted_held_signal_ids
                }
              />

              <EvidencePanel
                signals={selectedIncident.signals}
                events={data.events}
              />

              <div className="border border-outline-variant p-4">
                <h3 className="font-semibold text-on-surface">
                  Proposed Response Actions
                </h3>

                {selectedIncident.proposed_actions.length === 0 ? (
                  <p className="mt-2 text-sm text-on-surface-variant">
                    No proposed actions.
                  </p>
                ) : (
                  <div className="mt-3 space-y-2">
                    {selectedIncident.proposed_actions.map((action) => (
                      <div
                        key={action.id}
                        className="flex flex-wrap items-center justify-between gap-3 border border-outline-variant p-3"
                      >
                        <div>
                          <p className="font-mono text-sm text-on-surface">
                            {action.kind.replaceAll("_", " ")}
                          </p>
                          <p className="text-xs text-on-surface-variant">
                            Target: {action.target}
                          </p>
                        </div>

                        <button
                          type="button"
                          onClick={() =>
                            onOpenResponse(selectedIncident.id)
                          }
                          className="border border-primary px-3 py-2 text-xs text-primary"
                        >
                          Review response
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  )
}


