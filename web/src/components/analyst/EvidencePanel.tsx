
import { Panel } from "../primitives/Panel"
import { SignalKindBadge } from "./AnalystBadges"

type EvidenceSignal = {
  id: string
  kind?: string
  event_ids?: string[]
}

type EvidenceEvent = {
  id: string
  ts?: string
  source?: string
  host?: string
  user?: string
  action?: string
  obj?: string
  raw?: unknown
}

type EvidencePanelProps = {
  signals?: EvidenceSignal[] | null
  events?: EvidenceEvent[] | null
}

function formatUtc(ts?: string): string {
  if (!ts) return "Unavailable"

  const date = new Date(ts)

  if (Number.isNaN(date.getTime())) {
    return "Unavailable"
  }

  return (
    date.toLocaleString("en-GB", {
      timeZone: "UTC",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + " UTC"
  )
}

function formatRaw(raw: unknown): string {
  if (raw === undefined || raw === null) {
    return "Raw event unavailable."
  }

  if (typeof raw === "string") {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2)
    } catch {
      return raw
    }
  }

  return JSON.stringify(raw, null, 2) ?? "Raw event unavailable."
}

export function EvidencePanel({
  signals,
  events,
}: EvidencePanelProps) {
  const signalList = signals ?? []
  const eventMap = new Map(
    (events ?? []).map((event) => [event.id, event]),
  )

  return (
    <Panel title="Incident Evidence">
      <div className="space-y-4 p-4">
        {signalList.length === 0 ? (
          <p className="text-sm text-on-surface-variant">
            No evidence signals available.
          </p>
        ) : (
          signalList.map((signal) => (
            <section
              key={signal.id}
              className="border border-outline-variant bg-surface-container-low p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <SignalKindBadge kind={signal.kind} />

                <span className="font-mono text-xs text-on-surface-variant">
                  {signal.id}
                </span>
              </div>

              <div className="mt-3 space-y-3">
                {(signal.event_ids ?? []).length === 0 ? (
                  <p className="text-sm text-on-surface-variant">
                    No linked events.
                  </p>
                ) : (
                  signal.event_ids?.map((eventId) => {
                    const event = eventMap.get(eventId)

                    if (!event) {
                      return (
                        <p
                          key={eventId}
                          className="text-sm text-on-surface-variant"
                        >
                          Event {eventId} unavailable.
                        </p>
                      )
                    }

                    return (
                      <div
                        key={eventId}
                        className="border border-outline-variant bg-surface-container-lowest p-3"
                      >
                        <p className="font-mono text-xs text-on-surface-variant">
                          {formatUtc(event.ts)}
                        </p>

                        <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                          <p>
                            <strong>Host:</strong>{" "}
                            {event.host || "Unavailable"}
                          </p>

                          <p>
                            <strong>User:</strong>{" "}
                            {event.user || "Unavailable"}
                          </p>

                          <p>
                            <strong>Action:</strong>{" "}
                            {event.action || "Unavailable"}
                          </p>

                          <p>
                            <strong>Object:</strong>{" "}
                            {event.obj || "Unavailable"}
                          </p>
                        </div>

                        <details className="mt-3">
                          <summary className="cursor-pointer font-mono text-xs text-primary">
                            View raw event
                          </summary>

                          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all bg-surface-container p-3 font-mono text-xs text-on-surface">
                            {formatRaw(event.raw)}
                          </pre>
                        </details>
                      </div>
                    )
                  })
                )}
              </div>
            </section>
          ))
        )}
      </div>
    </Panel>
  )
}

