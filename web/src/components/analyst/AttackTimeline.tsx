
import { Panel } from "../primitives/Panel"
import { Badge } from "../primitives/Badge"

type ChainStep = {
  ts?: string
  tactic?: string
  technique?: string
  description?: string
  signal_id?: string
  matched_routine?: boolean
}

type ChainStop = {
  index?: number
  reason?: string
}


type AttackTimelineProps = {
  chain?: ChainStep[] | null
  chainStop?: ChainStop | null
  promotedHeldSignalIds?: string[] | null
}


function utcTime(timestamp?: string): string {
  if (!timestamp) return "Time unavailable"

  const date = new Date(timestamp)

  if (Number.isNaN(date.getTime())) {
    return "Time unavailable"
  }

  return date.toLocaleString("en-GB", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }) + " UTC"
}


export function AttackTimeline({
  chain,
  chainStop,
  promotedHeldSignalIds,
}: AttackTimelineProps) {
  const steps = chain ?? []
  const promotedIds = new Set(promotedHeldSignalIds ?? [])


  return (
    <Panel title="MITRE ATT&CK Timeline">
      {steps.length === 0 ? (
        <p className="p-4 text-sm text-on-surface-variant">
          No attack steps available.
        </p>
      ) : (
        <ol className="space-y-0 p-4">
          {steps.map((step, index) => {
            const isChainStop = chainStop?.index === index
            const isRecovered =
                step.signal_id !== undefined &&
                promotedIds.has(step.signal_id)

            return (
              <li
                key={`${step.signal_id ?? "step"}-${index}`}
                className="relative border-l-2 border-outline-variant pb-6 pl-5 last:pb-0"
              >
                <span
                  className={`absolute -left-[5px] top-1 h-2 w-2 rounded-full ${
                    isChainStop
                      ? "bg-error"
                      : "bg-secondary-fixed-dim"
                  }`}
                />

                <p className="font-mono text-xs text-on-surface-variant">
                  {utcTime(step.ts)}
                </p>

                <h3 className="mt-1 font-semibold text-on-surface">
                  {step.tactic || "Unknown tactic"}
                </h3>

                <p className="font-mono text-xs text-on-surface-variant">
                  {step.technique || "Technique unavailable"}
                </p>

                <p className="mt-2 text-sm text-on-surface">
                  {step.description || "No description available."}
                </p>

                {step.matched_routine === true && (
                  <div className="mt-2">
                    <Badge signal="info">
                      Matches admin routine
                    </Badge>
                  </div>
                )}

                {isRecovered && (
                 <div className="mt-2">
                    <Badge signal="warning">
                        Recovered earlier step
                    </Badge>
                </div>
                )}


                {isChainStop && (
                  <div className="mt-3 border border-error bg-surface-container-low p-3">
                    <Badge signal="critical">
                      Chain stops matching routine
                    </Badge>

                    <p className="mt-2 text-sm text-on-surface">
                      {chainStop?.reason || "Reason unavailable."}
                    </p>
                  </div>
                )}
              </li>
            )
          })}
        </ol>
      )}
    </Panel>
  )
}
