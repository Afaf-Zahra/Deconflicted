import { useMemo, useState } from "react"
import {
  AlertTriangle,
  Check,
  ChevronRight,
  ShieldAlert,
  X,
} from "lucide-react"
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { Badge } from "../primitives/Badge"
import { DataReadout } from "../primitives/DataReadout"
import { Panel } from "../primitives/Panel"
import { previewResponse, useIncident } from "./data"
import type {
  IncidentAction,
  ResponsePreview,
  TracePoint,
} from "./types"

type ResponsePageProps = {
  incidentId: string
}

type ActionStatus = "idle" | "loading" | "error"

function actionLabel(action: IncidentAction): string {
  switch (action.kind) {
    case "isolate_host":
      return `Isolate host: ${action.target}`
    case "block_write":
      return `Block write: ${action.target}`
    case "disable_account":
      return `Disable account: ${action.target}`
    default:
      return `${action.kind}: ${action.target}`
  }
}

function decisionSignal(
  decision: ResponsePreview["decision"],
): "info" | "warning" | "critical" {
  if (decision === "allow") return "info"
  if (decision === "downgrade") return "warning"
  return "critical"
}

function buildChartRows(
  beforeTrace: TracePoint[],
  afterTrace: TracePoint[],
) {
  const length = Math.max(beforeTrace.length, afterTrace.length)

  return Array.from({ length }, (_, index) => ({
    t: beforeTrace[index]?.t ?? afterTrace[index]?.t ?? String(index),
    before: beforeTrace[index]?.level ?? null,
    after: afterTrace[index]?.level ?? null,
  }))
}

export function ResponsePage({ incidentId }: ResponsePageProps) {
  const { data: incident, loading, error } = useIncident(incidentId)

  const [selectedActionId, setSelectedActionId] = useState<string | null>(null)
  const [preview, setPreview] = useState<ResponsePreview | null>(null)
  const [status, setStatus] = useState<ActionStatus>("idle")
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [analyst, setAnalyst] = useState("")
  const [decisionStatus, setDecisionStatus] = useState<
    "idle" | "submitting" | "success" | "error"
  >("idle")
  const [decisionError, setDecisionError] = useState<string | null>(null)

  const selectedAction = useMemo(() => {
    if (!incident || !selectedActionId) return null

    return (
      incident.proposed_actions.find(
        (action) => action.id === selectedActionId,
      ) ?? null
    )
  }, [incident, selectedActionId])

  const chartRows = useMemo(() => {
    if (!preview) return []

    return buildChartRows(preview.before_trace, preview.after_trace)
  }, [preview])

  async function selectAction(action: IncidentAction) {
    setSelectedActionId(action.id)
    setPreview(null)
    setPreviewError(null)
    setStatus("loading")
    setDecisionStatus("idle")
    setDecisionError(null)

    try {
      const result = await previewResponse(action.id)
      setPreview(result)
      setStatus("idle")
    } catch (err) {
      setStatus("error")
      setPreviewError(
        err instanceof Error ? err.message : "Failed to load response preview",
      )
    }
  }

  async function submitDecision(
    decision: "approve" | "reject",
  ) {
    if (!selectedAction || !analyst || !preview) return

    setDecisionStatus("submitting")
    setDecisionError(null)

    try {
      const endpoint =
        decision === "approve"
          ? `/response/${selectedAction.id}/approve`
          : `/response/${selectedAction.id}/reject`

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          analyst,
        }),
      })

      if (!response.ok) {
        throw new Error(`Response request failed: ${response.status}`)
      }

      setDecisionStatus("success")
    } catch (err) {
      setDecisionStatus("error")
      setDecisionError(
        err instanceof Error ? err.message : "Failed to submit response",
      )
    }
  }

  if (loading) {
    return (
      <Panel title="Response Preview" icon={<ShieldAlert size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>Loading incident actions...</DataReadout>
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="Response Preview" icon={<ShieldAlert size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <div className="text-center">
            <AlertTriangle className="mx-auto mb-2 text-error" size={20} />
            <DataReadout className="text-error">{error}</DataReadout>
          </div>
        </div>
      </Panel>
    )
  }

  if (!incident || incident.proposed_actions.length === 0) {
    return (
      <Panel title="Response Preview" icon={<ShieldAlert size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>
            No proposed response actions available.
          </DataReadout>
        </div>
      </Panel>
    )
  }

  return (
    <Panel
      title="Response Preview"
      icon={<ShieldAlert size={14} />}
      aside={
        <DataReadout dim>
          {incident.proposed_actions.length} proposed actions
        </DataReadout>
      }
      bodyClassName="p-4"
    >
      <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
        <div className="space-y-3">
          <div>
            <div className="mb-2 text-[10px] uppercase tracking-wide text-on-surface-variant">
              Proposed actions
            </div>

            <div className="space-y-1.5">
              {incident.proposed_actions.map((action) => {
                const selected = action.id === selectedActionId

                return (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => void selectAction(action)}
                    className={`flex w-full items-center justify-between gap-2 border px-3 py-2 text-left transition-colors ${
                      selected
                        ? "border-primary-container bg-surface-container"
                        : "border-outline-variant bg-surface-container-low hover:bg-surface-container"
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-[11px] font-semibold text-on-surface">
                        {actionLabel(action)}
                      </div>

                      <div className="mt-1 font-mono text-[10px] text-on-surface-variant">
                        {action.id}
                      </div>
                    </div>

                    <ChevronRight
                      size={14}
                      className={
                        selected
                          ? "shrink-0 text-primary"
                          : "shrink-0 text-on-surface-variant"
                      }
                    />
                  </button>
                )
              })}
            </div>
          </div>

          {selectedAction && (
            <div className="border-t border-outline-variant pt-3">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-on-surface-variant">
                Target
              </div>

              <DataReadout className="break-all text-xs">
                {selectedAction.target}
              </DataReadout>
            </div>
          )}
        </div>

        <div className="min-w-0">
          {!selectedAction && (
            <div className="flex min-h-[360px] items-center justify-center border border-outline-variant">
              <DataReadout dim>
                Select an action to generate its response preview.
              </DataReadout>
            </div>
          )}

          {status === "loading" && (
            <div className="flex min-h-[360px] items-center justify-center border border-outline-variant">
              <DataReadout dim>
                Loading response preview...
              </DataReadout>
            </div>
          )}

          {status === "error" && (
            <div className="flex min-h-[360px] items-center justify-center border border-outline-variant">
              <div className="text-center">
                <AlertTriangle
                  className="mx-auto mb-2 text-error"
                  size={20}
                />
                <DataReadout className="text-error">
                  {previewError}
                </DataReadout>
              </div>
            </div>
          )}

          {preview && status !== "loading" && (
            <div className="space-y-4">
              <div
                className={`border-2 p-3 ${
                  preview.decision === "allow"
                    ? "border-secondary-fixed-dim bg-secondary-fixed-dim/10"
                    : preview.decision === "downgrade"
                      ? "border-warning bg-warning/10"
                      : "border-error bg-error/10"
                }`}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                      Decision
                    </div>

                    <div className="mt-1">
                      <Badge signal={decisionSignal(preview.decision)}>
                        {preview.decision}
                      </Badge>
                    </div>
                  </div>

                  <div className="sm:max-w-[70%]">
                    <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                      Reason
                    </div>

                    <div className="mt-1 font-mono text-[11px] leading-relaxed text-on-surface">
                      {preview.reason || "No reason provided."}
                    </div>
                  </div>
                </div>
              </div>

              <Panel title="Before / After Trace">
                <div className="h-56 p-2">
                  {chartRows.length === 0 ? (
                    <div className="flex h-full items-center justify-center">
                      <DataReadout dim>No trace data available.</DataReadout>
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart
                        data={chartRows}
                        margin={{
                          top: 8,
                          right: 16,
                          bottom: 8,
                          left: 4,
                        }}
                      >
                        <CartesianGrid
                          stroke="var(--color-outline-variant)"
                          strokeDasharray="1 6"
                          vertical={false}
                        />

                        <XAxis
                          dataKey="t"
                          tick={{
                            fill: "var(--color-on-surface-variant)",
                            fontFamily: "monospace",
                            fontSize: 10,
                          }}
                          axisLine={{
                            stroke: "var(--color-outline-variant)",
                          }}
                          tickLine={{
                            stroke: "var(--color-outline-variant)",
                          }}
                        />

                        <YAxis
                          domain={[0, 1]}
                          tick={{
                            fill: "var(--color-on-surface-variant)",
                            fontFamily: "monospace",
                            fontSize: 10,
                          }}
                          axisLine={{
                            stroke: "var(--color-outline-variant)",
                          }}
                          tickLine={{
                            stroke: "var(--color-outline-variant)",
                          }}
                          width={36}
                        />

                        <Tooltip
                          contentStyle={{
                            background: "var(--color-surface)",
                            border:
                              "1px solid var(--color-outline-variant)",
                            fontFamily: "monospace",
                            fontSize: 11,
                          }}
                          labelStyle={{
                            color: "var(--color-on-surface-variant)",
                          }}
                        />

                        <ReferenceLine
                          y={0}
                          stroke="var(--color-outline-variant)"
                          strokeDasharray="2 4"
                        />

                        <ReferenceLine
                          y={1}
                          stroke="var(--color-outline-variant)"
                          strokeDasharray="2 4"
                        />

                        <Line
                          type="monotone"
                          dataKey="before"
                          name="before"
                          stroke="var(--color-warning)"
                          strokeWidth={2}
                          dot={false}
                          connectNulls
                          isAnimationActive={false}
                        />

                        <Line
                          type="monotone"
                          dataKey="after"
                          name="after"
                          stroke="var(--color-primary-container)"
                          strokeWidth={2}
                          strokeDasharray="5 4"
                          dot={false}
                          connectNulls
                          isAnimationActive={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </Panel>

              <div className="grid gap-4 lg:grid-cols-2">
                <Panel title="Violations">
                  {preview.violations.length === 0 ? (
                    <div className="p-3">
                      <DataReadout dim>No violations reported.</DataReadout>
                    </div>
                  ) : (
                    <div className="space-y-2 p-3">
                      {preview.violations.map((violation) => (
                        <div
                          key={`${violation.rule_id}-${violation.ts}`}
                          className="border-l-2 border-error pl-2.5"
                        >
                          <div className="font-mono text-[10px] font-semibold text-error">
                            {violation.rule_id}
                          </div>

                          <div className="mt-1 font-mono text-[10px] leading-relaxed text-on-surface-variant">
                            {violation.detail}
                          </div>

                          <div className="mt-1 font-mono text-[9px] text-on-surface-variant">
                            {violation.ts}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                <Panel title="Safer Options">
                  {preview.safer_options.length === 0 ? (
                    <div className="p-3">
                      <DataReadout dim>
                        No safer options provided.
                      </DataReadout>
                    </div>
                  ) : (
                    <div className="space-y-2 p-3">
                      {preview.safer_options.map((option) => (
                        <div
                          key={option}
                          className="border border-outline-variant bg-surface-container-low p-2.5"
                        >
                          <div className="flex items-start gap-2">
                            <Check
                              size={13}
                              className="mt-0.5 shrink-0 text-secondary-fixed-dim"
                            />

                            <span className="font-mono text-[10px] leading-relaxed text-on-surface">
                              {option}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>

              <Panel title="Response Decision">
                <div className="space-y-3 p-3">
                  <label className="flex flex-col gap-1">
                    <span className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                      Analyst
                    </span>

                    <select
                      value={analyst}
                      onChange={(event) => {
                        setAnalyst(event.target.value)
                        setDecisionStatus("idle")
                        setDecisionError(null)
                      }}
                      className="border border-outline-variant bg-surface-container-lowest px-2 py-1.5 font-mono text-[11px] text-primary focus:border-primary-container focus:outline-none"
                    >
                      <option value="">Select analyst</option>
                      <option value="analyst">Analyst</option>
                    </select>
                  </label>

                  {decisionStatus === "error" && (
                    <div className="flex items-center gap-2 font-mono text-[10px] text-error">
                      <AlertTriangle size={12} />
                      {decisionError}
                    </div>
                  )}

                  {decisionStatus === "success" && (
                    <div className="flex items-center gap-2 font-mono text-[10px] text-secondary-fixed-dim">
                      <Check size={12} />
                      Response decision submitted.
                    </div>
                  )}

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={
                        !analyst ||
                        preview.decision === "block" ||
                        decisionStatus === "submitting"
                      }
                      onClick={() => void submitDecision("approve")}
                      className="flex items-center gap-1.5 bg-primary-container px-3 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wide text-surface-container-lowest transition-opacity hover:opacity-90 disabled:opacity-40"
                    >
                      <Check size={12} />
                      Approve
                    </button>

                    <button
                      type="button"
                      disabled={
                        !analyst || decisionStatus === "submitting"
                      }
                      onClick={() => void submitDecision("reject")}
                      className="flex items-center gap-1.5 border border-outline-variant bg-surface-container-low px-3 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wide text-primary transition-colors hover:bg-surface-container disabled:opacity-40"
                    >
                      <X size={12} />
                      Reject
                    </button>
                  </div>

                  {preview.decision === "block" && (
                    <div className="flex items-center gap-2 border-l-2 border-error pl-2.5 font-mono text-[10px] text-error">
                      <AlertTriangle size={12} />
                      Approval is disabled because the decision is block.
                    </div>
                  )}
                </div>
              </Panel>
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}