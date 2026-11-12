import { AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react"
import { Badge } from "../primitives/Badge"
import { DataReadout } from "../primitives/DataReadout"
import { Panel } from "../primitives/Panel"
import { useDecoys } from "./data"
import type { DecoyPlacement } from "./types"

type DecoysPageProps = {
  incidentId: string
}

function placementSignal(
  placement: DecoyPlacement,
): "info" | "warning" | "critical" {
  return placement.safety_ok ? "info" : "critical"
}

export function DecoysPage({ incidentId }: DecoysPageProps) {
  const { data, loading, error } = useDecoys()

  if (loading) {
    return (
      <Panel title="Decoys" icon={<ShieldCheck size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>Loading decoy data...</DataReadout>
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="Decoys" icon={<ShieldCheck size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <div className="text-center">
            <AlertTriangle className="mx-auto mb-2 text-error" size={20} />
            <DataReadout className="text-error">{error}</DataReadout>
          </div>
        </div>
      </Panel>
    )
  }

  if (!data) {
    return (
      <Panel title="Decoys" icon={<ShieldCheck size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>No decoy data available.</DataReadout>
        </div>
      </Panel>
    )
  }

  return (
    <Panel
      title="Decoys"
      icon={<ShieldCheck size={14} />}
      aside={
        <DataReadout dim>
          incident {incidentId}
        </DataReadout>
      }
      bodyClassName="p-4"
    >
      <div className="space-y-4">
        <Panel
          title="Decoy Inventory"
          aside={
            <DataReadout dim>
              {data.decoys.length} decoys
            </DataReadout>
          }
        >
          {data.decoys.length === 0 ? (
            <div className="p-3">
              <DataReadout dim>No decoys configured.</DataReadout>
            </div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {data.decoys.map((decoy) => (
                <div
                  key={decoy.id}
                  className="border border-outline-variant bg-surface-container-low p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <DataReadout className="text-xs">
                      {decoy.id}
                    </DataReadout>

                    <Badge signal="info">{decoy.type}</Badge>
                  </div>

                  <div className="mt-3 flex justify-between gap-3">
                    <span className="text-[10px] text-on-surface-variant">
                      address
                    </span>

                    <DataReadout className="text-[10px]">
                      {decoy.address}
                    </DataReadout>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Decoy Hits"
          aside={
            <DataReadout dim>
              {data.hits.length} hits
            </DataReadout>
          }
        >
          {data.hits.length === 0 ? (
            <div className="p-3">
              <DataReadout dim>No decoy hits recorded.</DataReadout>
            </div>
          ) : (
            <div className="divide-y divide-outline-variant">
              {data.hits.map((hit, index) => (
                <div
                  key={`${hit.ts}-${hit.decoy}-${hit.source}-${index}`}
                  className="grid gap-2 p-3 sm:grid-cols-[180px_1fr_1fr] sm:items-center"
                >
                  <DataReadout className="text-[10px]">
                    {hit.ts}
                  </DataReadout>

                  <div>
                    <div className="text-[9px] uppercase tracking-wide text-on-surface-variant">
                      decoy
                    </div>

                    <DataReadout className="text-[10px]">
                      {hit.decoy}
                    </DataReadout>
                  </div>

                  <div>
                    <div className="text-[9px] uppercase tracking-wide text-on-surface-variant">
                      source
                    </div>

                    <DataReadout className="text-[10px]">
                      {hit.source}
                    </DataReadout>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Trail Ahead Placements"
          aside={
            <DataReadout dim>
              {data.placements.length} proposed
            </DataReadout>
          }
        >
          {data.placements.length === 0 ? (
            <div className="p-3">
              <DataReadout dim>
                No Trail Ahead placements proposed.
              </DataReadout>
            </div>
          ) : (
            <div className="space-y-2 p-3">
              {data.placements.map((placement) => (
                <div
                  key={`${placement.host}-${placement.reason}`}
                  className="border border-outline-variant bg-surface-container-low p-3"
                >
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <div className="text-[9px] uppercase tracking-wide text-on-surface-variant">
                        proposed host
                      </div>

                      <DataReadout className="text-xs">
                        {placement.host}
                      </DataReadout>

                      <div className="mt-2 text-[9px] uppercase tracking-wide text-on-surface-variant">
                        reason
                      </div>

                      <div className="mt-1 font-mono text-[10px] leading-relaxed text-on-surface">
                        {placement.reason}
                      </div>
                    </div>

                    <Badge signal={placementSignal(placement)}>
                      {placement.safety_ok ? "safe" : "unsafe"}
                    </Badge>
                  </div>

                  <div className="mt-3 flex items-center gap-2 border-t border-outline-variant pt-2">
                    {placement.safety_ok ? (
                      <CheckCircle2
                        size={13}
                        className="text-secondary-fixed-dim"
                      />
                    ) : (
                      <AlertTriangle size={13} className="text-error" />
                    )}

                    <span className="font-mono text-[10px] text-on-surface-variant">
                      {placement.safety_ok
                        ? "Safety check passed"
                        : "Safety check failed"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </Panel>
  )
}