import { useEffect, useMemo, useRef, useState } from "react"
import ForceGraph2D from "react-force-graph-2d"
import {
  AlertTriangle,
  Crosshair,
  Network,
  ZoomIn,
  ZoomOut,
} from "lucide-react"
import { Panel } from "../primitives/Panel"
import { Badge } from "../primitives/Badge"
import { DataReadout } from "../primitives/DataReadout"
import { useGraph, useIncident } from "./data"
import type { GraphNode, IncidentSignal } from "./types"
import { SIGNAL_HEX, type Signal } from "../../lib/severity"

type GraphPageProps = {
  incidentId: string
}

type GraphPoint = GraphNode & {
  x?: number
  y?: number
  vx?: number
  vy?: number
}

function nodeSignal(node: GraphNode): Signal {
  if (node.decoy_hit) return "critical"
  if (node.anchor) return "warning"
  return "info"
}

function nodeLabel(node: GraphNode) {
  switch (node.kind) {
    case "host":
      return "HOST"
    case "user":
      return "USER"
    case "proc":
      return "PROC"
    case "plc":
      return "PLC"
    case "decoy":
      return "DECOY"
  }
}

function cssVariable(name: string) {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim()
}

/** The incident's signals that name this node (their entity ids include it). */
function signalsFor(signals: IncidentSignal[] | undefined, nodeId: string): IncidentSignal[] {
  return (signals ?? []).filter((signal) => signal.entity_ids.includes(nodeId))
}

function signalNote(signal: IncidentSignal): string {
  const detail = signal.detail
  const note = detail.note ?? detail.rule ?? detail.decoy
  return typeof note === "string" ? note : ""
}

export function TopologyGraph({ incidentId }: GraphPageProps) {
  const { data, loading, error } = useGraph(incidentId)
  const { data: incident } = useIncident(incidentId)
  const graphRef = useRef<any>(null)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  const graphData = useMemo(() => {
    if (!data) {
      return { nodes: [], links: [] }
    }

    return {
      nodes: data.nodes.map((node) => ({ ...node })),
      links: data.edges.map((edge) => ({
        source: edge.source,
        target: edge.target,
        token: edge.token,
        ts: edge.ts,
      })),
    }
  }, [data])

  useEffect(() => {
    if (!selectedNode || !data) return

    const updated = data.nodes.find((node) => node.id === selectedNode.id)

    if (!updated) {
      setSelectedNode(null)
    }
  }, [data, selectedNode])

  if (loading) {
    return (
      <Panel title="Incident Graph" icon={<Network size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>Loading incident graph...</DataReadout>
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="Incident Graph" icon={<Network size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <div className="text-center">
            <AlertTriangle className="mx-auto mb-2 text-error" size={20} />
            <DataReadout className="text-error">{error}</DataReadout>
          </div>
        </div>
      </Panel>
    )
  }

  if (!data || data.nodes.length === 0) {
    return (
      <Panel title="Incident Graph" icon={<Network size={14} />}>
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>No graph data available.</DataReadout>
        </div>
      </Panel>
    )
  }

  return (
    <Panel
      title="Incident Graph"
      icon={<Network size={14} />}
      aside={
        <div className="flex items-center gap-3">
          <DataReadout dim>{data.nodes.length} nodes</DataReadout>
          <DataReadout dim>{data.edges.length} edges</DataReadout>
        </div>
      }
      bodyClassName="relative"
    >
      <div className="relative min-h-[520px] overflow-hidden">
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel={(node) => {
            const item = node as GraphPoint
            return `${nodeLabel(item)}: ${item.id}`
          }}
          linkLabel={(link) => {
            const item = link as { token: string; ts: string }
            return `${item.token} · ${item.ts}`
          }}
          onNodeClick={(node) => {
            setSelectedNode(node as GraphNode)
          }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const item = node as GraphPoint
            const x = item.x ?? 0
            const y = item.y ?? 0
            const radius = item.decoy_hit || item.anchor ? 7 : 5
            const signal = nodeSignal(item)

            const onSurface = cssVariable("--color-on-surface")

            ctx.beginPath()
            ctx.arc(x, y, radius, 0, 2 * Math.PI)
            ctx.fillStyle = SIGNAL_HEX[signal]
            ctx.fill()

            if (item.anchor) {
              ctx.beginPath()
              ctx.arc(x, y, radius + 4, 0, 2 * Math.PI)
              ctx.strokeStyle = SIGNAL_HEX.warning
              ctx.lineWidth = 1.5
              ctx.stroke()
            }

            if (item.decoy_hit) {
              ctx.beginPath()
              ctx.arc(x, y, radius + 6, 0, 2 * Math.PI)
              ctx.strokeStyle = SIGNAL_HEX.critical
              ctx.lineWidth = 1
              ctx.stroke()
            }

            const label = item.id
            const fontSize = Math.max(8, 11 / globalScale)

            ctx.font = `${fontSize}px monospace`
            ctx.fillStyle = onSurface
            ctx.textAlign = "left"
            ctx.textBaseline = "middle"
            ctx.fillText(label, x + radius + 5, y)
          }}
          linkCanvasObject={(link, ctx) => {
            const source = link.source as GraphPoint
            const target = link.target as GraphPoint

            if (
              typeof source.x !== "number" ||
              typeof source.y !== "number" ||
              typeof target.x !== "number" ||
              typeof target.y !== "number"
            ) {
              return
            }

            ctx.beginPath()
            ctx.moveTo(source.x, source.y)
            ctx.lineTo(target.x, target.y)

            ctx.strokeStyle = cssVariable("--color-outline-variant")
            ctx.lineWidth = 1
            ctx.stroke()
          }}
          cooldownTicks={80}
          d3AlphaDecay={0.04}
          d3VelocityDecay={0.3}
          onEngineStop={() => {
            graphRef.current?.zoomToFit(500, 40)
          }}
          onEngineTick={() => {
            // ForceGraph2D handles simulation updates internally.
          }}
          width={undefined}
          height={520}
        />

        <div className="absolute left-3 top-3 flex items-center gap-2">
          <Badge signal="info">Graph</Badge>

          <Badge signal="warning">
            <Crosshair size={10} />
            Anchor
          </Badge>

          <Badge signal="critical">
            <AlertTriangle size={10} />
            Decoy hit
          </Badge>
        </div>

        <div className="absolute bottom-3 right-3 flex gap-1">
          <button
            type="button"
            aria-label="Zoom in"
            className="border border-outline-variant bg-surface-container-low px-2 py-1 text-primary hover:bg-surface-container"
            onClick={() =>
              graphRef.current?.zoom(graphRef.current.zoom() * 1.2, 300)
            }
          >
            <ZoomIn size={14} />
          </button>

          <button
            type="button"
            aria-label="Zoom out"
            className="border border-outline-variant bg-surface-container-low px-2 py-1 text-primary hover:bg-surface-container"
            onClick={() =>
              graphRef.current?.zoom(graphRef.current.zoom() * 0.8, 300)
            }
          >
            <ZoomOut size={14} />
          </button>
        </div>

        {selectedNode && (
          <div className="absolute right-3 top-3 w-72">
            <Panel
              title="Selected Node"
              icon={<Crosshair size={14} />}
              aside={
                <Badge signal={nodeSignal(selectedNode)}>
                  {nodeLabel(selectedNode)}
                </Badge>
              }
            >
              <div className="space-y-3 p-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                    Node
                  </div>

                  <DataReadout className="break-all text-xs">
                    {selectedNode.id}
                  </DataReadout>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                      Anchor
                    </div>

                    <Badge signal={selectedNode.anchor ? "warning" : "info"}>
                      {selectedNode.anchor ? "YES" : "NO"}
                    </Badge>
                  </div>

                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                      Decoy hit
                    </div>

                    <Badge
                      signal={selectedNode.decoy_hit ? "critical" : "info"}
                    >
                      {selectedNode.decoy_hit ? "YES" : "NO"}
                    </Badge>
                  </div>
                </div>

                <div>
                  <div className="mb-1 text-[10px] uppercase tracking-wide text-on-surface-variant">
                    Signals
                  </div>

                  {signalsFor(incident?.signals, selectedNode.id).length === 0 ? (
                    <DataReadout dim className="text-xs">
                      No signal names this node
                    </DataReadout>
                  ) : (
                    <ul className="max-h-40 space-y-1.5 overflow-y-auto">
                      {signalsFor(incident?.signals, selectedNode.id).map((signal) => (
                        <li key={signal.id} className="border-l-2 border-outline-variant pl-2">
                          <div className="font-mono text-[10px] font-semibold text-on-surface">
                            {`${signal.kind} · ${signal.score.toFixed(4)}`}
                          </div>
                          <div className="font-mono text-[9px] text-on-surface-variant">
                            {`${signal.ts.slice(11, 19)} UTC ${signalNote(signal)}`.trim()}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </Panel>
          </div>
        )}
      </div>
    </Panel>
  )
}