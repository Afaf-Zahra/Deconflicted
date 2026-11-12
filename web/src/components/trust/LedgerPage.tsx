import { useState } from "react"
import {
  CheckCircle2,
  Download,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
} from "lucide-react"
import { Badge } from "../primitives/Badge"
import { DataReadout } from "../primitives/DataReadout"
import { Panel } from "../primitives/Panel"
import {
  useLedger,
  useLedgerNodes,
  useLedgerVerify,
} from "./data"
import type { LedgerEntry } from "./types"

type LedgerPageProps = {
  incidentId: string
}

function formatTimestamp(value: string): string {
  return value.replace("T", " ")
}

function truncateHash(value: string): string {
  if (value.length <= 18) return value
  return `${value.slice(0, 9)}...${value.slice(-7)}`
}

function exportAuditJson(entries: LedgerEntry[]) {
  const blob = new Blob([JSON.stringify(entries, null, 2)], {
    type: "application/json",
  })

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = "deconflicted-audit.json"
  anchor.click()
  URL.revokeObjectURL(url)
}

export function LedgerPage({ incidentId }: LedgerPageProps) {
  const {
    data: entries,
    loading: entriesLoading,
    error: entriesError,
  } = useLedger()

  const {
    data: nodes,
    loading: nodesLoading,
    error: nodesError,
  } = useLedgerNodes()

  const {
    data: verification,
    loading: verificationLoading,
    error: verificationError,
  } = useLedgerVerify()

  const [exporting, setExporting] = useState(false)

  const loading =
    entriesLoading || nodesLoading || verificationLoading

  const error =
    entriesError || nodesError || verificationError

  async function handleExport() {
    if (!entries) return

    setExporting(true)

    try {
      exportAuditJson(entries)
    } finally {
      setExporting(false)
    }
  }

  if (loading) {
    return (
      <Panel
        title="Ledger"
        icon={<ShieldCheck size={14} />}
      >
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>Loading ledger...</DataReadout>
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel
        title="Ledger"
        icon={<ShieldCheck size={14} />}
      >
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <div className="text-center">
            <TriangleAlert
              className="mx-auto mb-2 text-error"
              size={20}
            />
            <DataReadout className="text-error">
              {error}
            </DataReadout>
          </div>
        </div>
      </Panel>
    )
  }

  if (!entries || entries.length === 0) {
    return (
      <Panel
        title="Ledger"
        icon={<ShieldCheck size={14} />}
      >
        <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
          <DataReadout dim>No ledger entries available.</DataReadout>
        </div>
      </Panel>
    )
  }

  return (
    <Panel
      title="Ledger"
      icon={<ShieldCheck size={14} />}
      aside={
        <div className="flex items-center gap-3">
          <DataReadout dim>
            incident {incidentId}
          </DataReadout>

          <button
            type="button"
            onClick={() => void handleExport()}
            disabled={exporting}
            className="flex items-center gap-1.5 border border-outline-variant bg-surface-container-low px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-wide text-primary transition-colors hover:bg-surface-container disabled:opacity-40"
          >
            <Download size={12} />
            {exporting ? "Exporting" : "Export audit JSON"}
          </button>
        </div>
      }
      bodyClassName="p-4"
    >
      <div className="space-y-4">
        <div
          className={`border-2 p-3 ${
            verification?.ok
              ? "border-secondary-fixed-dim bg-secondary-fixed-dim/10"
              : "border-error bg-error/10"
          }`}
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              {verification?.ok ? (
                <CheckCircle2
                  size={16}
                  className="text-secondary-fixed-dim"
                />
              ) : (
                <ShieldX
                  size={16}
                  className="text-error"
                />
              )}

              <div>
                <div className="text-[10px] uppercase tracking-wide text-on-surface-variant">
                  Ledger verification
                </div>

                <div className="mt-1">
                  <Badge
                    signal={verification?.ok ? "info" : "critical"}
                  >
                    {verification?.ok ? "verified" : "failed"}
                  </Badge>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <DataReadout dim>
                checked: {verification?.checked ?? 0}
              </DataReadout>

              <button
                type="button"
                disabled={verificationLoading}
                onClick={() => window.location.reload()}
                className="flex items-center gap-1.5 border border-outline-variant bg-surface-container-low px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-wide text-primary transition-colors hover:bg-surface-container disabled:opacity-40"
              >
                <RefreshCw size={12} />
                Verify
              </button>
            </div>
          </div>

          {!verification?.ok &&
            verification?.errors &&
            verification.errors.length > 0 && (
              <div className="mt-3 space-y-1 border-t border-error/40 pt-2">
                {verification.errors.map((item) => (
                  <div
                    key={`${item.seq}-${item.reason}`}
                    className="font-mono text-[10px] text-error"
                  >
                    seq {item.seq}: {item.reason}
                  </div>
                ))}
              </div>
            )}
        </div>

        <Panel title="Ledger Entries">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left font-mono text-[10px]">
              <thead>
                <tr className="border-b border-outline-variant text-on-surface-variant">
                  <th className="px-3 py-2 font-medium">seq</th>
                  <th className="px-3 py-2 font-medium">ts</th>
                  <th className="px-3 py-2 font-medium">kind</th>
                  <th className="px-3 py-2 font-medium">payload</th>
                  <th className="px-3 py-2 font-medium">prev</th>
                  <th className="px-3 py-2 font-medium">entry</th>
                  <th className="px-3 py-2 font-medium">signatures</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-outline-variant/40">
                {entries.map((entry) => (
                  <tr key={entry.seq}>
                    <td className="px-3 py-2 text-on-surface">
                      {entry.seq}
                    </td>

                    <td className="whitespace-nowrap px-3 py-2 text-on-surface-variant">
                      {formatTimestamp(entry.ts)}
                    </td>

                    <td className="px-3 py-2">
                      <Badge signal="info">{entry.kind}</Badge>
                    </td>

                    <td className="px-3 py-2 text-on-surface-variant">
                      {truncateHash(entry.payload_hash)}
                    </td>

                    <td className="px-3 py-2 text-on-surface-variant">
                      {truncateHash(entry.prev_hash)}
                    </td>

                    <td className="px-3 py-2 text-on-surface">
                      {truncateHash(entry.entry_hash)}
                    </td>

                    <td className="px-3 py-2 text-on-surface-variant">
                      {entry.signatures.length}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Ledger Nodes">
          {!nodes || nodes.length === 0 ? (
            <div className="p-3">
              <DataReadout dim>No ledger nodes available.</DataReadout>
            </div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {nodes.map((node) => (
                <div
                  key={node.node}
                  className="border border-outline-variant bg-surface-container-low p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <DataReadout className="text-xs">
                      {node.node}
                    </DataReadout>

                    <Badge signal={node.up ? "info" : "critical"}>
                      {node.up ? "up" : "down"}
                    </Badge>
                  </div>

                  <div className="mt-3 space-y-1.5">
                    <div className="flex justify-between gap-3">
                      <span className="text-[10px] text-on-surface-variant">
                        head
                      </span>

                      <DataReadout className="text-[10px]">
                        {truncateHash(node.head)}
                      </DataReadout>
                    </div>

                    <div className="flex justify-between gap-3">
                      <span className="text-[10px] text-on-surface-variant">
                        signatures
                      </span>

                      <DataReadout className="text-[10px]">
                        {node.signatures}
                      </DataReadout>
                    </div>
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