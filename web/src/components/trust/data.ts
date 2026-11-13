import { useEffect, useState } from "react"
import { API_BASE, API_MODE } from "../../lib/env"
import type {
  Decision,
  DecoysData,
  GraphData,
  Incident,
  IncidentAction,
  LedgerEntry,
  LedgerNode,
  LedgerVerify,
  ResponsePreview,
} from "./types"

/** The analysts listed in config/policy.yaml. The API refuses any other name. */
export const ANALYSTS = ["analyst-1", "analyst-2"] as const

export type DataState<T> = {
  data: T | null
  loading: boolean
  error: string | null
}

/** In mock mode the debug tamper button flips this, so verify then shows the tampered export. */
let mockTampered = false

/** An error that carries the reason the API gave (its "detail" field), not only the status code. */
async function failure(response: Response, what: string): Promise<Error> {
  let reason = ""
  try {
    const body = (await response.json()) as { detail?: unknown }
    if (typeof body.detail === "string") reason = `: ${body.detail}`
  } catch {
    // the body was not JSON; the status is enough
  }
  return new Error(`${what} failed (${response.status})${reason}`)
}

async function getMock<T>(file: string): Promise<T> {
  const response = await fetch(`/mock/${file}.json`)
  if (!response.ok) throw await failure(response, `Loading the mock ${file}`)
  return response.json() as Promise<T>
}

async function getLive<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`)
  if (!response.ok) throw await failure(response, `The request to ${path}`)
  return response.json() as Promise<T>
}

async function postLive<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw await failure(response, `The request to ${path}`)
  return response.json() as Promise<T>
}

function useData<T>(loader: () => Promise<T>, dependencies: unknown[] = []): DataState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true

    setLoading(true)
    setError(null)

    loader()
      .then((result) => {
        if (active) setData(result)
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : "Failed to load data")
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, dependencies)

  return { data, loading, error }
}

export function useGraph(incidentId: string): DataState<GraphData> {
  return useData(async () => {
    if (API_MODE === "mock") {
      const graphs = await getMock<Record<string, GraphData>>("graph")
      const graph = graphs[incidentId]
      if (!graph) throw new Error(`Graph not found for incident ${incidentId}`)
      return graph
    }
    return getLive<GraphData>(`/incidents/${incidentId}/graph`)
  }, [incidentId])
}

export function useIncident(incidentId: string): DataState<Incident> {
  return useData(async () => {
    if (API_MODE === "mock") {
      const incidents = await getMock<Incident[]>("incidents")
      const incident = incidents.find((item) => item.id === incidentId)
      if (!incident) throw new Error(`Incident not found: ${incidentId}`)
      return incident
    }
    return getLive<Incident>(`/incidents/${incidentId}`)
  }, [incidentId])
}

/** Ask the safety guard about one action. The API wants the incident id and the whole action. */
export async function previewResponse(incidentId: string, action: IncidentAction): Promise<ResponsePreview> {
  if (API_MODE === "mock") return getMock<ResponsePreview>("preview")
  return postLive<ResponsePreview>("/response/preview", { incident_id: incidentId, action })
}

/** Approve or reject an action. The API signs the decision into the ledger and returns the entry. */
export async function decide(actionId: string, analyst: string, decision: Decision): Promise<{ seq: number | null }> {
  if (API_MODE === "mock") return { seq: null }
  const entry = await postLive<{ seq: number }>(`/response/${encodeURIComponent(actionId)}/${decision}`, { analyst })
  return { seq: entry.seq }
}

export function useLedger(): DataState<LedgerEntry[]> {
  return useData(() => (API_MODE === "mock" ? getMock<LedgerEntry[]>("ledger") : getLive<LedgerEntry[]>("/ledger")), [])
}

export function useLedgerVerify(): DataState<LedgerVerify> {
  return useData(() => fetchVerify(), [])
}

/** Verify the ledger now. The Verify button calls this again instead of reloading the page. */
export async function fetchVerify(): Promise<LedgerVerify> {
  if (API_MODE === "mock") return getMock<LedgerVerify>(mockTampered ? "verify_tampered" : "verify")
  return getLive<LedgerVerify>("/ledger/verify")
}

/** The whole ledger with payloads and signatures, the file `python -m deconflicted.ledger.verify_cli` checks. */
export async function fetchAudit(): Promise<unknown> {
  if (API_MODE === "mock") return getMock<unknown>("audit")
  return getLive<unknown>("/audit/export")
}

/** Debug only: change one stored payload so that verify fails. The API needs DECONFLICTED_DEBUG=1. */
export async function tamperLedger(): Promise<{ tampered_seq: number }> {
  if (API_MODE === "mock") {
    mockTampered = true
    return { tampered_seq: 4 }
  }
  return postLive<{ tampered_seq: number }>("/debug/tamper", {})
}

export function useLedgerNodes(): DataState<LedgerNode[]> {
  return useData(() => (API_MODE === "mock" ? getMock<LedgerNode[]>("nodes") : getLive<LedgerNode[]>("/ledger/nodes")), [])
}

/** The decoys, their hits and the Trail Ahead placements. With an incident, placements follow its hosts. */
export function useDecoys(incidentId?: string): DataState<DecoysData> {
  return useData(() => {
    if (API_MODE === "mock") return getMock<DecoysData>("decoys")
    const query = incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : ""
    return getLive<DecoysData>(`/decoys${query}`)
  }, [incidentId])
}