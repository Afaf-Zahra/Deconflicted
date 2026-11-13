import { API_BASE } from "../../lib/env"

export type DemoStatus = {
  enabled: boolean
  running: boolean
  sent: number
  total: number
  speed: number
  error: string | null
}

export type IngestAnswer = { accepted: number; errors: { index: number; error: string }[]; incidents: number }
export type IncidentRow = { id: string; severity: string; title: string }

const JSON_HEADERS = { "Content-Type": "application/json" }

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init)
  if (!response.ok) {
    let reason = ""
    try {
      const body = (await response.json()) as { detail?: unknown }
      if (typeof body.detail === "string") reason = `: ${body.detail}`
    } catch {
      // the body was not JSON; the status is enough
    }
    throw new Error(`${path} failed (${response.status})${reason}`)
  }
  return response.json() as Promise<T>
}

export const demoStatus = () => call<DemoStatus>("/demo/status")

export const startAttack = (speed: number) =>
  call<DemoStatus>("/demo/attack", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ speed }) })

export const resetDemo = () => call<DemoStatus>("/demo/reset", { method: "POST" })

export const sendJson = (body: unknown, source?: string) =>
  call<IngestAnswer>(`/ingest/json${source ? `?source=${encodeURIComponent(source)}` : ""}`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  })

export const sendRaw = (source: string, raw: string) =>
  call<IngestAnswer>("/ingest", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ events: [{ source, raw }] }) })

export async function listIncidents(): Promise<IncidentRow[]> {
  const rows = await call<IncidentRow[]>("/incidents")
  return rows.map(({ id, severity, title }) => ({ id, severity, title }))
}