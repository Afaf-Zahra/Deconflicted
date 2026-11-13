import { API_BASE } from "../../lib/env"
import { useEffect, useState } from "react"
import type {
  Incident,
  EvidenceEvent,
  Budget,
} from "./types"

export type AnalystData = {
  incidents: Incident[]
  events: EvidenceEvent[]
  budget: Budget | null
}

type AnalystDataState = {
  data: AnalystData
  loading: boolean
  error: string | null
  updatedAt: number | null
}

const EMPTY_DATA: AnalystData = {
  incidents: [],
  events: [],
  budget: null,
}

const POLL_INTERVAL_MS = 2000

function apiMode(): "mock" | "live" {
  return import.meta.env.VITE_API === "live" ? "live" : "mock"
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url)

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`)
  }

  return response.json() as Promise<T>
}

async function loadAnalystData(): Promise<AnalystData> {
  if (apiMode() === "mock") {
    const [incidents, events, budget] = await Promise.all([
      fetchJson<Incident[]>("/mock/incidents.json"),
      fetchJson<EvidenceEvent[]>("/mock/events.json"),
      fetchJson<Budget>("/mock/budget.json"),
    ])

    return { incidents, events, budget }
  }

  const incidents = await fetchJson<Incident[]>(`${API_BASE}/incidents`)
  const budget = await fetchJson<Budget>(`${API_BASE}/budget`)

  const eventIds = [
    ...new Set(
      incidents.flatMap((incident) =>
        incident.signals.flatMap((signal) => signal.event_ids),
      ),
    ),
  ]

  const events =
    eventIds.length > 0
      ? await fetchJson<EvidenceEvent[]>(
          `${API_BASE}/events?ids=${encodeURIComponent(eventIds.join(","))}`,
        )
      : []

  return { incidents, events, budget }
}

export function useAnalystData(): AnalystDataState {
  const [state, setState] = useState<AnalystDataState>({
    data: EMPTY_DATA,
    loading: true,
    error: null,
    updatedAt: null,
  })

  useEffect(() => {
    let active = true
    let refreshing = false
    async function refresh() {
        if (!active || refreshing) return

        refreshing = true
        try {
            const data = await loadAnalystData()

        if (!active) return

        setState({
          data,
          loading: false,
          error: null,
          updatedAt: Date.now(),
        })
      
      } catch (error) {
        if (!active) return

        setState((previous) => ({
          ...previous,
          loading: false,
          error:
            error instanceof Error
              ? error.message
              : "Unable to load analyst data.",
        }))
      } finally {
        refreshing = false
      }
    }


    void refresh()

    const interval = window.setInterval(() => {
      void refresh()
    }, POLL_INTERVAL_MS)

    return () => {
      active = false
      window.clearInterval(interval)
    }
  }, [])

  return state
}

