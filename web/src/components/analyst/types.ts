
export interface ChainStep {
  ts: string
  tactic: string
  technique: string
  description: string
  signal_id: string
  matched_routine: boolean
}

export interface IncidentSignal {
  id: string
  ts: string
  entity_ids: string[]
  kind: string
  score: number
  event_ids: string[]
  techniques: string[]
  detail: Record<string, unknown>
}

export interface ProposedAction {
  id: string
  kind: string
  target: string
  params: Record<string, unknown>
}

export interface Incident {
  id: string
  title?: string
  status: string
  severity: string
  first_event_ts: string
  first_alert_ts?: string
  chain: ChainStep[]
  signals: IncidentSignal[]
  entities: string[]
  promoted_held_signal_ids: string[]
  chain_stop?: {
    index: number
    reason: string
  }
  proposed_actions: ProposedAction[]
}

export interface EvidenceEvent {
  id: string
  ts: string
  source: string
  host?: string
  user?: string
  process?: string
  cmdline?: string
  src_ip?: string
  dst_ip?: string
  dst_port?: number
  action?: string
  obj?: string
  value?: number
  raw?: unknown
}

export interface Budget {
  budget: number
  used: number
  window_hours: number
}

