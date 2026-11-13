export type GraphNodeKind = "host" | "user" | "proc" | "plc" | "decoy"

export interface GraphNode {
  id: string
  kind: GraphNodeKind
  anchor: boolean
  decoy_hit: boolean
}

export interface GraphEdge {
  source: string
  target: string
  token: string
  ts: string
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/** Seconds into the 300 second safety simulation, and the tank level in percent. */
export interface TracePoint {
  t: number
  level: number
}

export interface Violation {
  rule_id: string
  detail: string
  ts: number
}

export interface IncidentAction {
  id: string
  kind: string
  target: string
  params: Record<string, unknown>
}

export interface ResponsePreview {
  action: IncidentAction
  before_trace: TracePoint[]
  after_trace: TracePoint[]
  violations: Violation[]
  safer_options: IncidentAction[]
  decision: "allow" | "downgrade" | "block"
  reason: string
}

export type Decision = "approve" | "reject"

export interface LedgerEntry {
  seq: number
  ts: string
  kind: string
  payload_hash: string
  prev_hash: string
  entry_hash: string
  signatures: {
    node: string
    sig: string
  }[]
}

export interface LedgerNode {
  node: string
  up: boolean
  head: string
  signatures: number
}

export interface LedgerVerifyError {
  seq: number
  reason: string
}

export interface LedgerVerify {
  ok: boolean
  checked: number
  errors: LedgerVerifyError[]
  /** The head hash each node reports, by node name. */
  heads: Record<string, string>
}

export interface Decoy {
  id: string
  type: string
  address: string
}

export interface DecoyHit {
  ts: string
  decoy: string
  source: string
}

export interface DecoyPlacement {
  host: string
  reason: string
  safety_ok: boolean
  decoy_type?: string
  address?: string
}

export interface DecoysData {
  decoys: Decoy[]
  hits: DecoyHit[]
  placements: DecoyPlacement[]
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

export interface Incident {
  id: string
  proposed_actions: IncidentAction[]
  signals: IncidentSignal[]
}