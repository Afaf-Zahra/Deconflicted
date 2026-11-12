import { TopologyGraph } from "../../components/trust/TopologyGraph"
import { ResponsePage as ResponseTrustPage } from "../../components/trust/ResponsePage"
import { LedgerPage as LedgerTrustPage } from "../../components/trust/LedgerPage"
import { DecoysPage as DecoysTrustPage } from "../../components/trust/DecoysPage"

export interface TrustPageProps {
  incidentId: string | null
}

export function GraphPage({ incidentId }: TrustPageProps) {
  if (!incidentId) return null
  return <TopologyGraph incidentId={incidentId} />
}

export function ResponsePage({ incidentId }: TrustPageProps) {
  if (!incidentId) return null
  return <ResponseTrustPage incidentId={incidentId} />
}

export function LedgerPage({ incidentId }: TrustPageProps) {
  if (!incidentId) return null
  return <LedgerTrustPage incidentId={incidentId} />
}

export function DecoysPage({ incidentId }: TrustPageProps) {
  if (!incidentId) return null
  return <DecoysTrustPage incidentId={incidentId} />
}
