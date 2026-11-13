import { Network, ShieldAlert } from "lucide-react"
import { DataReadout } from "../../components/primitives/DataReadout"
import { Panel } from "../../components/primitives/Panel"
import { TopologyGraph } from "../../components/trust/TopologyGraph"
import { ResponsePage as ResponseTrustPage } from "../../components/trust/ResponsePage"
import { LedgerPage as LedgerTrustPage } from "../../components/trust/LedgerPage"
import { DecoysPage as DecoysTrustPage } from "../../components/trust/DecoysPage"

export interface TrustPageProps {
  incidentId: string | null
}

function NeedIncident({ title, icon }: { title: string; icon: React.ReactNode }) {
  return (
    <Panel title={title} icon={icon}>
      <div className="flex min-h-[420px] items-center justify-center px-4 py-8">
        <DataReadout dim>Select an incident on the Incidents tab first.</DataReadout>
      </div>
    </Panel>
  )
}

/** Needs an incident: the graph belongs to one. */
export function GraphPage({ incidentId }: TrustPageProps) {
  if (!incidentId) return <NeedIncident title="Incident Graph" icon={<Network size={14} />} />
  return <TopologyGraph incidentId={incidentId} />
}

/** Needs an incident: the actions belong to one. */
export function ResponsePage({ incidentId }: TrustPageProps) {
  if (!incidentId) return <NeedIncident title="Response Preview" icon={<ShieldAlert size={14} />} />
  return <ResponseTrustPage incidentId={incidentId} />
}

/** The ledger is system-wide, so it works with no incident selected. */
export function LedgerPage({ incidentId }: TrustPageProps) {
  return <LedgerTrustPage incidentId={incidentId} />
}

/** The decoys are system-wide too. With an incident, the placements follow its hosts. */
export function DecoysPage({ incidentId }: TrustPageProps) {
  return <DecoysTrustPage incidentId={incidentId} />
}