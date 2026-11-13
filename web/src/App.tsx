import { useState } from "react"
import { Header, type Tab } from "./components/layout/Header"
import { Footer } from "./components/layout/Footer"
import { AnalystPage } from "./pages/analyst"
import { DemoPage } from "./pages/demo"
import { DecoysPage, GraphPage, LedgerPage, ResponsePage } from "./pages/trust"

/** The shell: five tabs (and Demo when VITE_DEBUG=1) and the selected incident, which every page receives. */
function App({ onHome }: { onHome?: () => void }) {
  const [tab, setTab] = useState<Tab>("incidents")
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)

  function openResponse(id: string) {
    setSelectedIncidentId(id)
    setTab("response")
  }

  return (
    <div className="flex min-h-screen flex-col bg-surface-container-lowest font-sans text-on-surface">
      <Header tab={tab} onTabChange={setTab} selectedIncidentId={selectedIncidentId} onHome={onHome} />
      <main className="flex flex-1 flex-col overflow-y-auto">
        {tab === "incidents" && (
          <AnalystPage selectedIncidentId={selectedIncidentId} onSelectIncident={setSelectedIncidentId} onOpenResponse={openResponse} />
        )}
        {tab === "graph" && <GraphPage incidentId={selectedIncidentId} />}
        {tab === "response" && <ResponsePage incidentId={selectedIncidentId} />}
        {tab === "ledger" && <LedgerPage incidentId={selectedIncidentId} />}
        {tab === "decoys" && <DecoysPage incidentId={selectedIncidentId} />}
        {tab === "demo" && <DemoPage onSelectIncident={setSelectedIncidentId} onGoTo={setTab} />}
      </main>
      <Footer />
    </div>
  )
}

export default App