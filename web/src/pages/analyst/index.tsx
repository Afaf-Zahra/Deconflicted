/**
 * Incidents tab. This is a placeholder with the agreed interface; the real page replaces it.
 * Keep the export name and the props exactly as they are.
 */
export interface AnalystPageProps {
  selectedIncidentId: string | null
  onSelectIncident: (id: string) => void
  onOpenResponse: (id: string) => void
}

export function AnalystPage(_props: AnalystPageProps) {
  return (
    <section className="flex flex-1 items-center justify-center p-6 font-mono text-[13px] text-on-surface-variant">
      incident list and detail: not built yet
    </section>
  )
}
