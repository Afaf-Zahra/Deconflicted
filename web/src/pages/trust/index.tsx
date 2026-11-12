/**
 * Graph, Response, Ledger and Decoys tabs. These are placeholders with the agreed interface;
 * the real pages replace them. Keep the export names and the `incidentId` prop exactly as they are.
 */
export interface TrustPageProps {
  incidentId: string | null
}

function Placeholder({ name }: { name: string }) {
  return (
    <section className="flex flex-1 items-center justify-center p-6 font-mono text-[13px] text-on-surface-variant">
      {name}: not built yet
    </section>
  )
}

export function GraphPage(_props: TrustPageProps) {
  return <Placeholder name="incident graph" />
}

export function ResponsePage(_props: TrustPageProps) {
  return <Placeholder name="response preview" />
}

export function LedgerPage(_props: TrustPageProps) {
  return <Placeholder name="ledger" />
}

export function DecoysPage(_props: TrustPageProps) {
  return <Placeholder name="decoys" />
}
