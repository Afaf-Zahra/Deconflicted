import { DEBUG_UI } from "../../lib/env"

export type Tab = "incidents" | "graph" | "response" | "ledger" | "decoys" | "demo"

const TABS: { id: Tab; label: string }[] = [
  { id: "incidents", label: "Incidents" },
  { id: "graph", label: "Graph" },
  { id: "response", label: "Response" },
  { id: "ledger", label: "Ledger" },
  { id: "decoys", label: "Decoys" },
  ...(DEBUG_UI ? [{ id: "demo" as const, label: "Demo" }] : []),
]

/** Top bar: the product name, the five tabs (and Demo when VITE_DEBUG=1), and the incident that is currently selected. */
export function Header({
  tab,
  onTabChange,
  selectedIncidentId,
  onHome,
}: {
  tab: Tab
  onTabChange: (tab: Tab) => void
  selectedIncidentId: string | null
  onHome?: () => void
}) {
  return (
    <header className="sticky top-0 z-50 flex w-full flex-col border-b border-outline-variant bg-surface-container-lowest">
      <div className="flex items-center justify-between border-b border-outline-variant/60 px-5 py-2.5">
        <button
          onClick={onHome}
          disabled={!onHome}
          className="flex items-center gap-2 font-sans text-sm font-semibold tracking-tight text-on-surface disabled:cursor-default"
        >
          <span className="h-2 w-2 rounded-full bg-primary-container" />
          Deconflicted
        </button>
        <span className="font-mono text-[11px] text-on-surface-variant">
          incident <span className="text-on-surface">{selectedIncidentId ?? "none selected"}</span>
        </span>
      </div>

      <nav aria-label="Sections" className="flex flex-wrap items-center gap-1 px-5 py-2">
        {TABS.map((item) => (
          <button
            key={item.id}
            onClick={() => onTabChange(item.id)}
            aria-current={tab === item.id ? "page" : undefined}
            className={`flex items-center gap-1.5 border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider transition-colors ${
              tab === item.id
                ? "border-outline-variant bg-surface-container text-on-surface"
                : "border-transparent text-on-surface-variant hover:text-on-surface"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${tab === item.id ? "bg-primary-container" : "border border-on-surface-variant"}`} />
            {item.label}
          </button>
        ))}
      </nav>
    </header>
  )
}