import { API_MODE } from "../../lib/env"

/** Status strip. It makes no network call: it only shows where the data comes from. */
export function Footer() {
  return (
    <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-outline-variant bg-surface-container-lowest px-5 py-2 font-mono text-[11px] text-on-surface-variant">
      <span className="flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-secondary-fixed-dim" />
        runs offline
      </span>
      <span>
        data <span className="text-on-surface">{API_MODE === "live" ? "live API" : "mock files"}</span>
      </span>
    </footer>
  )
}
