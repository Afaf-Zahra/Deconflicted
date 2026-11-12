/**
 * Where the UI gets its data. `VITE_API=mock` (the default) reads the files in web/mock/.
 * `VITE_API=live` calls the API at VITE_API_BASE (default /api, which the dev server proxies to
 * port 8000 on this machine). Pages read these two values and never decide for themselves.
 */
export type ApiMode = "mock" | "live"

export const API_MODE: ApiMode = import.meta.env.VITE_API === "live" ? "live" : "mock"
export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "/api"
