import { afterEach, describe, expect, it, vi } from "vitest"

afterEach(() => {
  vi.unstubAllEnvs()
  vi.resetModules()
})

describe("api mode", () => {
  it("defaults to mock files and the /api proxy", async () => {
    vi.stubEnv("VITE_API", "")
    vi.stubEnv("VITE_API_BASE", undefined as unknown as string)
    const env = await import("../../src/lib/env")
    expect(env.API_MODE).toBe("mock")
    expect(env.API_BASE).toBe("/api")
  })

  it("switches to the live API only when asked", async () => {
    vi.stubEnv("VITE_API", "live")
    vi.stubEnv("VITE_API_BASE", "http://localhost:8000")
    const env = await import("../../src/lib/env")
    expect(env.API_MODE).toBe("live")
    expect(env.API_BASE).toBe("http://localhost:8000")
  })

  it("treats any other value as mock", async () => {
    vi.stubEnv("VITE_API", "production")
    expect((await import("../../src/lib/env")).API_MODE).toBe("mock")
  })
})
