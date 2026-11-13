import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const ACTION = { id: "act-001", kind: "isolate_host", target: "plc-1", params: {} }

function reply(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

async function load(mode: "mock" | "live") {
  vi.resetModules()
  vi.stubEnv("VITE_API", mode)
  return import("../../src/components/trust/data")
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal("fetch", fetchMock)
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe("trust data layer, live", () => {
  it("sends the incident id and the whole action to the preview", async () => {
    fetchMock.mockResolvedValue(reply({ decision: "allow" }))
    const data = await load("live")

    await data.previewResponse("INC-0001", ACTION)

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe("/api/response/preview")
    expect(init.method).toBe("POST")
    expect(JSON.parse(init.body)).toEqual({ incident_id: "INC-0001", action: ACTION })
  })

  it("posts approvals and rejections with the analyst id and returns the ledger entry number", async () => {
    fetchMock.mockResolvedValue(reply({ seq: 9, kind: "approval" }))
    const data = await load("live")

    expect(await data.decide("act-001", "analyst-1", "approve")).toEqual({ seq: 9 })
    expect(await data.decide("act-002", "analyst-2", "reject")).toEqual({ seq: 9 })

    expect(fetchMock.mock.calls[0][0]).toBe("/api/response/act-001/approve")
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ analyst: "analyst-1" })
    expect(fetchMock.mock.calls[1][0]).toBe("/api/response/act-002/reject")
  })

  it("uses the API paths for verify, the audit export and the debug tamper", async () => {
    fetchMock.mockResolvedValue(reply({ ok: true, tampered_seq: 3 }))
    const data = await load("live")

    await data.fetchVerify()
    await data.fetchAudit()
    await data.tamperLedger()

    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual(["/api/ledger/verify", "/api/audit/export", "/api/debug/tamper"])
    expect(fetchMock.mock.calls[2][1].method).toBe("POST")
  })

  it("shows the reason the server gave, not only the status", async () => {
    fetchMock.mockResolvedValue(reply({ detail: "action 'act-001' was blocked by the safety check" }, 409))
    const data = await load("live")

    await expect(data.decide("act-001", "analyst-1", "approve")).rejects.toThrow("blocked by the safety check")
  })
})

describe("trust data layer, mock", () => {
  it("reads the mock files, posts nothing, and lets the debug tamper switch the verify file", async () => {
    fetchMock.mockImplementation(async (url: string) => reply({ from: url }))
    const data = await load("mock")

    await data.previewResponse("INC-0001", ACTION)
    expect(fetchMock).toHaveBeenLastCalledWith("/mock/preview.json")
    expect(await data.decide("act-001", "analyst-1", "approve")).toEqual({ seq: null })
    expect(await data.fetchVerify()).toEqual({ from: "/mock/verify.json" })

    await data.tamperLedger()
    expect(await data.fetchVerify()).toEqual({ from: "/mock/verify_tampered.json" })
    expect(fetchMock.mock.calls.every((call) => call[1] === undefined)).toBe(true)
  })
})