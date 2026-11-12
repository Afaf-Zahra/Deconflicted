import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { LedgerPage } from "../../src/components/trust/LedgerPage"

vi.mock("../../src/components/trust/data", () => ({
  useLedger: vi.fn(() => ({
    data: [
      {
        seq: 1,
        ts: "2026-03-04T04:50:00Z",
        kind: "incident_created",
        payload_hash: "payload-hash-12345678901234567890",
        prev_hash: "prev-hash-12345678901234567890",
        entry_hash: "entry-hash-12345678901234567890",
        signatures: [
          { node: "node-1", sig: "signature-1" },
        ],
      },
    ],
    loading: false,
    error: null,
  })),
  useLedgerNodes: vi.fn(() => ({
    data: [
      {
        node: "node-1",
        up: true,
        head: "head-hash-12345678901234567890",
        signatures: 2,
      },
    ],
    loading: false,
    error: null,
  })),
  useLedgerVerify: vi.fn(() => ({
    data: {
      ok: true,
      checked: 1,
      errors: [],
      heads: ["head-hash-12345678901234567890"],
    },
    loading: false,
    error: null,
  })),
}))

describe("LedgerPage", () => {
  it("shows loading state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } =
      await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({
      data: null,
      loading: true,
      error: null,
    })

    vi.mocked(useLedgerNodes).mockReturnValueOnce({
      data: null,
      loading: false,
      error: null,
    })

    vi.mocked(useLedgerVerify).mockReturnValueOnce({
      data: null,
      loading: false,
      error: null,
    })

    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("Loading ledger...")).toBeInTheDocument()
  })

  it("shows error state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } =
      await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({
      data: null,
      loading: false,
      error: "Ledger request failed",
    })

    vi.mocked(useLedgerNodes).mockReturnValueOnce({
      data: null,
      loading: false,
      error: null,
    })

    vi.mocked(useLedgerVerify).mockReturnValueOnce({
      data: null,
      loading: false,
      error: null,
    })

    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("Ledger request failed")).toBeInTheDocument()
  })

  it("shows empty state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } =
      await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({
      data: [],
      loading: false,
      error: null,
    })

    vi.mocked(useLedgerNodes).mockReturnValueOnce({
      data: [],
      loading: false,
      error: null,
    })

    vi.mocked(useLedgerVerify).mockReturnValueOnce({
      data: {
        ok: true,
        checked: 0,
        errors: [],
        heads: [],
      },
      loading: false,
      error: null,
    })

    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("No ledger entries available.")).toBeInTheDocument()
  })

  it("renders verification, entries, and nodes", () => {
    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("Ledger verification")).toBeInTheDocument()
    expect(screen.getByText("verified")).toBeInTheDocument()
    expect(screen.getByText("checked: 1")).toBeInTheDocument()
    expect(screen.getByText("incident_created")).toBeInTheDocument()
    expect(screen.getByText("node-1")).toBeInTheDocument()
    expect(screen.getByText("up")).toBeInTheDocument()
    expect(screen.getByText("Export audit JSON")).toBeInTheDocument()
    expect(screen.getByText("Verify")).toBeInTheDocument()
  })
})
