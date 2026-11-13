import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import { LedgerPage } from "../../src/components/trust/LedgerPage"

const mocks = vi.hoisted(() => ({ fetchVerify: vi.fn(), fetchAudit: vi.fn(), tamperLedger: vi.fn() }))

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
        signatures: [{ node: "node-1", sig: "signature-1" }],
      },
    ],
    loading: false,
    error: null,
  })),
  useLedgerNodes: vi.fn(() => ({
    data: [{ node: "node-1", up: true, head: "head-hash-12345678901234567890", signatures: 2 }],
    loading: false,
    error: null,
  })),
  useLedgerVerify: vi.fn(() => ({
    data: { ok: true, checked: 1, errors: [], heads: { "node-1": "head-hash-12345678901234567890" } },
    loading: false,
    error: null,
  })),
  fetchVerify: mocks.fetchVerify,
  fetchAudit: mocks.fetchAudit,
  tamperLedger: mocks.tamperLedger,
}))

describe("LedgerPage", () => {
  it("shows loading state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } = await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({ data: null, loading: true, error: null })
    vi.mocked(useLedgerNodes).mockReturnValueOnce({ data: null, loading: false, error: null })
    vi.mocked(useLedgerVerify).mockReturnValueOnce({ data: null, loading: false, error: null })

    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("Loading ledger...")).toBeInTheDocument()
  })

  it("shows error state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } = await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({ data: null, loading: false, error: "Ledger request failed" })
    vi.mocked(useLedgerNodes).mockReturnValueOnce({ data: null, loading: false, error: null })
    vi.mocked(useLedgerVerify).mockReturnValueOnce({ data: null, loading: false, error: null })

    render(<LedgerPage incidentId="INC-0042" />)

    expect(screen.getByText("Ledger request failed")).toBeInTheDocument()
  })

  it("shows empty state", async () => {
    const { useLedger, useLedgerNodes, useLedgerVerify } = await import("../../src/components/trust/data")

    vi.mocked(useLedger).mockReturnValueOnce({ data: [], loading: false, error: null })
    vi.mocked(useLedgerNodes).mockReturnValueOnce({ data: [], loading: false, error: null })
    vi.mocked(useLedgerVerify).mockReturnValueOnce({
      data: { ok: true, checked: 0, errors: [], heads: {} },
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
    expect(screen.getByText("nodes agree: yes")).toBeInTheDocument()
    expect(screen.getByText("incident_created")).toBeInTheDocument()
    expect(screen.getByText("node-1")).toBeInTheDocument()
    expect(screen.getByText("up")).toBeInTheDocument()
    expect(screen.getByText("Export audit JSON")).toBeInTheDocument()
    expect(screen.getByText("Verify")).toBeInTheDocument()
  })

  it("works with no incident selected and hides the debug tamper button", () => {
    render(<LedgerPage incidentId={null} />)

    expect(screen.getByText("Ledger verification")).toBeInTheDocument()
    expect(screen.queryByText(/^incident /)).not.toBeInTheDocument()
    expect(screen.queryByText("Tamper (debug)")).not.toBeInTheDocument()
  })

  it("verifies again from the API instead of reloading the page", async () => {
    mocks.fetchVerify.mockResolvedValue({
      ok: false,
      checked: 1,
      errors: [{ seq: 4, reason: "payload_hash_mismatch" }],
      heads: {},
    })
    const user = userEvent.setup()

    render(<LedgerPage incidentId="INC-0042" />)
    await user.click(screen.getByText("Verify"))

    expect(await screen.findByText("failed")).toBeInTheDocument()
    expect(screen.getByText("seq 4: payload_hash_mismatch")).toBeInTheDocument()
    expect(mocks.fetchVerify).toHaveBeenCalledTimes(1)
  })

  it("downloads the audit export from the API", async () => {
    mocks.fetchAudit.mockResolvedValue({ entries: [] })
    const createObjectURL = vi.fn(() => "blob:audit")
    Object.defineProperty(URL, "createObjectURL", { value: createObjectURL, configurable: true, writable: true })
    Object.defineProperty(URL, "revokeObjectURL", { value: vi.fn(), configurable: true, writable: true })
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined)
    const user = userEvent.setup()

    render(<LedgerPage incidentId="INC-0042" />)
    await user.click(screen.getByText("Export audit JSON"))

    await waitFor(() => expect(click).toHaveBeenCalled())
    expect(mocks.fetchAudit).toHaveBeenCalled()
    expect(createObjectURL).toHaveBeenCalled()
    click.mockRestore()
  })
})