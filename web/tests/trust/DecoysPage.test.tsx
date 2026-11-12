import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { DecoysPage } from "../../src/components/trust/DecoysPage"

vi.mock("../../src/components/trust/data", () => ({
  useDecoys: vi.fn(() => ({
    data: {
      decoys: [
        {
          id: "decoy-01",
          type: "honeytoken",
          address: "10.0.0.20",
        },
      ],
      hits: [
        {
          ts: "2026-03-04T04:50:00Z",
          decoy: "decoy-01",
          source: "eng-ws-01",
        },
      ],
      placements: [
        {
          host: "eng-ws-02",
          reason: "Place decoy near engineering workstation",
          safety_ok: true,
        },
        {
          host: "plc-2",
          reason: "Placement conflicts with safety constraint",
          safety_ok: false,
        },
      ],
    },
    loading: false,
    error: null,
  })),
}))

describe("DecoysPage", () => {
  it("shows loading state", async () => {
    const { useDecoys } =
      await import("../../src/components/trust/data")

    vi.mocked(useDecoys).mockReturnValueOnce({
      data: null,
      loading: true,
      error: null,
    })

    render(<DecoysPage incidentId="INC-0042" />)

    expect(screen.getByText("Loading decoy data...")).toBeInTheDocument()
  })

  it("shows error state", async () => {
    const { useDecoys } =
      await import("../../src/components/trust/data")

    vi.mocked(useDecoys).mockReturnValueOnce({
      data: null,
      loading: false,
      error: "Decoy request failed",
    })

    render(<DecoysPage incidentId="INC-0042" />)

    expect(screen.getByText("Decoy request failed")).toBeInTheDocument()
  })

  it("shows empty state", async () => {
    const { useDecoys } =
      await import("../../src/components/trust/data")

    vi.mocked(useDecoys).mockReturnValueOnce({
      data: null,
      loading: false,
      error: null,
    })

    render(<DecoysPage incidentId="INC-0042" />)

    expect(screen.getByText("No decoy data available.")).toBeInTheDocument()
  })

  it("renders decoys, hits, and Trail Ahead placements", () => {
    render(<DecoysPage incidentId="INC-0042" />)

    expect(screen.getByText("Decoy Inventory")).toBeInTheDocument()
    expect(screen.getAllByText("decoy-01")).toHaveLength(2)
    expect(screen.getByText("honeytoken")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.20")).toBeInTheDocument()

    expect(screen.getByText("Decoy Hits")).toBeInTheDocument()
    expect(screen.getByText("eng-ws-01")).toBeInTheDocument()

    expect(screen.getByText("Trail Ahead Placements")).toBeInTheDocument()
    expect(screen.getByText("eng-ws-02")).toBeInTheDocument()
    expect(screen.getByText("plc-2")).toBeInTheDocument()
    expect(screen.getByText("safe")).toBeInTheDocument()
    expect(screen.getByText("unsafe")).toBeInTheDocument()
    expect(screen.getByText("Safety check passed")).toBeInTheDocument()
    expect(screen.getByText("Safety check failed")).toBeInTheDocument()
  })
})
