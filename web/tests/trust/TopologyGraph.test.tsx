import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { TopologyGraph } from "../../src/components/trust/TopologyGraph"

vi.mock("../../src/components/trust/data", () => ({
  useGraph: vi.fn(() => ({
    data: {
      nodes: [
        {
          id: "user:alice",
          kind: "user",
          anchor: false,
          decoy_hit: false,
        },
        {
          id: "plc:plc-1",
          kind: "plc",
          anchor: true,
          decoy_hit: false,
        },
        {
          id: "decoy:dc-decoy-01",
          kind: "decoy",
          anchor: false,
          decoy_hit: true,
        },
      ],
      edges: [
        {
          source: "user:alice",
          target: "plc:plc-1",
          token: "ot:write_setpoint",
          ts: "2026-03-04T04:50:00Z",
        },
      ],
    },
    loading: false,
    error: null,
  })),
}))

vi.mock("react-force-graph-2d", () => ({
  default: () => <div data-testid="force-graph" />,
}))

describe("TopologyGraph", () => {
  it("shows loading state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({
      data: null,
      loading: true,
      error: null,
    })

    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("Loading incident graph...")).toBeInTheDocument()
  })

  it("shows error state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({
      data: null,
      loading: false,
      error: "Graph request failed",
    })

    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("Graph request failed")).toBeInTheDocument()
  })

  it("shows empty state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({
      data: { nodes: [], edges: [] },
      loading: false,
      error: null,
    })

    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("No graph data available.")).toBeInTheDocument()
  })

  it("renders graph metadata and signal legend", () => {
    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("Incident Graph")).toBeInTheDocument()
    expect(screen.getByText("3 nodes")).toBeInTheDocument()
    expect(screen.getByText("1 edges")).toBeInTheDocument()
    expect(screen.getByText("Graph")).toBeInTheDocument()
    expect(screen.getByText("Anchor")).toBeInTheDocument()
    expect(screen.getByText("Decoy hit")).toBeInTheDocument()
    expect(screen.getByTestId("force-graph")).toBeInTheDocument()
  })
})
