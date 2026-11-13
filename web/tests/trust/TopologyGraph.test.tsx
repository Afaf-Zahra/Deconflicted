import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import { TopologyGraph } from "../../src/components/trust/TopologyGraph"

vi.mock("../../src/components/trust/data", () => ({
  useGraph: vi.fn(() => ({
    data: {
      nodes: [
        { id: "user:alice", kind: "user", anchor: false, decoy_hit: false },
        { id: "plc:plc-1", kind: "plc", anchor: true, decoy_hit: false },
        { id: "decoy:dc-decoy-01", kind: "decoy", anchor: false, decoy_hit: true },
      ],
      edges: [
        { source: "user:alice", target: "plc:plc-1", token: "ot:write_setpoint", ts: "2026-03-04T04:50:00Z" },
      ],
    },
    loading: false,
    error: null,
  })),
  useIncident: vi.fn(() => ({
    data: {
      id: "INC-0042",
      proposed_actions: [],
      signals: [
        {
          id: "sig-1",
          ts: "2026-03-04T03:43:02Z",
          entity_ids: ["host:ws-help-01", "user:alice"],
          kind: "role_deviation",
          score: 0.99817,
          event_ids: ["e1"],
          techniques: ["T1059.001"],
          detail: { note: "proc:powershell_enc is unusual for the admin role" },
        },
        {
          id: "sig-2",
          ts: "2026-03-04T04:50:00Z",
          entity_ids: ["plc:plc-1", "host:eng-ws-01"],
          kind: "ot_invariant",
          score: 1,
          event_ids: ["e2"],
          techniques: ["T0836"],
          detail: { rule: "setpoint_range" },
        },
      ],
    },
    loading: false,
    error: null,
  })),
}))

vi.mock("react-force-graph-2d", () => ({
  default: (props: { graphData: { nodes: { id: string }[] }; onNodeClick?: (node: unknown) => void }) => (
    <div data-testid="force-graph">
      {props.graphData.nodes.map((node) => (
        <button key={node.id} type="button" onClick={() => props.onNodeClick?.(node)}>
          {node.id}
        </button>
      ))}
    </div>
  ),
}))

describe("TopologyGraph", () => {
  it("shows loading state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({ data: null, loading: true, error: null })

    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("Loading incident graph...")).toBeInTheDocument()
  })

  it("shows error state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({ data: null, loading: false, error: "Graph request failed" })

    render(<TopologyGraph incidentId="INC-0042" />)

    expect(screen.getByText("Graph request failed")).toBeInTheDocument()
  })

  it("shows empty state", async () => {
    const { useGraph } = await import("../../src/components/trust/data")
    vi.mocked(useGraph).mockReturnValueOnce({ data: { nodes: [], edges: [] }, loading: false, error: null })

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

  it("lists the incident signals that name the clicked node", async () => {
    const user = userEvent.setup()
    render(<TopologyGraph incidentId="INC-0042" />)

    await user.click(screen.getByRole("button", { name: "user:alice" }))

    expect(screen.getByText("role_deviation · 0.9982")).toBeInTheDocument()
    expect(screen.getByText("03:43:02 UTC proc:powershell_enc is unusual for the admin role")).toBeInTheDocument()
    expect(screen.queryByText("ot_invariant · 1.0000")).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "plc:plc-1" }))

    expect(screen.getByText("ot_invariant · 1.0000")).toBeInTheDocument()
    expect(screen.getByText("04:50:00 UTC setpoint_range")).toBeInTheDocument()
  })

  it("says so when no signal names the node", async () => {
    const user = userEvent.setup()
    render(<TopologyGraph incidentId="INC-0042" />)

    await user.click(screen.getByRole("button", { name: "decoy:dc-decoy-01" }))

    expect(screen.getByText("No signal names this node")).toBeInTheDocument()
  })
})