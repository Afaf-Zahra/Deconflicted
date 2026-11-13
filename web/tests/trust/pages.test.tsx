import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { DecoysPage, GraphPage, LedgerPage, ResponsePage } from "../../src/pages/trust"

vi.mock("../../src/components/trust/TopologyGraph", () => ({
  TopologyGraph: (props: { incidentId: string }) => <p>{`graph for ${props.incidentId}`}</p>,
}))
vi.mock("../../src/components/trust/ResponsePage", () => ({
  ResponsePage: (props: { incidentId: string }) => <p>{`response for ${props.incidentId}`}</p>,
}))
vi.mock("../../src/components/trust/LedgerPage", () => ({
  LedgerPage: (props: { incidentId?: string | null }) => <p>{`ledger for ${String(props.incidentId)}`}</p>,
}))
vi.mock("../../src/components/trust/DecoysPage", () => ({
  DecoysPage: (props: { incidentId?: string | null }) => <p>{`decoys for ${String(props.incidentId)}`}</p>,
}))

describe("trust pages without an incident", () => {
  it("tells the analyst to select an incident on the graph and response tabs", () => {
    const graph = render(<GraphPage incidentId={null} />)
    expect(screen.getByText("Incident Graph")).toBeInTheDocument()
    expect(screen.getByText("Select an incident on the Incidents tab first.")).toBeInTheDocument()
    graph.unmount()

    render(<ResponsePage incidentId={null} />)
    expect(screen.getByText("Response Preview")).toBeInTheDocument()
    expect(screen.getByText("Select an incident on the Incidents tab first.")).toBeInTheDocument()
  })

  it("still shows the ledger and the decoys, which belong to the whole system", () => {
    const ledger = render(<LedgerPage incidentId={null} />)
    expect(screen.getByText("ledger for null")).toBeInTheDocument()
    ledger.unmount()

    render(<DecoysPage incidentId={null} />)
    expect(screen.getByText("decoys for null")).toBeInTheDocument()
  })

  it("passes the incident on once one is selected", () => {
    render(<GraphPage incidentId="INC-0001" />)
    expect(screen.getByText("graph for INC-0001")).toBeInTheDocument()
  })
})