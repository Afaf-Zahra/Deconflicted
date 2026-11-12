import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import * as analyst from "../../src/pages/analyst"
import * as trust from "../../src/pages/trust"

describe("page stubs keep the agreed interface", () => {
  it("analyst exports AnalystPage and renders with the agreed props", () => {
    expect(typeof analyst.AnalystPage).toBe("function")
    render(<analyst.AnalystPage selectedIncidentId={null} onSelectIncident={vi.fn()} onOpenResponse={vi.fn()} />)
    expect(screen.getByText(/Loading incidents/)).toBeInTheDocument()
  })

  it("trust exports the four pages and each takes incidentId", () => {
    expect(typeof trust.GraphPage).toBe("function")
    expect(typeof trust.ResponsePage).toBe("function")
    expect(typeof trust.LedgerPage).toBe("function")
    expect(typeof trust.DecoysPage).toBe("function")

    const graph = render(<trust.GraphPage incidentId="INC-0042" />)
    expect(screen.getByText("Incident Graph")).toBeInTheDocument()
    graph.unmount()

    const response = render(<trust.ResponsePage incidentId="INC-0042" />)
    expect(screen.getByText("Response Preview")).toBeInTheDocument()
    response.unmount()

    const ledger = render(<trust.LedgerPage incidentId="INC-0042" />)
    expect(screen.getByText("Ledger")).toBeInTheDocument()
    ledger.unmount()

    const decoys = render(<trust.DecoysPage incidentId="INC-0042" />)
    expect(screen.getByText("Decoys")).toBeInTheDocument()
    decoys.unmount()

    const graphWithoutIncident = render(<trust.GraphPage incidentId={null} />)
    expect(graphWithoutIncident.container).toBeEmptyDOMElement()
    graphWithoutIncident.unmount()
  })

  it("trust exports nothing else that a page would have to remove", () => {
    expect(Object.keys(trust).sort()).toEqual(["DecoysPage", "GraphPage", "LedgerPage", "ResponsePage"])
    expect(Object.keys(analyst)).toEqual(["AnalystPage"])
  })
})

