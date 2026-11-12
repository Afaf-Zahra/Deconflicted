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
    for (const name of ["GraphPage", "ResponsePage", "LedgerPage", "DecoysPage"] as const) {
      expect(typeof trust[name], name).toBe("function")
      const Page = trust[name]
      const { unmount } = render(<Page incidentId="INC-0042" />)
      expect(screen.getByText(/not built yet/)).toBeInTheDocument()
      unmount()
      const second = render(<Page incidentId={null} />)
      expect(screen.getByText(/not built yet/)).toBeInTheDocument()
      second.unmount()
    }
  })

  it("trust exports nothing else that a page would have to remove", () => {
    expect(Object.keys(trust).sort()).toEqual(["DecoysPage", "GraphPage", "LedgerPage", "ResponsePage"])
    expect(Object.keys(analyst)).toEqual(["AnalystPage"])
  })
})

