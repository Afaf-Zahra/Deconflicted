import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import App from "../../src/App"

vi.mock("../../src/pages/analyst", () => ({
  AnalystPage: (props: { selectedIncidentId: string | null; onSelectIncident: (id: string) => void; onOpenResponse: (id: string) => void }) => (
    <div>
      <p data-testid="analyst-selected">{String(props.selectedIncidentId)}</p>
      <button onClick={() => props.onSelectIncident("INC-0042")}>select incident</button>
      <button onClick={() => props.onOpenResponse("INC-0041")}>open response</button>
    </div>
  ),
}))

vi.mock("../../src/pages/trust", () => {
  const page = (name: string) => (props: { incidentId: string | null }) => <p data-testid={name}>{`${name}:${String(props.incidentId)}`}</p>
  return { GraphPage: page("graph"), ResponsePage: page("response"), LedgerPage: page("ledger"), DecoysPage: page("decoys") }
})

describe("app shell", () => {
  it("shows the product name and the five tabs in order", () => {
    render(<App />)
    expect(screen.getByRole("button", { name: "Deconflicted" })).toBeInTheDocument()
    const tabs = screen.getAllByRole("button").filter((b) => b.closest("nav"))
    expect(tabs.map((b) => b.textContent)).toEqual(["Incidents", "Graph", "Response", "Ledger", "Decoys"])
  })

  it("starts on Incidents with nothing selected", () => {
    render(<App />)
    expect(screen.getByRole("button", { name: "Incidents" })).toHaveAttribute("aria-current", "page")
    expect(screen.getByTestId("analyst-selected")).toHaveTextContent("null")
    expect(screen.getByText("none selected")).toBeInTheDocument()
  })

  it("keeps the selected incident and passes it to every other tab", async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(screen.getByText("select incident"))
    expect(screen.getByTestId("analyst-selected")).toHaveTextContent("INC-0042")
    expect(within(screen.getByRole("banner")).getByText("INC-0042")).toBeInTheDocument()
    for (const [tab, id] of [["Graph", "graph"], ["Response", "response"], ["Ledger", "ledger"], ["Decoys", "decoys"]] as const) {
      await user.click(screen.getByRole("button", { name: tab }))
      expect(screen.getByTestId(id)).toHaveTextContent(`${id}:INC-0042`)
      expect(screen.getByRole("button", { name: tab })).toHaveAttribute("aria-current", "page")
    }
    await user.click(screen.getByRole("button", { name: "Incidents" }))
    expect(screen.getByTestId("analyst-selected")).toHaveTextContent("INC-0042")
  })

  it("onOpenResponse selects the incident and switches to the Response tab", async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(screen.getByText("open response"))
    expect(screen.getByTestId("response")).toHaveTextContent("response:INC-0041")
    expect(screen.getByRole("button", { name: "Response" })).toHaveAttribute("aria-current", "page")
  })

  it("only renders the active tab", async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(screen.queryByTestId("graph")).not.toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Graph" }))
    expect(screen.getByTestId("graph")).toBeInTheDocument()
    expect(screen.queryByTestId("analyst-selected")).not.toBeInTheDocument()
  })

  it("the home button is only active when onHome is given", async () => {
    const user = userEvent.setup()
    const onHome = vi.fn()
    const { unmount } = render(<App />)
    expect(screen.getByRole("button", { name: "Deconflicted" })).toBeDisabled()
    unmount()
    render(<App onHome={onHome} />)
    await user.click(screen.getByRole("button", { name: "Deconflicted" }))
    expect(onHome).toHaveBeenCalledOnce()
  })
})
