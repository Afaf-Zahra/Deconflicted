
import { describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { AnalystPage } from "../../src/pages/analyst"
import { useAnalystData } from "../../src/components/analyst/data"

vi.mock("../../src/components/analyst/data", () => ({
  useAnalystData: vi.fn(),
}))

const mockedUseAnalystData = vi.mocked(useAnalystData)

const incident = {
  id: "INC-0042",
  title: "Suspicious admin activity",
  status: "open",
  severity: "critical",
  first_event_ts: "2026-03-04T03:40:00Z",
  first_alert_ts: "2026-03-04T03:44:12Z",
  chain: [],
  signals: [],
  entities: [],
  promoted_held_signal_ids: [],
  proposed_actions: [
    {
      id: "act-001",
      kind: "disable_account",
      target: "alice",
      params: {},
    },
  ],
}

function setMockData(incidents: typeof incident[]) {
  mockedUseAnalystData.mockReturnValue({
    data: {
      incidents,
      events: [],
      budget: {
        budget: 5,
        used: 3,
        window_hours: 24,
      },
    },
    loading: false,
    error: null,
    updatedAt: null,
  })
}

function renderPage(selectedIncidentId: string | null = null) {
  return renderToStaticMarkup(
    <AnalystPage
      selectedIncidentId={selectedIncidentId}
      onSelectIncident={() => {}}
      onOpenResponse={() => {}}
    />,
  )
}

describe("AnalystPage", () => {
  it("displays the incident list and budget", () => {
    setMockData([incident])

    const html = renderPage()

    expect(html).toContain("INC-0042")
    expect(html).toContain("3 of 5 incidents used")
  })

  it("shows an empty state when no incidents exist", () => {
    setMockData([])

    const html = renderPage()

    expect(html).toContain("No incidents available")
  })

  it("shows incident details when selected", () => {
    setMockData([incident])

    const html = renderPage("INC-0042")

    expect(html).toContain("Suspicious admin activity")
    expect(html).toContain("First alert detection time")
    expect(html).toContain("Proposed Response Actions")
  })

  it("shows a response review button", () => {
    setMockData([incident])

    const html = renderPage("INC-0042")

    expect(html).toContain("Review response")
    expect(html).toContain("disable account")
  })

  it("asks the analyst to select an incident", () => {
    setMockData([incident])

    const html = renderPage()

    expect(html).toContain(
      "Select an incident to view its details",
    )
  })
})

