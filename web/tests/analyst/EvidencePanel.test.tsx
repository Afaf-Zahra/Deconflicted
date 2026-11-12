
import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { EvidencePanel } from "../../src/components/analyst/EvidencePanel"

const signals = [
  {
    id: "sig-001",
    kind: "role_deviation",
    event_ids: ["event-001"],
  },
]

const events = [
  {
    id: "event-001",
    ts: "2026-03-04T03:40:00Z",
    source: "windows",
    host: "dc-01",
    user: "alice",
    action: "logon",
    obj: "logon_type:3",
    raw: '{"EventID":4624,"Computer":"dc-01"}',
  },
]

describe("EvidencePanel", () => {
  it("groups evidence under its signal", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel signals={signals} events={events} />,
    )

    expect(html).toContain("sig-001")
    expect(html).toContain("role deviation")
    expect(html).toContain("dc-01")
  })

  it("displays event details", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel signals={signals} events={events} />,
    )

    expect(html).toContain("alice")
    expect(html).toContain("logon")
    expect(html).toContain("logon_type:3")
    expect(html).toContain("UTC")
  })

  it("provides an expandable raw event section", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel signals={signals} events={events} />,
    )

    expect(html).toContain("<details")
    expect(html).toContain("View raw event")
    expect(html).toContain("EventID")
    expect(html).toContain("4624")
  })

  it("handles an event that cannot be found", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel signals={signals} events={[]} />,
    )

    expect(html).toContain("event-001 unavailable")
  })

  it("handles signals without linked events", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel
        signals={[
          {
            id: "sig-002",
            kind: "routine_break",
            event_ids: [],
          },
        ]}
        events={events}
      />,
    )

    expect(html).toContain("No linked events")
  })

  it("handles missing signals", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel events={events} />,
    )

    expect(html).toContain("No evidence signals available")
  })

  it("handles missing event fields", () => {
    const html = renderToStaticMarkup(
      <EvidencePanel
        signals={signals}
        events={[{ id: "event-001" }]}
      />,
    )

    expect(html).toContain("Unavailable")
    expect(html).toContain("Raw event unavailable")
  })
})

