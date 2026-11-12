
import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import {
  SeverityBadge,
  StatusBadge,
  SignalKindBadge,
} from "../../src/components/analyst/AnalystBadges"

describe("Analyst badges", () => {
  it("displays critical severity", () => {
    const html = renderToStaticMarkup(
      <SeverityBadge severity="critical" />,
    )

    expect(html).toContain("critical")
  })

  it("displays warning severity", () => {
    const html = renderToStaticMarkup(
      <SeverityBadge severity="warning" />,
    )

    expect(html).toContain("warning")
  })

  it("displays incident status", () => {
    const html = renderToStaticMarkup(
      <StatusBadge status="open" />,
    )

    expect(html).toContain("open")
  })

  it("formats signal kinds", () => {
    const html = renderToStaticMarkup(
      <SignalKindBadge kind="role_deviation" />,
    )

    expect(html).toContain("role deviation")
  })

  it("handles missing severity", () => {
    const html = renderToStaticMarkup(
      <SeverityBadge />,
    )

    expect(html).toContain("Unknown")
  })

  it("handles missing signal kind", () => {
    const html = renderToStaticMarkup(
      <SignalKindBadge />,
    )

    expect(html).toContain("Unknown")
  })
})

