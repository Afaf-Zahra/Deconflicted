
import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { FirstAlertBanner } from "../../src/components/analyst/FirstAlertBanner"

describe("FirstAlertBanner", () => {
  it("calculates the detection time correctly", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner
        firstEventTs="2026-03-04T03:40:00Z"
        firstAlertTs="2026-03-04T03:44:12Z"
      />,
    )

    expect(html).toContain("4 min 12 sec")
  })

  it("handles detection times under one minute", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner
        firstEventTs="2026-03-04T03:40:00Z"
        firstAlertTs="2026-03-04T03:40:30Z"
      />,
    )

    expect(html).toContain("30 seconds")
  })

  it("handles a missing first alert timestamp", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner
        firstEventTs="2026-03-03T10:15:00Z"
      />,
    )

    expect(html).toContain("Detection time unavailable")
  })

  it("handles both timestamps missing", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner />,
    )

    expect(html).toContain("Detection time unavailable")
  })

  it("handles invalid timestamps", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner
        firstEventTs="invalid"
        firstAlertTs="2026-03-04T03:44:12Z"
      />,
    )

    expect(html).toContain("Detection time unavailable")
  })

  it("handles an alert timestamp before the event", () => {
    const html = renderToStaticMarkup(
      <FirstAlertBanner
        firstEventTs="2026-03-04T03:44:12Z"
        firstAlertTs="2026-03-04T03:40:00Z"
      />,
    )

    expect(html).toContain("Detection time unavailable")
  })
})

