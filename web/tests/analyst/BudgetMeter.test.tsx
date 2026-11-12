
import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { BudgetMeter } from "../../src/components/analyst/BudgetMeter"

describe("BudgetMeter", () => {
  it("shows the correct budget usage", () => {
    const html = renderToStaticMarkup(
      <BudgetMeter budget={5} used={3} windowHours={24} />,
    )

    expect(html).toContain("3 of 5 incidents used (24h)")
    expect(html).toContain('aria-valuenow="3"')
    expect(html).toContain("width:60%")
  })

  it("uses the warning color near the limit", () => {
    const html = renderToStaticMarkup(
      <BudgetMeter budget={5} used={4} windowHours={24} />,
    )

    expect(html).toContain("bg-warning")
  })

  it("uses the critical color at the limit", () => {
    const html = renderToStaticMarkup(
      <BudgetMeter budget={5} used={5} windowHours={24} />,
    )

    expect(html).toContain("bg-error")
  })

  it("handles a zero budget safely", () => {
    const html = renderToStaticMarkup(
      <BudgetMeter budget={0} used={0} windowHours={24} />,
    )

    expect(html).toContain("0 of 0 incidents used (24h)")
    expect(html).toContain("width:0%")
    expect(html).not.toContain("NaN")
  })
})

