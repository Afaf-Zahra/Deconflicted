
import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { AttackTimeline } from "../../src/components/analyst/AttackTimeline"

const chain = [
  {
    ts: "2026-03-04T03:40:00Z",
    tactic: "Initial Access",
    technique: "T1078",
    description: "Unusual account logon",
    signal_id: "sig-001",
    matched_routine: true,
  },
  {
    ts: "2026-03-04T03:43:02Z",
    tactic: "Execution",
    technique: "T1059.001",
    description: "Encoded PowerShell command",
    signal_id: "sig-002",
    matched_routine: false,
  },
]

describe("AttackTimeline", () => {
  it("displays attack steps and technique IDs", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline chain={chain} />,
    )

    expect(html).toContain("Initial Access")
    expect(html).toContain("Execution")
    expect(html).toContain("T1078")
    expect(html).toContain("T1059.001")
  })

  it("displays UTC timestamps", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline chain={chain} />,
    )

    expect(html).toContain("UTC")
  })

  it("marks steps matching admin routines", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline chain={chain} />,
    )

    expect(html).toContain("Matches admin routine")
  })

  it("highlights where the chain stops matching", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline
        chain={chain}
        chainStop={{
          index: 1,
          reason: "PowerShell is outside the admin routine",
        }}
      />,
    )

    expect(html).toContain("Chain stops matching routine")
    expect(html).toContain(
      "PowerShell is outside the admin routine",
    )
  })

  it("marks recovered earlier signals", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline
        chain={chain}
        promotedHeldSignalIds={["sig-001"]}
      />,
    )

    expect(html).toContain("Recovered earlier step")
  })

  it("handles an empty timeline", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline chain={[]} />,
    )

    expect(html).toContain("No attack steps available")
  })

  it("handles missing timeline data", () => {
    const html = renderToStaticMarkup(
      <AttackTimeline />,
    )

    expect(html).toContain("No attack steps available")
  })
})

