import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import { ResponsePage } from "../../src/components/trust/ResponsePage"

vi.mock("../../src/components/trust/data", () => ({
  useIncident: () => ({
    data: {
      id: "INC-0042",
      title: "Admin credentials used from ws-help-01, ends in a PLC setpoint write",
      status: "open",
      severity: "critical",
      first_event_ts: "2026-03-04T03:40:00Z",
      first_alert_ts: "2026-03-04T03:44:12Z",
      entities: [],
      signals: [],
      chain: [],
      promoted_held_signal_ids: [],
      chain_stop: {
        index: 1,
        reason: "powershell -enc is not part of any known admin routine",
      },
      proposed_actions: [
        { id: "act-001", kind: "isolate_host", target: "plc-1", params: {} },
        {
          id: "act-002",
          kind: "block_write",
          target: "eng-ws-01",
          params: { to: "plc-1" },
        },
        {
          id: "act-003",
          kind: "disable_account",
          target: "alice",
          params: {},
        },
      ],
    },
    loading: false,
    error: null,
  }),
  previewResponse: vi.fn().mockResolvedValue({
    action: {
      id: "act-001",
      kind: "isolate_host",
      target: "plc-1",
      params: {},
    },
    before_trace: [{ t: 0, level: 50 }],
    after_trace: [{ t: 0, level: 50 }],
    violations: [
      {
        rule_id: "level_low",
        detail: "level reaches 19.6 at 76 s",
        ts: 76,
      },
    ],
    safer_options: [
      {
        id: "act-001-opt1",
        kind: "block_write",
        target: "eng-ws-01",
        params: { to: "plc-1" },
      },
      {
        id: "act-001-opt3",
        kind: "rate_limit_writes",
        target: "plc-1",
        params: { max_per_minute: 6 },
      },
      {
        id: "act-001-opt2",
        kind: "reset_setpoint",
        target: "plc-1",
        params: { value: 50 },
      },
    ],
    decision: "downgrade",
    reason: "isolate_host on plc-1 would break level_low",
  }),
}))

describe("ResponsePage", () => {
  it("renders proposed actions and preview details", async () => {
    const user = userEvent.setup()

    render(<ResponsePage incidentId="INC-0042" />)

    expect(screen.getByText("Response Preview")).toBeInTheDocument()
    expect(screen.getByText("Isolate host: plc-1")).toBeInTheDocument()
    expect(screen.getByText("Block write: eng-ws-01")).toBeInTheDocument()
    expect(screen.getByText("Disable account: alice")).toBeInTheDocument()

    await user.click(screen.getByText("Isolate host: plc-1"))

    await waitFor(() => {
      expect(screen.getByText("downgrade")).toBeInTheDocument()
    })

    expect(screen.getByText("level_low")).toBeInTheDocument()
    expect(screen.getByText("block_write → eng-ws-01")).toBeInTheDocument()
    expect(screen.getByText("rate_limit_writes → plc-1")).toBeInTheDocument()
    expect(screen.getByText("reset_setpoint → plc-1")).toBeInTheDocument()
  })

  it("disables approval until an analyst is selected", async () => {
    const user = userEvent.setup()

    render(<ResponsePage incidentId="INC-0042" />)

    await user.click(screen.getByText("Isolate host: plc-1"))

    await waitFor(() => {
      expect(screen.getByText("downgrade")).toBeInTheDocument()
    })

    const approveButton = screen.getByRole("button", { name: "Approve" })
    expect(approveButton).toBeDisabled()

    await user.selectOptions(
      screen.getByRole("combobox", { name: "Analyst" }),
      "analyst",
    )

    expect(approveButton).not.toBeDisabled()
  })
})
