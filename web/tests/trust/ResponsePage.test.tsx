import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { ResponsePage } from "../../src/components/trust/ResponsePage"

const mocks = vi.hoisted(() => ({
  previewResponse: vi.fn(),
  decide: vi.fn(),
  incident: {
    id: "INC-0042",
    proposed_actions: [
      { id: "act-001", kind: "isolate_host", target: "plc-1", params: {} },
      { id: "act-002", kind: "block_write", target: "eng-ws-01", params: { to: "plc-1" } },
      { id: "act-003", kind: "disable_account", target: "alice", params: {} },
    ],
    signals: [],
  },
}))

vi.mock("../../src/components/trust/data", () => ({
  ANALYSTS: ["analyst-1", "analyst-2"],
  useIncident: () => ({ data: mocks.incident, loading: false, error: null }),
  previewResponse: mocks.previewResponse,
  decide: mocks.decide,
}))

const ACTION = { id: "act-001", kind: "isolate_host", target: "plc-1", params: {} }

const DOWNGRADE = {
  action: ACTION,
  before_trace: [{ t: 0, level: 50 }],
  after_trace: [{ t: 0, level: 50 }],
  violations: [{ rule_id: "level_low", detail: "level reaches 19.6 at 76 s", ts: 76 }],
  safer_options: [
    { id: "act-001-opt1", kind: "block_write", target: "eng-ws-01", params: { to: "plc-1" } },
    { id: "act-001-opt3", kind: "rate_limit_writes", target: "plc-1", params: { max_per_minute: 6 } },
    { id: "act-001-opt2", kind: "reset_setpoint", target: "plc-1", params: { value: 50 } },
  ],
  decision: "downgrade",
  reason: "isolate_host on plc-1 would break level_low",
}

async function openFirstAction() {
  const user = userEvent.setup()
  render(<ResponsePage incidentId="INC-0042" />)
  await user.click(screen.getByText("Isolate host: plc-1"))
  await waitFor(() => expect(screen.getByText(/^(allow|downgrade|block)$/)).toBeInTheDocument())
  return user
}

describe("ResponsePage", () => {
  beforeEach(() => {
    mocks.previewResponse.mockReset().mockResolvedValue(DOWNGRADE)
    mocks.decide.mockReset().mockResolvedValue({ seq: 7 })
  })

  it("renders proposed actions and preview details", async () => {
    await openFirstAction()

    expect(screen.getByText("Response Preview")).toBeInTheDocument()
    expect(screen.getByText("Block write: eng-ws-01")).toBeInTheDocument()
    expect(screen.getByText("Disable account: alice")).toBeInTheDocument()
    expect(screen.getByText("downgrade")).toBeInTheDocument()
    expect(screen.getByText("level_low")).toBeInTheDocument()
    expect(screen.getByText("76 s")).toBeInTheDocument()
    expect(screen.getByText("block_write → eng-ws-01")).toBeInTheDocument()
    expect(screen.getByText("rate_limit_writes → plc-1")).toBeInTheDocument()
    expect(screen.getByText("reset_setpoint → plc-1")).toBeInTheDocument()
  })

  it("asks the API with the incident id and the whole action", async () => {
    await openFirstAction()

    expect(mocks.previewResponse).toHaveBeenCalledWith("INC-0042", mocks.incident.proposed_actions[0])
  })

  it("says which safer option an approval would apply when the action is downgraded", async () => {
    await openFirstAction()

    expect(screen.getByText("Approving applies the first safer option: block_write → eng-ws-01")).toBeInTheDocument()
  })

  it("offers the analysts of the ledger policy and disables approval until one is selected", async () => {
    const user = await openFirstAction()
    const select = screen.getByRole("combobox", { name: "Analyst" })

    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "Select analyst",
      "analyst-1",
      "analyst-2",
    ])

    const approve = screen.getByRole("button", { name: "Approve" })
    expect(approve).toBeDisabled()

    await user.selectOptions(select, "analyst-1")

    expect(approve).not.toBeDisabled()
  })

  it("keeps approval disabled when the safety check blocks the action", async () => {
    mocks.previewResponse.mockResolvedValue({ ...DOWNGRADE, decision: "block", safer_options: [], reason: "plc-1 would go out of range" })
    const user = await openFirstAction()

    await user.selectOptions(screen.getByRole("combobox", { name: "Analyst" }), "analyst-1")

    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Reject" })).not.toBeDisabled()
    expect(screen.getByText("Approval is disabled because the decision is block.")).toBeInTheDocument()
  })

  it("sends the approval with the analyst id and shows the ledger entry", async () => {
    const user = await openFirstAction()

    await user.selectOptions(screen.getByRole("combobox", { name: "Analyst" }), "analyst-1")
    await user.click(screen.getByRole("button", { name: "Approve" }))

    expect(mocks.decide).toHaveBeenCalledWith("act-001", "analyst-1", "approve")
    expect(await screen.findByText("Approved and signed into the ledger as entry 7.")).toBeInTheDocument()
  })

  it("shows the reason when the API refuses a decision", async () => {
    mocks.decide.mockRejectedValue(new Error("The request to /response/act-001/approve failed (403): 'x' is not a listed analyst"))
    const user = await openFirstAction()

    await user.selectOptions(screen.getByRole("combobox", { name: "Analyst" }), "analyst-2")
    await user.click(screen.getByRole("button", { name: "Reject" }))

    expect(await screen.findByText(/is not a listed analyst/)).toBeInTheDocument()
  })
})