import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

const load = (name: string) => JSON.parse(readFileSync(join(__dirname, "..", "..", "mock", name), "utf-8"))

describe("mock files the pages build against", () => {
  it("preview is a downgrade with 31 trace points and a safer option", () => {
    const preview = load("preview.json")
    expect(preview.decision).toBe("downgrade")
    expect(preview.before_trace).toHaveLength(31)
    expect(preview.after_trace).toHaveLength(31)
    expect(preview.safer_options[0].kind).toBe("block_write")
    expect(preview.violations[0].rule_id).toBe("level_low")
  })

  it("ledger entries link into a chain and carry signatures", () => {
    const entries = load("ledger.json")
    expect(entries[0].prev_hash).toBe("0".repeat(64))
    entries.slice(1).forEach((entry: { prev_hash: string }, i: number) => expect(entry.prev_hash).toBe(entries[i].entry_hash))
    expect(entries.every((e: { signatures: unknown[] }) => e.signatures.length >= 2)).toBe(true)
  })

  it("nodes, verify, audit and decoys have the documented shape", () => {
    expect(load("nodes.json").map((n: { node: string }) => n.node)).toEqual(["node-a", "node-b", "node-c"])
    expect(load("verify.json")).toMatchObject({ ok: true, errors: [] })
    expect(load("verify_tampered.json")).toMatchObject({ ok: false })
    expect(load("verify_tampered.json").errors).toHaveLength(1)
    expect(Object.keys(load("audit.json")).sort()).toEqual(["entries", "generated_at", "heads", "ok"])
    const decoys = load("decoys.json")
    expect(decoys.decoys).toHaveLength(2)
    expect(decoys.hits[0].decoy).toBe("dc-decoy-01")
  })
})
