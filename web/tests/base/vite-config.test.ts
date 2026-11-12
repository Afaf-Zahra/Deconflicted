// @vitest-environment node
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import config, { mockFile } from "../../vite.config"

type Proxy = Record<string, { target: string; rewrite?: (path: string) => string }>
const proxy = config.server?.proxy as unknown as Proxy
const apiPaths = Object.keys(proxy).filter((path) => path !== "/api")

describe("mockFile", () => {
  let dir = ""

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mock-"))
    writeFileSync(join(dir, "graph.json"), "{}")
    writeFileSync(join(dir, "notes.txt"), "not json")
    mkdirSync(join(dir, "sub"))
    writeFileSync(join(dir, "sub", "a.json"), "{}")
  })

  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  it("finds a json file, with or without a query string", () => {
    expect(mockFile(dir, "/graph.json")).toBe(join(dir, "graph.json"))
    expect(mockFile(dir, "/graph.json?x=1")).toBe(join(dir, "graph.json"))
    expect(mockFile(dir, "/sub/a.json")).toBe(join(dir, "sub", "a.json"))
  })

  it("refuses other file types and missing files", () => {
    expect(mockFile(dir, "/notes.txt")).toBeNull()
    expect(mockFile(dir, "/missing.json")).toBeNull()
    expect(mockFile(dir, "/")).toBeNull()
  })

  it("never leaves the folder", () => {
    for (const path of ["/../package.json", "/%2e%2e/package.json", "/%2e%2e%2fpackage.json", "/sub/../../package.json"]) {
      expect(mockFile(dir, path), path).toBeNull()
    }
  })

  it("does not throw on a bad escape sequence", () => {
    expect(mockFile(dir, "/%zz.json")).toBeNull()
  })
})

describe("dev server proxy", () => {
  it("forwards every path the screens call to the API", () => {
    for (const path of ["/incidents", "/budget", "/events", "/response", "/ledger", "/audit", "/decoys", "/debug", "/ingest", "/health"]) {
      expect(proxy[path]?.target, path).toBe("http://localhost:8000")
    }
  })

  it("keeps the /api prefix working", () => {
    expect(proxy["/api"].rewrite?.("/api/budget")).toBe("/budget")
  })

  it("forwards the same paths as the web container", () => {
    const conf = readFileSync(join(__dirname, "..", "..", "..", "docker", "nginx.conf"), "utf-8")
    const match = conf.match(/location ~ \^\/\(([^)]+)\)/)
    expect(match, "docker/nginx.conf has no API location").not.toBeNull()
    expect([...apiPaths.map((path) => path.slice(1))].sort()).toEqual(match![1].split("|").sort())
  })
})