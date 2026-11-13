import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

const root = join(__dirname, "..", "..")
const read = (path: string) => readFileSync(join(root, path), "utf-8")

describe("branding and offline rules", () => {
  it("the page title is Deconflicted", () => {
    expect(read("index.html")).toContain("<title>Deconflicted</title>")
  })

  it("the shell files carry no NeuralShield name or numbers", () => {
    for (const file of ["index.html", "src/App.tsx", "src/components/layout/Header.tsx", "src/components/layout/Footer.tsx", "src/pages/Home.tsx"]) {
      const text = read(file)
      expect(text.replace("Interface adapted from NeuralShield.", ""), file).not.toMatch(/NeuralShield|GNN|0\.989|0\.933|CIC-IDS/)
    }
  })

  it("the shell files reference no external address", () => {
    for (const file of ["index.html", "src/App.tsx", "src/lib/env.ts", "src/components/layout/Header.tsx", "src/components/layout/Footer.tsx", "src/pages/Home.tsx", "src/index.css"]) {
      expect(read(file), file).not.toMatch(/https?:\/\//)
    }
  })

  it("the favicon is a local file", () => {
    expect(read("index.html")).toContain('href="/favicon.svg"')
    expect(read("public/favicon.svg")).toContain("<svg")
  })

  it("the test script never watches", () => {
    expect(JSON.parse(read("package.json")).scripts.test).toBe("vitest run")
  })

  it("the NeuralShield panels and its backend client are gone", () => {
    for (const path of ["src/components/panels", "src/lib/api.ts", "src/lib/types.ts", "src/lib/fixtures", "src/lib/icons.ts", "src/lib/constants.ts"]) {
      expect(existsSync(join(root, path)), path).toBe(false)
    }
  })

  it("no source file reaches for a removed module", () => {
    const files: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = join(dir, name)
        if (statSync(full).isDirectory()) walk(full)
        else if (/\.(ts|tsx)$/.test(name)) files.push(full)
      }
    }
    walk(join(root, "src"))
    expect(files.length).toBeGreaterThan(5)
    for (const file of files) {
      expect(readFileSync(file, "utf-8"), file).not.toMatch(/components\/panels|lib\/(api|types|fixtures|icons|constants)/)
    }
  })

  it("the shared primitives the pages build on are still there", () => {
    for (const name of ["Panel", "Badge", "DataReadout"]) {
      expect(existsSync(join(root, `src/components/primitives/${name}.tsx`)), name).toBe(true)
    }
    for (const dep of ["recharts", "react-force-graph-2d", "d3-force-3d", "lucide-react"]) {
      expect(JSON.parse(read("package.json")).dependencies[dep], dep).toBeTruthy()
    }
  })
})
