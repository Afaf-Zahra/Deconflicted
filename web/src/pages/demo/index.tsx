import { useEffect, useState } from "react"
import { Play, RotateCcw, Send } from "lucide-react"
import type { Tab } from "../../components/layout/Header"
import { DataReadout } from "../../components/primitives/DataReadout"
import { Panel } from "../../components/primitives/Panel"
import { API_MODE } from "../../lib/env"
import {
  demoStatus,
  listIncidents,
  resetDemo,
  sendJson,
  sendRaw,
  startAttack,
  type DemoStatus,
  type IncidentRow,
  type IngestAnswer,
} from "./api"
import { ATTACK_STEPS } from "./steps"

const SPEEDS = [
  { label: "Instant", value: 0 },
  { label: "Fast, about 45 s", value: 120 },
  { label: "Normal, about 2 min", value: 40 },
  { label: "Slow, about 6 min", value: 15 },
]
const SOURCES = ["auto", "windows", "proxy", "flow", "linux", "modbus", "opcua"]
const BUTTON =
  "flex items-center gap-1.5 border border-outline-variant bg-surface-container-low px-3 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wide text-primary transition-colors hover:bg-surface-container disabled:opacity-40"
const FIELD =
  "border border-outline-variant bg-surface-container-lowest px-2 py-1.5 font-mono text-[11px] text-primary focus:border-primary-container focus:outline-none"

type Props = {
  onSelectIncident: (id: string) => void
  onGoTo: (tab: Tab) => void
}

/** One JSON value, or one JSON value per line. Undefined when the text is not JSON. */
function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    const lines = text.split("\n").filter((line) => line.trim())
    try {
      return lines.length > 1 ? lines.map((line) => JSON.parse(line)) : undefined
    } catch {
      return undefined
    }
  }
}

function describe(answer: IngestAnswer): string {
  const problem = answer.errors.length > 0 ? `; refused: ${answer.errors[0].error}` : ""
  return `Sent. Taken ${answer.accepted}, incidents changed ${answer.incidents}${problem}`
}

export function DemoPage({ onSelectIncident, onGoTo }: Props) {
  const live = API_MODE === "live"
  const [status, setStatus] = useState<DemoStatus | null>(null)
  const [incidents, setIncidents] = useState<IncidentRow[]>([])
  const [pollError, setPollError] = useState<string | null>(null)
  const [speed, setSpeed] = useState(40)
  const [message, setMessage] = useState<string | null>(null)
  const [done, setDone] = useState<number[]>([])
  const [text, setText] = useState("")
  const [source, setSource] = useState("auto")

  useEffect(() => {
    if (!live) return
    let active = true

    async function refresh() {
      try {
        const [next, rows] = await Promise.all([demoStatus(), listIncidents()])
        if (active) {
          setStatus(next)
          setIncidents(rows)
          setPollError(null)
        }
      } catch (err) {
        if (active) setPollError(err instanceof Error ? err.message : "The API is not reachable")
      }
    }

    void refresh()
    const timer = window.setInterval(() => void refresh(), 1000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [live])

  async function run<T>(action: () => Promise<T>, report: (value: T) => string) {
    setMessage(null)
    try {
      setMessage(report(await action()))
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "That did not work")
    }
  }

  async function sendCustom() {
    const body = text.trim()
    if (!body) return
    const parsed = parseJson(body)
    await run(async () => {
      if (parsed !== undefined) return sendJson(parsed, source === "auto" ? undefined : source)
      if (source === "auto") throw new Error("A raw log line needs its source: choose one in the list")
      return sendRaw(source, body)
    }, describe)
  }

  if (!live) {
    return (
      <div className="p-5">
        <Panel title="Demo" icon={<Play size={14} />}>
          <div className="flex min-h-[320px] items-center justify-center px-4 py-8">
            <DataReadout dim>The demo controls need the live API: start the web with VITE_API=live.</DataReadout>
          </div>
        </Panel>
      </div>
    )
  }

  const controlsOn = status?.enabled === true
  const running = status?.running === true

  return (
    <div className="space-y-4 p-5">
      {pollError && <DataReadout className="block text-xs text-error">{pollError}</DataReadout>}
      {message && <DataReadout className="block text-xs">{message}</DataReadout>}

      <Panel title="Recorded attack" icon={<Play size={14} />} bodyClassName="space-y-3 p-4">
        {!controlsOn ? (
          <DataReadout dim className="block text-xs">
            The replay controls are off. Start the API with DECONFLICTED_DEMO=1.
          </DataReadout>
        ) : (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1">
                <span className="text-[10px] uppercase tracking-wide text-on-surface-variant">Speed</span>
                <select value={speed} onChange={(event) => setSpeed(Number(event.target.value))} className={FIELD}>
                  {SPEEDS.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>

              <button
                type="button"
                disabled={running}
                onClick={() => void run(() => startAttack(speed), () => "Replaying the recorded attack. Open the Incidents or Graph tab and watch.")}
                className={BUTTON}
              >
                <Play size={12} />
                Run recorded attack
              </button>

              <button
                type="button"
                onClick={() =>
                  void run(async () => {
                    await resetDemo()
                    setDone([])
                  }, () => "Reset. Incidents, events and decoy hits are cleared.")
                }
                className={BUTTON}
              >
                <RotateCcw size={12} />
                Reset
              </button>
            </div>

            {status && status.total > 0 && (
              <DataReadout dim className="block text-xs">
                {running ? "Replaying" : "Done"}: {status.sent} of {status.total} events
              </DataReadout>
            )}
            {status?.error && <DataReadout className="block text-xs text-error">{status.error}</DataReadout>}
          </>
        )}
      </Panel>

      <Panel title="Attacker console" icon={<Send size={14} />} bodyClassName="space-y-2 p-4">
        <DataReadout dim className="block text-xs">
          Each button sends one step of the attack, stamped with the time of now.
        </DataReadout>

        {ATTACK_STEPS.map((step, index) => (
          <div
            key={step.title}
            className="flex flex-col gap-2 border border-outline-variant bg-surface-container-low p-2.5 sm:flex-row sm:items-center"
          >
            <button
              type="button"
              onClick={() =>
                void run(async () => {
                  const answer = await sendJson(step.body())
                  setDone((previous) => [...previous, index])
                  return answer
                }, describe)
              }
              className={`${BUTTON} sm:w-36 sm:shrink-0`}
            >
              {done.includes(index) ? "Sent" : "Send"} step {index + 1}
            </button>

            <div className="min-w-0">
              <div className="font-mono text-[11px] font-semibold text-on-surface">{step.title}</div>
              <div className="font-mono text-[10px] text-on-surface-variant">Say: {step.say}</div>
            </div>
          </div>
        ))}
      </Panel>

      <Panel title="Send your own event" icon={<Send size={14} />} bodyClassName="space-y-3 p-4">
        <textarea
          value={text}
          onChange={(event) => setText(event.target.value)}
          rows={5}
          placeholder="Paste one JSON event, several (one per line), or one raw log line"
          className={`${FIELD} w-full`}
          aria-label="Event to send"
        />

        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wide text-on-surface-variant">Source</span>
            <select value={source} onChange={(event) => setSource(event.target.value)} className={FIELD}>
              {SOURCES.map((name) => (
                <option key={name} value={name}>
                  {name === "auto" ? "auto (JSON only)" : name}
                </option>
              ))}
            </select>
          </label>

          <button type="button" disabled={!text.trim()} onClick={() => void sendCustom()} className={BUTTON}>
            <Send size={12} />
            Send
          </button>
        </div>
      </Panel>

      <Panel
        title="Follow along"
        bodyClassName="space-y-2 p-4"
        aside={
          <button type="button" onClick={() => onGoTo("incidents")} className={BUTTON}>
            Open incidents
          </button>
        }
      >
        {incidents.length === 0 ? (
          <DataReadout dim className="block text-xs">
            No incidents yet.
          </DataReadout>
        ) : (
          incidents.map((row) => (
            <div
              key={row.id}
              className="flex flex-wrap items-center gap-3 border border-outline-variant bg-surface-container-low p-2.5"
            >
              <DataReadout className="text-xs">{row.id}</DataReadout>
              <DataReadout dim className="text-[10px] uppercase">
                {row.severity}
              </DataReadout>
              <span className="min-w-0 flex-1 font-mono text-[11px] text-on-surface">{row.title}</span>
              <button
                type="button"
                className={BUTTON}
                onClick={() => {
                  onSelectIncident(row.id)
                  onGoTo("graph")
                }}
              >
                Graph
              </button>
              <button
                type="button"
                className={BUTTON}
                onClick={() => {
                  onSelectIncident(row.id)
                  onGoTo("response")
                }}
              >
                Response
              </button>
            </div>
          ))
        )}
      </Panel>
    </div>
  )
}