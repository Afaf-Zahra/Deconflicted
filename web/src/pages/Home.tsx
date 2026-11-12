import { ArrowRight, Database, GitMerge, Link2, Radar, ShieldCheck } from "lucide-react"
import { FloatingArtifacts } from "../components/home/FloatingArtifacts"
import { Reveal } from "../components/home/Reveal"

/** Landing page. Plain words and no numbers: everything here is something the product does. */
const WORKFLOW = [
  { n: "01", icon: Database, title: "Ingest", body: "Windows, proxy, flow, Linux, Modbus and OPC-UA logs become one event format." },
  { n: "02", icon: Radar, title: "Detect", body: "Each role has a normal routine. Steps outside it, decoy touches and broken process rules become signals." },
  { n: "03", icon: GitMerge, title: "Correlate", body: "Weak signals join into one incident, kept inside an alert budget and mapped to MITRE ATT&CK." },
  { n: "04", icon: ShieldCheck, title: "Respond", body: "Every action is simulated against the process before it can run. Unsafe actions are blocked or downgraded." },
  { n: "05", icon: Link2, title: "Record", body: "Detections and decisions go into a hash-chained ledger that three nodes sign together." },
]

const SAFETY = [
  "A response is tested on a model of the process first, and the before and after traces are shown.",
  "If anything is unknown or broken, the answer is block, never allow.",
  "An analyst approves only after the safety check, and the approval is signed into the ledger.",
]

const STACK = ["Python", "FastAPI", "NetworkX", "PyTorch", "React", "Docker"]

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" })
}

export function Home({ onLaunch }: { onLaunch: () => void }) {
  return (
    <div className="home-page min-h-screen bg-surface-container-lowest font-sans text-on-surface">
      <nav className="sticky top-0 z-50 flex items-center justify-between border-b border-outline-variant bg-surface-container-lowest/95 px-6 py-4 backdrop-blur">
        <span className="flex items-center gap-2 text-sm font-semibold tracking-tight">
          <span className="h-2 w-2 rounded-full bg-primary-container" />
          Deconflicted
        </span>
        <div className="hidden items-center gap-8 font-mono text-[12px] text-on-surface-variant md:flex">
          <button onClick={() => scrollTo("workflow")} className="transition-colors hover:text-on-surface">
            How it works
          </button>
          <button onClick={() => scrollTo("safety")} className="transition-colors hover:text-on-surface">
            Safety
          </button>
        </div>
        <button
          onClick={onLaunch}
          className="bg-on-surface px-4 py-2 font-mono text-[12px] font-semibold uppercase tracking-wider text-surface-container-lowest transition-opacity hover:opacity-90"
        >
          Open console
        </button>
      </nav>

      <section className="relative overflow-hidden border-b border-outline-variant px-6 py-28 text-center">
        <FloatingArtifacts />
        <div className="relative mx-auto flex max-w-3xl flex-col items-center gap-6">
          <span className="border border-outline-variant bg-surface-container px-3 py-1 font-mono text-[10px] uppercase tracking-[0.2em] text-on-surface-variant">
            Offline IT/OT threat hunting
          </span>
          <h1 className="text-5xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
            <span className="text-on-surface">Find the attack that looks like an admin.</span>
            <br />
            <span className="text-on-surface-variant">Check every response before it runs.</span>
          </h1>
          <p className="max-w-xl text-[15px] leading-relaxed text-on-surface-variant">
            Deconflicted watches IT and OT logs for intrusions that use normal admin tools. It joins weak signals into one
            incident, explains each step, and tests every automated response against process-safety rules. It runs without
            the internet.
          </p>
          <button
            onClick={onLaunch}
            className="flex items-center gap-2 bg-on-surface px-6 py-3 font-mono text-[12px] font-semibold uppercase tracking-wider text-surface-container-lowest transition-opacity hover:opacity-90"
          >
            Open console <ArrowRight size={14} />
          </button>
        </div>
      </section>

      <section id="workflow" className="border-b border-outline-variant px-6 py-20">
        <p className="mb-12 text-center font-mono text-[10px] uppercase tracking-[0.25em] text-on-surface-variant">How it works</p>
        <div className="mx-auto grid max-w-6xl grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-5">
          {WORKFLOW.map((step, i) => (
            <Reveal key={step.n} delayMs={i * 90} className="flex flex-col gap-3">
              <span className="font-mono text-[11px] text-on-surface-variant">{step.n}</span>
              <step.icon size={20} />
              <h3 className="text-base font-semibold">{step.title}</h3>
              <p className="text-[13px] leading-relaxed text-on-surface-variant">{step.body}</p>
            </Reveal>
          ))}
        </div>
      </section>

      <section id="safety" className="border-b border-outline-variant px-6 py-20">
        <div className="mx-auto max-w-3xl">
          <Reveal>
            <h2 className="mb-6 text-3xl font-bold tracking-tight">Nothing runs until it is proven safe.</h2>
            <ul className="flex flex-col gap-3 text-[14px] leading-relaxed text-on-surface-variant">
              {SAFETY.map((line) => (
                <li key={line} className="flex gap-3">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-primary-container" />
                  {line}
                </li>
              ))}
            </ul>
          </Reveal>
        </div>
      </section>

      <Reveal className="flex flex-wrap items-center justify-center gap-x-10 gap-y-4 border-b border-outline-variant px-6 py-14">
        {STACK.map((name) => (
          <span key={name} className="font-mono text-[12px] uppercase tracking-wider text-on-surface-variant">
            {name}
          </span>
        ))}
      </Reveal>

      <footer className="flex flex-col gap-2 px-6 py-10 font-mono text-[11px] text-on-surface-variant sm:flex-row sm:items-center sm:justify-between">
        <span className="font-semibold text-on-surface">Deconflicted</span>
        <span>Interface adapted from NeuralShield.</span>
      </footer>
    </div>
  )
}
