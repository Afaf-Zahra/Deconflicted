# Deconflicted

An offline IT/OT threat hunter. It finds attacks that use normal admin tools, joins weak signals into one incident mapped to MITRE ATT&CK, keeps false alarms within a budget, checks every automated response against process-safety rules, and records decisions in a hash-chained ledger across three nodes.

## What it does

## Overview

```mermaid
flowchart LR
    logs["Raw logs: Windows, proxy, flow, Linux, Modbus, OPC-UA"] --> ingest["POST /ingest: adapters parse each line into an Event"]
    ingest --> pipe["Detection pipeline"]
    pipe --> inc["Incidents, graph and alert budget"]
    inc --> api["API: incidents, graph, events, budget"]
    api --> ui["Web UI: Incidents, Graph, Response, Ledger, Decoys"]
    ui --> guard["Safety guard: 300 s tank simulation"]
    guard --> led[("Ledger: 3 nodes, 2 of 3 signatures")]
    pipe --> led
    cfg["Protected config files"] --> pipe
    cfg -.-> led
```

## How it works

1. Raw logs from six sources are parsed into one event type. The event id comes from the unchanged log line.
2. Each event becomes a behaviour token such as `proc:powershell_enc`.
3. A per-role statistical baseline scores how rare the behaviour is, by sequence and by hour of day. Rules add the certain signals.
4. The pipeline joins signals into incidents, applies the budget, and records each incident in the ledger.
5. The analyst previews a response, approves it, and the decision is signed into the ledger.

### What happens to one event

```mermaid
flowchart TD
    E["Event"] --> T["Behaviour token"]
    T --> D{"Decoy touched, log cleared or OT rule broken?"}
    D -- yes --> C["Certain signal: opens or joins an incident"]
    D -- no --> M{"Fits a known admin routine?"}
    M -- yes --> N["No signal"]
    M -- no --> S{"Baseline score at or above the weak threshold, or a routine broken?"}
    S -- no --> N
    S -- yes --> H{"Score at or above the strong threshold?"}
    H -- yes --> Q{"Room left in the quota for incidents opened by a score alone?"}
    Q -- yes --> C
    Q -- no --> HOLD["Held signal"]
    H -- no --> HOLD
    HOLD --> P["Promoted into an incident that shares a user, workstation or PLC"]
```

### How signals become one incident

The demo attack as the system sees it. Weak signals are held until a certain signal opens the incident, then they are pulled in.

```mermaid
flowchart LR
    s1["03:40 Odd-hour logon by alice: weak"] --> inc
    s2["03:43 powershell -enc: weak"] --> inc
    s3["03:48 nltest from the wrong host: weak"] --> inc
    s4["03:48 Decoy touched: certain"] --> inc
    s5["04:00 Admin share on file-01 then eng-ws-01: weak"] --> inc
    s6["04:20 Audit log cleared: certain"] --> inc
    s7["04:50 Setpoint write of 95 to plc-1: certain"] --> inc
    inc{{"One critical incident with an ATT&CK chain and a graph"}}
```

### How the ledger signs an entry

Each node signs the entry hash when it is proposed. The entry commits once two of the three have signed. One node can be down.

```mermaid
sequenceDiagram
    participant API
    participant A as node-a
    participant B as node-b
    participant C as node-c
    API->>A: propose the entry hash
    API->>B: propose the entry hash
    API->>C: propose the entry hash
    A-->>API: signature
    B-->>API: signature
    C--xAPI: no answer
    Note over API: 2 of 3 signatures, so the entry commits
    API->>A: commit
    API->>B: commit
```

### How a response is approved

```mermaid
sequenceDiagram
    actor Analyst
    participant UI
    participant API
    participant Guard as Safety guard
    participant Ledger
    Analyst->>UI: choose a proposed action
    UI->>API: preview, with the incident and the action
    API->>Guard: simulate 300 s before and after
    Guard-->>API: allow, downgrade or block, with the traces
    API->>Ledger: record the decision
    API-->>UI: the preview
    Analyst->>UI: approve as analyst-1
    UI->>API: approve the action
    alt decision is block
        API-->>UI: refused, nothing is applied
    else allow or downgrade
        API->>Ledger: signed approval, 2 of 3 nodes
        API-->>UI: ledger entry number
    end
```

- **Finds attacks that look normal.** It learns what each role does on a normal day (admin, helpdesk, engineer, operator, service account) and flags behaviour that does not fit. A known admin routine is left alone.
- **Certain signals.** Touching a decoy, clearing an audit log and writing an out-of-range value to the PLC are always flagged, whatever the score.
- **One incident, not a pile of alerts.** Weak signals are held and joined into one incident when they share a user, a workstation or a PLC. The incident has an ATT&CK timeline, the point where the activity stops matching a routine, and a graph.
- **A false-alarm budget.** At most 5 incidents per day, and at most 3 of them opened by a score alone.
- **Safe response.** Every proposed action is simulated against a water-tank model for 300 seconds. The guard allows it, downgrades it to a safer option or blocks it. It fails closed on any error.
- **A record nobody can quietly change.** Detections, guard decisions and approvals go into a hash-chained ledger on three nodes. Each entry needs 2 of 3 signatures. A changed entry, or a changed safety config file, is detected.

## Run it

You need Python 3.11 and Node 22. The repository already holds the demo data, the trained baseline and the calibrated threshold.

Set up once (Windows PowerShell):

```
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd web
npm ci
cd ..
```

Then use three terminals in the project folder. In the first, start the API with an in-process ledger:

```
.venv\Scripts\Activate.ps1
$env:DECONFLICTED_LEDGER_EMBEDDED = "1"
python -m uvicorn deconflicted.api.main:app --port 8000
```

In the second, start the UI against it:

```
cd web
$env:VITE_API = "live"
npm run dev
```

In the third, replay the attack. At 60 times speed it takes about 90 seconds:

```
.venv\Scripts\Activate.ps1
python -m deconflicted.sim.replay --file data\demo\scenario.jsonl --speed 60 --url http://localhost:8000
```

Open http://localhost:5173 and watch the incident build. Without `VITE_API=live` the UI shows the mock data in `web/mock/`.

### Docker

```
make demo
docker compose --profile demo run --rm replay
```

The UI is at http://localhost:8080. The stack was built and tested in pieces. It has not been run end to end on the final code, so run it once before relying on it.

## Results

All numbers come from `data/eval/report.json`, written by `make calibrate`. The data is simulated: a scripted attack and its 10 variants, mixed into simulated normal days. They show that the engine works as designed. They are not a measure of how it would do against a real attacker.

| Measure | Result |
|---|---|
| False incidents on a held-out normal day (budget 5) | 3 |
| Attack scenarios with exactly one incident | 11 of 11 |
| Attack scenarios missed | 0 |
| Chain recall (labeled steps found) | 1.0, mean and worst |
| Zero-disruption violations in 300 random safety cases | 0 |
| Ledger tampers found at the right entry | 5 of 5 |

The optional PyTorch scorer was not evaluated (PyTorch was not installed for the run), so it stays off. To change the thresholds, edit `config/detection.yaml`, or run `make calibrate` again.

## How it works

1. Raw logs from six sources are parsed into one event type. The event id comes from the unchanged log line.
2. Each event becomes a behaviour token such as `proc:powershell_enc`.
3. A per-role statistical baseline scores how rare the behaviour is, by sequence and by hour of day. Rules add the certain signals.
4. The pipeline joins signals into incidents, applies the budget, and records each incident in the ledger.
5. The analyst previews a response, approves it, and the decision is signed into the ledger.

## Layout

- `deconflicted/` holds all Python: `adapters/`, `ingest/`, `core/` (detection), `eval/`, `sim/`, `deception/`, `response/`, `ledger/`, `ml/` and `api/`.
- `config/` holds the YAML settings. `data/` holds the demo data and the evaluation report.
- `web/` is the UI. `docs/` is documentation. `tests/` holds the Python tests.

## Limits

- It is a prototype for an isolated network. There is no login: the analyst name is a label checked against a list.
- It has only been run on simulated data in the spec's sample log formats. New formats need a mapping file (`docs/ingest.md`).
- The safety guard simulates one water tank.

## More

- `AGENTS.md`: setup, folder ownership and the rules for every change.
- `docs/scenario.md`: the attack story the tests and the demo follow.
- `docs/conventions.md`: ids, tokens and the ledger hash recipes.
- `docs/metrics.md`: how each number is measured.
- `docs/ingest.md`: how logs are read and how to add a format.

## Credits

The web UI is adapted from NeuralShield (https://github.com/atif09/sh).