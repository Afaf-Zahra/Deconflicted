# AGENTS.md

Deconflicted is an offline IT/OT threat hunter. It finds living-off-the-land intrusions by behaviour, joins weak signals into one incident mapped to MITRE ATT&CK, keeps false-positive incidents within an alert budget, checks every automated response against process-safety rules, and records decisions in a hash-chained, co-signed ledger. It runs from one Docker command with no internet.

## Read first
1. `deconflicted/schema.py` has every shared type and interface. Do not guess a field name.
2. `docs/conventions.md` covers UTC, ids, entity ids, behaviour tokens, OT registers and the ledger hash recipes.
3. `docs/scenario.md` is the story every test and the demo are built around.
4. `config/hosts.yaml` lists the hosts, roles, users and decoys that exist.

## Setup
- Python 3.11 and Node 22. Do not use other versions.
- Windows: `py -3.11 -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt`.
- Linux and macOS: `python3.11 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt`.
- Activate the venv in every terminal before using `make` (Windows: `.venv\Scripts\Activate.ps1`).
- Windows also needs GNU Make: `winget install ezwinports.make`, then reopen the terminal.
- PyTorch is only for the scorer. Ayaz installs it with `python -m pip install -r requirements-ml.txt`.
- Python tests: `python -m pytest tests -q`. The contract tests alone: `python -m pytest tests/contracts -q`.
- Web: `cd web && npm ci && npm run lint && npm test && npm run build`.
- Make targets used across the project: `make test`, `make demo`, `make intake`, `make calibrate`, `make audit-verify`.

## Layout
- `deconflicted/` holds all Python: `schema.py`, `fakes.py`, `adapters/`, `ingest/`, `core/`, `eval/`, `sim/`, `deception/`, `response/`, `ledger/`, `ml/` and `api/`.
- `config/` holds YAML. `data/` holds organizer files and generated data. `docker/`, `scripts/` and `docker-compose.yml` hold the infrastructure.
- `web/` is the UI. `docs/` is documentation. `tests/` holds Python tests.

## Ownership (one owner per file)
Branch prefix shows whose work it is: `atif/`, `ayaz/`, `afaf/`, `maimoona/`. Only edit files in your own list. Before you open a pull request, run `git diff --name-only main` and check that every path is yours. If you need a change in a file you do not own, ask its owner.

- **Atif:**
  - Python: `schema.py`, `fakes.py`, `core/`, `eval/`, `ingest/` (mapper and sniffer), `sim/attack/`, `sim/build.py`, `sim/__init__.py`, `api/main.py` and every `api/routes_*.py` not listed under Ayaz.
  - Tests and data: `tests/contracts/`, `tests/fixtures/`, `data/`.
  - Config: `config/hosts.yaml`, `roles.yaml`, `routines.yaml`, `invariants.yaml`, `attack_map.yaml`.
  - Project files: `AGENTS.md`, `Makefile`, `README.md`, `pytest.ini`, `.gitignore`, requirements files.
  - Docs: `docs/conventions.md`, `docs/scenario.md`, `docs/metrics.md`.
  - Web mocks: `web/mock/incidents.json`, `events.json`, `budget.json`, `graph.json`.
- **Ayaz:**
  - Python: `adapters/`, `sim/roles/`, `sim/process.py`, `sim/replay.py`, `deception/`, `response/`, `ledger/`, `ml/`, `api/routes_ledger.py`, `routes_response.py`, `routes_audit.py`, `routes_decoys.py`.
  - Config: `config/decoys.yaml`, `actions.yaml`, `safety_rules.yaml`, `policy.yaml`.
  - Infrastructure: `docker-compose.yml`, `docker/`, `scripts/`.
  - Shared UI base: `web/package.json`, lockfile, `vite.config.ts`, `index.html`, `public/`, `src/App.tsx`, `src/Root.tsx`, `src/main.tsx`, `src/index.css`, `src/components/layout/`, `src/components/primitives/`, `src/lib/`.
  - Web mocks: `web/mock/preview.json`, `ledger.json`, `nodes.json`, `verify.json`, `audit.json`, `decoys.json`.
  - Tests: `tests/adapters`, `tests/sim_roles`, `tests/deception`, `tests/response`, `tests/ledger`, `tests/ml`.
- **Afaf:** `web/src/components/analyst/`, `web/src/pages/analyst/`, `web/tests/analyst/`, `docs/README_demo.md`, `docs/demo_script.md`, `docs/safety_and_evaluation_plan.md`, `docs/qa_afaf.md`.
- **Maimoona:** `web/src/components/trust/`, `web/src/pages/trust/`, `web/tests/trust/`, `web/scripts/check_offline.sh`, `docs/data_plan.md`, `docs/deception_strategy.md`, `docs/qa_maimoona.md`.

## Rules for every change
- **Write tests alongside your code.** Never claim a feature works unless a test shows it. Never edit a test to make it pass.
- **Fail closed.** Any error, unknown input, missing model or missing rule means block or reject, never allow. This applies to the response guard, the ledger verify and config integrity.
- **UTC only.** Every timestamp is timezone-aware UTC. A naive datetime is a bug (the schema rejects it).
- **Deterministic.** Same input gives the same output. Seed every random generator. Event ids are `f"{source}-{sha1(raw)[:12]}"`.
- **Offline.** No network call, no download at runtime, no external API, no CDN or external fonts in the UI. Model weights and data ship in the repo or the image.
- **No secrets in the repo.** No private keys, tokens or passwords. Ledger keys are generated at start-up.
- **Contracts are frozen.** Do not rename or remove a field in `schema.py`, a file name, or a mock shape. If it does not fit, tell Atif.
- **Mock first for the UI.** Build against `web/mock/` and switch to the API with `VITE_API=live`. If a field is missing show a placeholder, never crash, never invent a field.
- **Keep scope tight.** One task per pull request, only the files it needs, no unrelated reformatting.
- **Docs:** easy words, short sentences, no emojis, no em dashes. Do not claim anything the demo does not show. Leave unknown numbers as TODO.
- **Commit messages:** short, past tense, one task per commit (for example `Added the Windows adapter`).

## Definition of done
- New behaviour has a test and the whole suite passes.
- The web build, lint and tests pass on Node 22.
- `git diff --name-only main` lists only files you own.
- For response and ledger work: the zero-disruption test (violations = 0) and the tamper tests pass.