# Measurements: data, safety guard, scorer and stack

Numbers from real runs. Each section shows how to run it again. A number marked TODO was not measured.

## Benign day size

Call `day_lines(date, seed)` from `deconflicted.sim.roles`.


- One day (2026-03-04), seeds 1 to 5: **16,753 to 17,002 lines**. The target was 15,000 to 60,000.
- Seed 1 by source: flow 7,488, modbus 6,591, opcua 2,859, windows 35, proxy 27, linux 2.
- Seed 1 by actor: dave 6,481, background 10,344, carol 112, bob 25, svc-backup 23, alice 17.
- Most lines are plant (OT) traffic and flows. Only about 80 lines a day are admin activity on the IT side. A role baseline
  learned from one day has little to learn from, so use several benign days. TODO: say how many days the baseline needs.

## Response safety guard

```
python -m deconflicted.response.zero_disruption --cases 20000 --seed 11
```

| Run | Cases | Actions | Allowed | Downgraded | Blocked | Violations | Time |
|---|---|---|---|---|---|---|---|
| Day 1 size | 1,000 (seed 7) | 9,000 | 6,170 | 1,830 | 1,000 | **0** | 12.8 s |
| Day 2 size | 20,000 (seed 11) | 180,000 | 123,491 | 36,509 | 20,000 | **0** | 4 min 11 s |

- Each case is a random starting state: level, setpoint, pump, valve and 0 to 3 attacker writes. 20 percent of cases start
  with the process already outside its limits.
- Each case asks the guard about nine actions. The one action that is always blocked is `isolate_host plc-2`, because only
  `plc-1` has a process model.
- The check was also run against a guard that allows everything. It reports violations, so the check can fail.
- Time was measured on one CPU core.

## PyTorch scorer

```
python -m deconflicted.ml.train --simulate 3 --out deconflicted/ml/weights
```

- Trained on 3 simulated benign days: 48 sequences, 10,015 windows, vocabulary of 15 tokens, 8 epochs.
- Training time **9.6 s** on CPU. Final loss 0.1559.
- Saved files: `scorer.pt` 115 KB and `vocab.json` 269 bytes.
- An attack-like token sequence scores **1.0**. A held-out benign day averages **0.62**.
- Same weights and same input always give the same score.

## Ledger

- Three nodes, 2 of 3 signatures needed.
- Tested over real HTTP with three separate processes: one node down still commits, two down refuses, and nodes that were down
  catch up when they return.
- Tested in the running stack: restarting the API keeps the ledger, and the audit export verifies offline inside a container.
- TODO: entries per second. It was not measured.

## Docker stack

Measured with the images built from the same Dockerfiles, without PyTorch (`--build-arg WITH_ML=0`).

| Item | Result |
|---|---|
| Start from built images until the API is healthy | about 12 s |
| API image | 383 MB (without PyTorch) |
| Web image | 189 MB |
| Two images saved with `docker save` | 89 MB |
| Replay of the 75 minute demo window at speed 60 | 75 s, 155 events in 75 batches |
| `scripts/offline_check.sh` with the host offline | 8 of 8 steps pass, 88 s |

- The ledger nodes are on a network with no route out. From inside a node, an outside address fails to resolve. The node
  ports are not reachable from the host.
- TODO: image size with PyTorch installed from the CPU index.
- TODO: `docker compose up --build` end to end. The images were built with `docker build`, then started with
  `docker compose up --no-build`.

## Tests

- 231 Python tests and 23 web tests, all passing. Python tests run with warnings treated as errors.
- Web: clean `npm ci`, lint with 0 warnings, build, and 0 audit findings on Node 22.
