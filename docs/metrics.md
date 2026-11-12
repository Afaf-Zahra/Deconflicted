# Metrics

How we measure Deconflicted. Every number in the docs and the demo comes from `make calibrate`, which writes `data/eval/report.json`. Numbers marked TODO are filled in from that report. Do not write a number here that the report did not produce.

## Labels
Test data has a label on each event. `label.attack` is true for a malicious event. `label.step` is its position in the attack chain (1, 2, 3, and so on). Benign events have no attack label.

## Detection metrics

| Metric | Meaning | How it is measured | Target |
|---|---|---|---|
| False incidents per 24 hours | Incidents opened on benign data only | Count incidents on one full benign day | At most the alert budget (default 5) |
| Calibration check | The threshold is not tuned to one day | Set the threshold on benign day A, then count incidents on held-out benign day B | Day B count at most the budget |
| Chain recovery | How much of the attack is in the incident | Labeled steps found in the incident divided by all labeled steps | TODO |
| One incident per attack | The attack is not split into pieces | Number of incidents that contain attack events | Exactly 1 |
| Time to first meaningful alert | How fast the analyst is told | `first_alert_ts` minus `first_event_ts`, in seconds | TODO |
| ATT&CK mapping accuracy | Steps get the right tactic and technique | Chain steps whose technique matches the labeled technique, divided by all steps | TODO |

- `first_event_ts` is the time of the earliest attack event in the incident.
- A "meaningful" alert is an opened incident that contains at least one attack event. A held weak signal does not count.
- Report the mean and the worst case across the variant attacks, not only the main scenario.

## Safety metrics

| Metric | Meaning | How it is measured | Target |
|---|---|---|---|
| Zero-disruption violations | Executed actions that leave the process unsafe | Run many seeds and variant attacks. After every executed action, simulate 300 seconds and check every safety rule | **0** |
| Cases run | How strong the claim is | Count of seed and attack combinations in the run | TODO (report it next to the 0) |
| Unsafe actions stopped | The guard does its job | Proposed actions that failed the check and were blocked or downgraded, divided by all that failed | 100% |
| Fail closed | Errors never allow an action | Tests with a missing model, a bad rule or bad input must return block | All pass |

## Ledger metrics

| Metric | Meaning | How it is measured | Target |
|---|---|---|---|
| Tamper detection | Edits are caught | Edit, delete, reorder or insert an entry, then verify | Every tamper detected, first broken entry named |
| Clean verify | No false alarms | Verify an untouched export | Reports valid |
| Quorum | One bad node cannot sign alone | An approval with fewer than 2 of 3 signatures is rejected | All pass |

## Scorer metric
The PyTorch scorer is turned on only if the evaluator shows it does not make things worse: false incidents per 24 hours not higher, chain recovery not lower, time to first alert not later. If any gets worse, the scorer stays off and the system runs on the baseline model alone. The report prints both runs side by side.

## Report format
`data/eval/report.json` has one entry per metric above, with the value, the target and a pass or fail flag. The docs quote the file and nothing else.