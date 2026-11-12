# Scenario: the day the attacker looks like an admin

All times are UTC on 2026-03-04. Hosts, users and ids match `config/hosts.yaml` and `docs/conventions.md`.

## The normal day (what the baseline learns)
- **alice** (admin) logs on from `ws-admin-01`, runs scheduled admin tasks, and uses PowerShell, `nltest` and `wmic` as part of known routines.
- **bob** (helpdesk) resets passwords from `ws-help-01` through PowerShell. This is a known routine and must not raise an incident.
- **carol** (engineer) works from `eng-ws-01` and writes setpoints to `plc-1` inside the allowed range (40 to 60).
- **dave** (operator) watches `plc-1` and `plc-2` from `ops-ws-01`.
- **svc-backup** (service) runs only `backup.exe` in the backup window.
- Background traffic runs continuously through `proxy-01`, `file-01`, `hist-01` and the PLCs.

## The attack (what the red team does, one chain)
Every command below is a normal admin tool. No step matches a malware signature.

| Time | Step | Tactic | What happens |
|---|---|---|---|
| 03:40:00 | 1 | Initial Access (T1078) | alice's account logs on to `dc-01` from `ws-help-01` at an odd hour. Weak signal, held. |
| 03:43:02 | 2 | Execution (T1059.001) | `powershell.exe -enc ...` on `ws-help-01` as alice. Strong signal. **Chain stop:** it is not part of any known admin routine. |
| 03:48:05 | 3 | Discovery (T1018) | `nltest /dclist:corp`. Alone this looks like routine admin work. Weak signal, held. |
| 03:48:20 | 4 | Discovery (T1018) | `ws-help-01` connects to the decoy `dc-decoy-01` (10.0.2.99:445). Nothing legitimate ever touches it. |
| 04:20:00 | 5 | Defense Evasion (T1070.001) | The audit log on `file-01` is cleared. |
| 04:50:00 | 6 | Impair Process Control (T0836) | A Modbus write of 95 to `plc-1` register 40001, from `eng-ws-01`. The allowed range is 40 to 60. |

## What the system must do
1. **One incident, not six alerts.** INC-0042 (critical) holds the whole chain. The two held weak signals (steps 1 and 3) are promoted into it because strong signals on the same entities arrive within the window.
2. **Time to first alert.** The first alert is at 03:44:12, 4 min 12 s after the first malicious event.
3. **Chain stop.** The view shows where the activity stopped matching an admin routine (step 2) and why.
4. **Decoy and OT anchors.** Steps 4 and 6 are certain on their own (decoy hit, broken process rule) and anchor the incident.
5. **Log clearing is exposed.** Step 5 becomes a `log_clear` signal and is also visible as a gap or tamper in the ledger.
6. **Mapped to ATT&CK.** Each step carries its tactic and technique.

## The response (what the guard decides)
The incident proposes three actions. The guard simulates each one against the tank model (level, pump, valve) over a 300-second horizon and shows the before and after traces.

| Action | Intended demo outcome |
|---|---|
| `block_write` from `eng-ws-01` to `plc-1` | Allowed. The process stays safe. |
| `disable_account` alice | Allowed. No effect on the process. |
| `isolate_host` plc-1 | Blocked, or downgraded to the block-write option, with the reason shown. Cutting the PLC would leave the pump and valve uncontrolled and push the tank outside its safe limits. |

The analyst approves only after the check, and the approval is signed into the ledger. The zero-disruption test must show 0 violations across every action the system actually executes. These outcomes are the targets that Ayaz's response tests lock in.

## The other incidents on the day (the alert budget)
- **INC-0041 (warning):** `svc-backup` runs remote PowerShell and WMI outside its backup window. It counts toward the budget.
- **INC-0040 (info, closed):** bob's password-reset burst matches a known routine and is closed as normal.
- Budget: 3 of 5 incidents used in the 24 hours (the default budget is 5).

## Ledger story
- Every detection and every guard decision is appended to the hash chain and co-signed by two of the three nodes.
- Only hashes and signatures move between nodes.
- Clearing the audit log on `file-01` (step 5), or editing a config file, produces an `integrity_violation` signal and is shown in the ledger.
- The verify command on an exported audit file reports valid. If any line is edited, it reports the first broken entry.

## How to use this file
- Fixtures, mock data and the red-team replay all follow this timeline. Do not change a time, host or id without telling Atif.
- A new test that needs a scenario uses this one first. Add a new scenario only if this one cannot cover it.