# Deconflicted

An offline IT/OT threat hunter. It finds attacks that use normal admin tools, joins weak signals into one incident mapped to MITRE ATT&CK, keeps false alarms within a budget, checks every automated response against process-safety rules, and records decisions in a hash-chained ledger across three nodes. It runs from one Docker command with no internet.

## Run

```
make demo
```

## Develop

Read `AGENTS.md` first. It covers setup, folder ownership and the rules for every change. The shared types are in `deconflicted/schema.py`.

## Credits

The web UI is adapted from NeuralShield (https://github.com/atif09/sih).