# Reading logs (ingest)

`deconflicted/ingest/` turns log files into `Event` objects. It does not detect anything.

```bash
python -m deconflicted.ingest data/organizer
python -m deconflicted.ingest data/organizer --out data/demo/organizer_scenario.jsonl
```

Every file is checked by its content, not its name. It is one of:

| Format | Looks like |
| --- | --- |
| `windows` | Sysmon-style JSON with `EventID` |
| `proxy` | Squid `access.log` |
| `flow` | CSV of 7 columns, the first a date (a header row is skipped) |
| `linux` | syslog (`Mar  4 01:00:03 host sshd[1]: ...`); the year comes from `--year` |
| `modbus` | JSON with `func` and `server` |
| `opcua` | JSON with `service` and `node` |
| `replay` | `{"source": ..., "raw": ...}` per line, the files `sim/build.py` writes |

A line that cannot be read is counted and skipped, and the first few messages name the file and line. A file that is
none of these is listed as `not recognized`. Times without a zone are read as UTC unless you pass `--strict-time`.

## A format we do not know: write a mapping

Put a YAML file in `config/mappings/` (or pass `--mappings DIR`). No code is needed.

```yaml
name: edr                       # not a built-in name
source: windows                 # which source the events count as
format: json                    # json, csv or regex
detect: {has: [event.kind, host.name]}   # optional: files whose lines have these fields use this mapping
timestamp: {field: "@timestamp", format: iso}   # iso, epoch, epoch_ms or a strptime pattern like "%d/%m/%Y %H:%M:%S"
action:
  field: event.kind             # or  constant: flow
  map: {process_start: proc_create, login: logon}
  default: net_conn             # optional
fields:                         # event field: field of the log (dotted paths walk into JSON)
  host: host.name
  user: user.name
  process: process.executable
  cmdline: process.command_line
  src_ip: source.ip
```

- Event fields you can map: `host user process parent_process cmdline src_ip dst_ip dst_port obj value`.
- If `host` is missing, it is looked up from `src_ip` in `config/hosts.yaml`.
- `csv` uses the first line as the header, or `columns: [a, b, c]`, and `delimiter`.
- `regex` uses named groups: `pattern: '^(?P<when>\S+) (?P<box>\S+) ran (?P<cmd>.+)$'`.
- Without `detect`, a mapping is only used when you ask for it: `--format edr`.
- The event id comes from the unchanged line, like every other format, and the line stays in `raw`.

## Live intake

Events do not have to come from files. The API takes them as they happen.

Send JSON directly. The body can be one object, an array, `{"events": [...]}`, `{"Records": [...]}` (the CloudTrail
wrapper) or one object per line (NDJSON). Built-in shapes (Sysmon, Modbus, OPC-UA) are recognized. A shape that a mapping
with `detect.has` describes is recognized too.

```
Invoke-RestMethod -Method Post -Uri http://localhost:8000/ingest/json -ContentType "application/json" -Body '{"EventID":1,"UtcTime":"2026-03-04T03:43:02.110Z","Computer":"ws-help-01","User":"CORP\\alice","Image":"C:\\Windows\\System32\\powershell.exe","CommandLine":"powershell.exe -enc AAAA"}'
```

- `?source=windows` forces a built-in format. `?mapping=edr` forces a mapping.
- The event id comes from the record with its keys sorted, so the same record always gets the same id. Sending it twice is harmless.
- The answer lists the records that could not be read, by position. The others are taken.

Follow files as they grow. Every new line is sent as soon as it is complete:

```
python -m deconflicted.ingest.follow C:\logs --url http://localhost:8000
```

- By default only lines written from now on are sent. `--from-start` sends what the files already hold.
- A rotated file is read again from its start. A file that appears later is read from its first line.
- If the API is down, nothing is lost: the lines are sent again when it is back.
- It follows built-in formats and replay files. Syslog lines carry no year, and the API reads them as 2026.
- The Incidents tab refreshes every 2 seconds, and the Graph tab does too in live mode.

## The Demo tab

Start the API with `DECONFLICTED_DEMO=1` and the web with `VITE_DEBUG=1`. A Demo tab appears. It can replay the recorded
attack (`data/demo/scenario.jsonl`) at a speed you choose, reset the system, send the attack one step at a time, or send
an event you paste. Reset clears incidents, events and decoy hits. The ledger keeps its history.