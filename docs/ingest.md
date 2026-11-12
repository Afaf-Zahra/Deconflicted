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