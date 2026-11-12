# Conventions

One place for how things are written, so every module fits together.

## Time
- All timestamps are timezone-aware UTC. Never naive datetimes.
- In JSON and API responses: ISO 8601, for example `2026-03-04T03:40:00Z`.
- Durations in the safety simulation are seconds. Tank level is percent (0 to 100).

## Event ids
- `id = f"{source}-{sha1(raw.encode('utf-8')).hexdigest()[:12]}"` where `raw` is the original log line, unchanged.
- The same line always gives the same id. Labels never appear in raw logs; they live in a separate `labels.jsonl` keyed by event id.

## Event fields
- `source`: `windows`, `proxy`, `flow`, `linux`, `modbus`, `opcua`.
- `action`: `proc_create`, `logon`, `net_conn`, `http_request`, `flow`, `read`, `write`, `log_clear`.
- User names keep only the part after the last backslash or slash (`CORP\alice` becomes `alice`).
- Process names keep only the file name, lower case (`powershell.exe`).
- `obj`: register (`reg:40001`), OPC-UA node id, URL, file, share name (`C$`), or `logon_type:3`.
- Unknown extra fields stay inside `raw`; nothing is dropped silently.

## Entity ids (lower case)
- `host:ws-help-01`, `user:alice`, `proc:powershell.exe`, `plc:plc-1`, `decoy:dc-decoy-01`.
- A host that is not in `config/hosts.yaml` is written with its IP: `host:10.0.9.77`.

## Roles and users
- Roles: `admin`, `helpdesk`, `engineer`, `operator`, `service`.
- Users: `alice` (admin), `bob` (helpdesk), `carol` (engineer), `dave` (operator), `svc-backup` (service).

## Behaviour tokens
Format `category:detail`, lower case. The core derives them from events:

| Event | Token |
| --- | --- |
| process `powershell.exe` with `-enc` or `-encodedcommand` | `proc:powershell_enc` |
| process `powershell.exe` with `-File` | `proc:powershell_script` |
| any other `powershell.exe` | `proc:powershell` |
| `nltest.exe` | `proc:nltest` |
| `net.exe` or `net1.exe` with `view` / `user` | `proc:net_view` / `proc:net_user` |
| `certutil.exe` with `-urlcache` | `proc:certutil_download` |
| `backup.exe` | `proc:backup` |
| any other process | `proc:<name without .exe>` |
| `logon` | `auth:logon` (`auth:logon_failed` when obj is `failed`) |
| `log_clear` | `log:cleared` |
| `net_conn` or `flow` to port 445 with obj ending in `$` | `net:smb_admin` |
| `net_conn` or `flow` to port 445 otherwise | `net:smb` |
| other `net_conn` or `flow` | `net:flow` |
| `http_request` | `net:http` |
| any event whose destination is a decoy | `net:decoy_touch` |
| OT `read` | `ot:read` |
| OT `write` to the setpoint (`reg:40001` or `Tank1.Setpoint`) | `ot:write_setpoint` |
| OT `write` to the pump (`reg:40010` or `Tank1.PumpCmd`) | `ot:write_pump` |
| any other OT `write` | `ot:write_other` |

## OT registers (simulated tank)
- `40001` setpoint, `40002` level (read only), `40010` pump command, `40011` valve command.
- OPC-UA nodes: `ns=2;s=Tank1.Level`, `ns=2;s=Tank1.Setpoint`, `ns=2;s=Tank1.PumpCmd`.
- Modbus function codes: 3 and 4 are reads; 6 and 16 are writes.

## Values
- Signal `score` is 0 to 1. Severity is `info`, `warning` or `critical`. Incident status is `open` or `closed`.
- Tactic names are the exact ATT&CK tactic names (for example `Lateral Movement`, `Impair Process Control`).
- Check every ATT&CK technique id on attack.mitre.org before using it. Do not invent ids.

## Ledger hashes
- `payload_hash = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")))`
- `entry_hash = sha256(f"{seq}|{ts.isoformat()}|{kind}|{payload_hash}|{prev_hash}")`
- The first entry uses `prev_hash = "0" * 64`.

## Safety
- Fail closed: any error, unknown action, unknown target, or missing model means block, never allow.

## General
- JSON field names are `snake_case`. Files are UTF-8 with LF line endings.
- Everything is deterministic for a given seed. Never use unseeded randomness.
- Nothing may need the internet at run time: no CDN, no external fonts.
- Never commit keys, tokens or real personal data.