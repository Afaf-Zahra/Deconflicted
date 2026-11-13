export type AttackStep = { title: string; say: string; body: () => unknown }

const stamp = () => new Date().toISOString()
const stampSeconds = () => stamp().replace(/\.\d{3}Z$/, "Z")
const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

/** The attack of docs/scenario.md, one button each, stamped with the time of now when it is sent. */
export const ATTACK_STEPS: AttackStep[] = [
  {
    title: "Log on as alice from the helpdesk PC",
    say: "An admin account used at an hour it never is. A weak signal.",
    body: () => ({ EventID: 4624, UtcTime: stamp(), Computer: "dc-01", TargetUserName: "alice", IpAddress: "10.0.1.21", LogonType: 3 }),
  },
  {
    title: "Run an encoded PowerShell command",
    say: "An admin never does this, and it is in no routine. This is where the chain stops looking normal.",
    body: () => ({
      EventID: 1, UtcTime: stamp(), Computer: "ws-help-01", User: "CORP\\alice", Image: POWERSHELL,
      ParentImage: "C:\\Windows\\explorer.exe", CommandLine: "powershell.exe -enc JABzAD0ATgBlAHcA",
    }),
  },
  {
    title: "Map the domain with nltest",
    say: "A known admin tool, but run from the wrong host.",
    body: () => ({
      EventID: 1, UtcTime: stamp(), Computer: "ws-help-01", User: "CORP\\alice", Image: "C:\\Windows\\System32\\nltest.exe",
      ParentImage: POWERSHELL, CommandLine: "nltest /dclist:corp",
    }),
  },
  {
    title: "Touch the decoy file server",
    say: "Nothing legitimate contacts it. A certain signal, and the decoy node turns red.",
    body: () => ({ source: "flow", raw: `${stampSeconds()},10.0.1.21,10.0.2.99,445,tcp,812,9` }),
  },
  {
    title: "Open the decoy file with vim",
    say: "The tool does not matter. vim, nano, cat or cp on this path is the same certain signal. Nobody has a reason to open it.",
    body: () => ({
      ts: stamp(), host: "file-01", user: "alice", process: "vim", op: "open", path: "/srv/finance/passwords_2026.xlsx",
    }),
  },
  {
    title: "Open the admin share on the file server",
    say: "Lateral movement with alice's account.",
    body: () => ({
      EventID: 5140, UtcTime: stamp(), Computer: "file-01", SubjectUserName: "CORP\\alice", IpAddress: "10.0.1.21",
      ShareName: "\\\\*\\C$",
    }),
  },
  {
    title: "Move on to the engineering workstation",
    say: "The graph reaches the OT side.",
    body: () => ({
      EventID: 5140, UtcTime: stamp(), Computer: "eng-ws-01", SubjectUserName: "CORP\\alice", IpAddress: "10.0.2.10",
      ShareName: "\\\\*\\C$",
    }),
  },
  {
    title: "Clear the audit log on the file server",
    say: "Covering tracks. Always flagged.",
    body: () => ({ EventID: 1102, UtcTime: stamp(), Computer: "file-01", SubjectUserName: "alice" }),
  },
  {
    title: "Write 95 to the PLC tank setpoint",
    say: "Outside 40 to 60. The incident turns critical. Seven alerts, one incident.",
    body: () => ({ ts: stamp(), server: "plc-1", client_ip: "10.0.3.5", func: 6, address: 40001, value: 95 }),
  },
]