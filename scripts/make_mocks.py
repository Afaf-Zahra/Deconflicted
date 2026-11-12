"""Write the six UI mock files in web/mock/ from the real ledger, guard and decoy code.

  python scripts/make_mocks.py

Keys are generated fresh each run, so the signatures differ between runs. The files are always
consistent with each other and with schema.py.
"""
from __future__ import annotations

import itertools
import json
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deconflicted.deception import DecoyService  # noqa: E402
from deconflicted.ledger import ConfigIntegrity, LedgerClient, NodeHandle, load_policy  # noqa: E402
from deconflicted.ledger.node import create_app  # noqa: E402
from deconflicted.ledger.transport import in_process_client  # noqa: E402
from deconflicted.ledger.chain import payload_hash  # noqa: E402
from deconflicted.response import ResponseGuard, service  # noqa: E402
from deconflicted.schema import Action, Event  # noqa: E402

OUT = ROOT / "web" / "mock"


def write(name: str, data) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    work = Path(tempfile.mkdtemp())
    policy = load_policy(ROOT / "config" / "policy.yaml")
    nodes = {n: NodeHandle(n, in_process_client(create_app(n, work / n))) for n in policy.nodes}
    tick = itertools.count()
    start = datetime(2026, 3, 4, 3, 44, 12, tzinfo=timezone.utc)
    client = LedgerClient(work / "client.db", nodes, policy, clock=lambda: start + timedelta(seconds=15 * next(tick)))
    ConfigIntegrity(client, policy, root=ROOT).ensure_anchor()

    guard = ResponseGuard(str(ROOT / "config"))
    plan = [("act-001", "isolate_host", "plc-1", {}), ("act-002", "block_write", "eng-ws-01", {"to": "plc-1"}),
            ("act-003", "disable_account", "alice", {})]
    previews = {}
    for action_id, kind, target, params in plan:
        action = Action(id=action_id, kind=kind, target=target, params=params)
        previews[action_id] = guard.preview(action, service.DEMO_STATE)
    client.append("detection", {"incident_id": "INC-0042", "signal_ids": ["sig-004"], "note": "decoy hit on dc-decoy-01"})
    client.append("detection", {"incident_id": "INC-0042", "signal_ids": ["sig-006"], "note": "setpoint write of 95 to plc-1"})
    for action_id, preview in previews.items():
        client.append("response_decision", {
            "incident_id": "INC-0042", "action_id": action_id, "action": preview.action.model_dump(mode="json"),
            "decision": preview.decision, "reason": preview.reason,
            "safer_options": [o.model_dump(mode="json") for o in preview.safer_options],
            "preview_hash": payload_hash(preview.model_dump(mode="json"))})
    client.append("approval", {"action_id": "act-002", "analyst": "analyst-1", "decision": "approved",
                               "preview_hash": payload_hash(previews["act-002"].model_dump(mode="json")),
                               "applied_action": previews["act-002"].action.model_dump(mode="json")})

    write("preview.json", previews["act-001"].model_dump(mode="json"))
    write("ledger.json", [e.model_dump(mode="json") for e in client.entries(limit=1000)])
    write("nodes.json", [n.model_dump(mode="json") for n in client.node_status()])
    report = client.verify()
    write("verify.json", report.model_dump(mode="json"))
    audit = client.export()
    write("audit.json", {"entries": len(audit["entries"]), "ok": report.ok, "generated_at": audit["generated_at"],
                         "heads": report.heads})
    client.tamper(4)
    write("verify_tampered.json", client.verify().model_dump(mode="json"))

    flow = next(e for e in json.loads((ROOT / "tests" / "fixtures" / "events.json").read_text())
                if e["id"] == "flow-c7621933881f")
    decoys = DecoyService(str(ROOT / "config"))
    decoys.trigger(Event(**{k: v for k, v in flow.items() if k != "label"}))
    write("decoys.json", decoys.view("INC-0042").model_dump(mode="json"))
    shutil.rmtree(work, ignore_errors=True)
    print(f"wrote 7 files to {OUT}")


if __name__ == "__main__":
    main()
