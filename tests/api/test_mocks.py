import json
from pathlib import Path

from deconflicted.ledger.chain import GENESIS, entry_hash
from deconflicted.schema import DecoysView, LedgerEntry, NodeStatus, Preview, VerifyReport

MOCK = Path(__file__).parents[2] / "web" / "mock"


def load(name):
    return json.loads((MOCK / name).read_text())


def test_preview_is_the_scenario_isolate_case():
    preview = Preview(**load("preview.json"))
    assert preview.decision == "downgrade" and preview.safer_options[0].kind == "block_write"
    assert [v.rule_id for v in preview.violations] == ["level_low"]
    assert [p.t for p in preview.before_trace] == [float(t) for t in range(0, 301, 10)]
    assert len(preview.after_trace) == 31


def test_ledger_follows_the_hash_recipe():
    entries = [LedgerEntry(**e) for e in load("ledger.json")]
    assert entries[0].prev_hash == GENESIS
    for earlier, later in zip(entries, entries[1:]):
        assert later.prev_hash == earlier.entry_hash
    for e in entries:
        assert e.entry_hash == entry_hash(e.seq, e.ts, e.kind, e.payload_hash, e.prev_hash)
        assert len(e.signatures) >= 2


def test_nodes_verify_and_audit_agree_with_the_ledger():
    entries = [LedgerEntry(**e) for e in load("ledger.json")]
    nodes = [NodeStatus(**n) for n in load("nodes.json")]
    assert [n.node for n in nodes] == ["node-a", "node-b", "node-c"] and all(n.up for n in nodes)
    assert {n.head for n in nodes} == {entries[-1].entry_hash}
    verify = VerifyReport(**load("verify.json"))
    assert verify.ok and verify.checked == len(entries) and set(verify.heads) == {"node-a", "node-b", "node-c"}
    audit = load("audit.json")
    assert audit["entries"] == len(entries) and audit["ok"] is True and audit["heads"] == verify.heads
    assert set(audit) == {"entries", "ok", "generated_at", "heads"}


def test_tampered_variant_has_exactly_one_error():
    tampered = VerifyReport(**load("verify_tampered.json"))
    assert not tampered.ok and len(tampered.errors) == 1
    assert tampered.errors[0].reason == "payload_hash_mismatch"


def test_decoys_view():
    view = DecoysView(**load("decoys.json"))
    assert [d.id for d in view.decoys] == ["dc-decoy-01", "plc-decoy-1"]
    assert [(h.decoy, h.source) for h in view.hits] == [("dc-decoy-01", "ws-help-01")]
    assert [p.safety_ok for p in view.placements] == [True, True]
