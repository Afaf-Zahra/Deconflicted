import hashlib
import json
from dataclasses import replace

import pytest

from deconflicted.ledger import (GENESIS, QuorumError, entry_hash, load_policy, merkle_root, payload_hash,
                                 verify_export, verify_ingest)
from deconflicted.ledger.client import LedgerClient
from deconflicted.ledger.policy import PolicyError
from deconflicted.ledger.verify_cli import main as verify_cli

from .conftest import CONFIG, make_ledger


def fill(client, count=4):
    kinds = ["detection", "response_decision", "approval", "detection"]
    return [client.append(kinds[i % 4], {"n": i, "note": f"entry {i}"}) for i in range(count)]


def reasons(report):
    return sorted({(e.seq, e.reason) for e in report.errors})


def test_hash_recipes():
    assert payload_hash({"b": 1, "a": 2}) == hashlib.sha256(b'{"a":2,"b":1}').hexdigest()
    from datetime import datetime, timezone
    ts = datetime(2026, 3, 4, 3, 40, tzinfo=timezone.utc)
    expected = hashlib.sha256(f"0|{ts.isoformat()}|detection|abc|{GENESIS}".encode()).hexdigest()
    assert entry_hash(0, ts, "detection", "abc", GENESIS) == expected
    assert entry_hash(0, ts.isoformat(), "detection", "abc", GENESIS) == expected


def test_clean_chain_verifies(ledger):
    entries = fill(ledger.client)
    assert entries[0].prev_hash == GENESIS
    assert [e.prev_hash for e in entries[1:]] == [e.entry_hash for e in entries[:-1]]
    assert all(len(e.signatures) == 3 for e in entries), "all three nodes were up and signed"
    report = ledger.client.verify()
    assert report.ok and report.checked == 4 and report.errors == []
    assert set(report.heads) == set(ledger.policy.nodes)
    assert set(report.heads.values()) == {entries[-1].entry_hash}
    assert [e.seq for e in ledger.client.entries(limit=2, offset=1)] == [1, 2]


def test_entries_hash_matches_the_recipe(ledger):
    entry = ledger.client.append("detection", {"a": 1})
    assert entry.payload_hash == payload_hash({"a": 1})
    assert entry.entry_hash == entry_hash(entry.seq, entry.ts, entry.kind, entry.payload_hash, entry.prev_hash)


def test_editing_a_payload_is_caught_at_that_entry(ledger):
    fill(ledger.client)
    ledger.client.db.execute("UPDATE entries SET payload=? WHERE seq=2", (json.dumps({"n": 99}),))
    assert reasons(ledger.client.verify()) == [(2, "payload_hash_mismatch")]


def test_deleting_an_entry_is_caught(ledger):
    fill(ledger.client)
    ledger.client.db.execute("DELETE FROM entries WHERE seq=1")
    found = reasons(ledger.client.verify())
    assert (2, "prev_mismatch") in found and (1, "head_divergence") in found


def test_reordering_two_entries_is_caught(ledger):
    fill(ledger.client)
    db = ledger.client.db
    one, two = (db.execute("SELECT ts,kind,payload,payload_hash,prev_hash,entry_hash FROM entries WHERE seq=?", (s,)).fetchone()
                for s in (1, 2))
    db.execute("UPDATE entries SET ts=?,kind=?,payload=?,payload_hash=?,prev_hash=?,entry_hash=? WHERE seq=1", two)
    db.execute("UPDATE entries SET ts=?,kind=?,payload=?,payload_hash=?,prev_hash=?,entry_hash=? WHERE seq=2", one)
    assert (1, "entry_hash_mismatch") in reasons(ledger.client.verify())


def test_a_forged_signature_is_caught(ledger):
    fill(ledger.client)
    sig = ledger.client.db.execute("SELECT sig FROM signatures WHERE seq=1 AND node='node-a'").fetchone()[0]
    forged = ("0" if sig[0] != "0" else "1") + sig[1:]
    ledger.client.db.execute("UPDATE signatures SET sig=? WHERE seq=1 AND node='node-a'", (forged,))
    assert reasons(ledger.client.verify()) == [(1, "bad_signature")], "two good signatures still meet the quorum"


def test_too_few_signatures_is_caught(ledger):
    fill(ledger.client)
    ledger.client.db.execute("DELETE FROM signatures WHERE seq=1 AND node IN ('node-a','node-b')")
    assert reasons(ledger.client.verify()) == [(1, "quorum_missing")]


def test_one_node_down_still_commits_and_two_down_does_not(ledger):
    ledger.switches["node-c"].down = True
    entry = ledger.client.append("response_decision", {"decision": "allow"})
    assert sorted(s.node for s in entry.signatures) == ["node-a", "node-b"]
    report = ledger.client.verify()
    assert report.ok and set(report.heads) == {"node-a", "node-b"}
    assert [(n.node, n.up) for n in ledger.client.node_status()] == [("node-a", True), ("node-b", True), ("node-c", False)]
    ledger.switches["node-b"].down = True
    with pytest.raises(QuorumError):
        ledger.client.append("response_decision", {"decision": "block"})
    assert ledger.client.count() == 1, "a failed append must write nothing"
    ledger.switches["node-b"].down = False
    assert ledger.client.append("response_decision", {"decision": "block"}).seq == 1, "the sequence continues cleanly"


def test_a_node_that_was_down_catches_up(ledger):
    ledger.switches["node-c"].down = True
    fill(ledger.client, 3)
    ledger.switches["node-c"].down = False
    assert ledger.client.node_status()[2].head != ledger.client.head()[1], "node-c is behind"
    entry = ledger.client.append("detection", {"after": "outage"})
    assert len(entry.signatures) == 3, "node-c caught up first, then signed"
    report = ledger.client.verify()
    assert report.ok and set(report.heads.values()) == {entry.entry_hash}


def test_sync_brings_a_node_up_to_date(ledger):
    ledger.switches["node-c"].down = True
    fill(ledger.client, 3)
    ledger.switches["node-c"].down = False
    assert ledger.client.sync() == {"node-a": 2, "node-b": 2, "node-c": 2}


def test_a_node_with_a_different_chain_is_reported(ledger):
    fill(ledger.client)
    store = ledger.apps["node-a"].state.store
    store.db.execute("UPDATE entries SET entry_hash=? WHERE seq=1", ("f" * 64,))
    store.db.commit()
    assert (1, "head_divergence") in reasons(ledger.client.verify())


def test_only_hashes_reach_the_nodes(ledger):
    ledger.client.append("detection", {"secret": "do not send"})
    sent = [body for switch in ledger.switches.values() for _, body in switch.sent]
    assert sent, "something must have been sent"
    for body in sent:
        assert set(body) == {"seq", "ts", "kind", "payload_hash", "prev_hash", "entry_hash"}
        assert "do not send" not in json.dumps(body)
    columns = [r[1] for r in ledger.apps["node-a"].state.store.db.execute("PRAGMA table_info(entries)")]
    assert "payload" not in columns


def test_the_debug_tamper_is_caught(ledger):
    fill(ledger.client)
    assert ledger.client.tamper() == 3
    assert reasons(ledger.client.verify()) == [(3, "payload_hash_mismatch")]
    with pytest.raises(LookupError):
        ledger.client.tamper(99)


def test_the_chain_survives_a_restart(ledger):
    fill(ledger.client, 2)
    again = LedgerClient(ledger.path / "client.db", ledger.nodes, ledger.policy)
    assert again.head() == ledger.client.head()
    assert again.append("detection", {"n": 2}).seq == 2 and again.verify().ok


# ---------------------------------------------------------------- ingest anchoring
def test_merkle_roots():
    h = lambda x: hashlib.sha256(x.encode()).digest()
    assert merkle_root(["a"]) == h("a").hex()
    assert merkle_root(["a", "b"]) == hashlib.sha256(h("a") + h("b")).hexdigest()
    ab, cc = hashlib.sha256(h("a") + h("b")).digest(), hashlib.sha256(h("c") + h("c")).digest()
    assert merkle_root(["a", "b", "c"]) == hashlib.sha256(ab + cc).hexdigest(), "an odd last leaf is repeated"
    with pytest.raises(ValueError):
        merkle_root([])


def test_ingest_anchoring_detects_missing_and_changed_events(tmp_path):
    ledger = make_ledger(tmp_path, replace(load_policy(CONFIG / "policy.yaml"), anchor_interval=3))
    ids = [f"windows-{i:012d}" for i in range(7)]
    wrote = [ledger.client.note_event(i) for i in ids]
    assert wrote == [False, False, True, False, False, True, False]
    assert ledger.client.flush_anchor() is True and ledger.client.flush_anchor() is False
    anchors = ledger.client.ingest_anchors()
    assert [(a["from_index"], a["to_index"], a["count"]) for a in anchors] == [(0, 2, 3), (3, 5, 3), (6, 6, 1)]
    assert anchors[0]["root"] == merkle_root(ids[:3])
    assert verify_ingest(ids, anchors) == []
    assert verify_ingest(ids, ledger.client) == [], "the ledger client can be passed directly"
    deleted = verify_ingest(ids[:3] + ids[4:], anchors)
    assert [(p["from_index"], p["reason"]) for p in deleted] == [(3, "root_mismatch"), (6, "events_missing")], \
        "a deleted event is located in the range where the roots first stop matching"
    changed = ids[:4] + ["windows-changed0000"] + ids[5:]
    assert verify_ingest(changed, anchors) == [{"from_index": 3, "to_index": 5, "reason": "root_mismatch"}]
    assert ledger.client.verify().ok
    again = LedgerClient(tmp_path / "client.db", ledger.nodes, ledger.policy)
    again.note_event("windows-next"), again.flush_anchor()
    assert again.ingest_anchors()[-1]["from_index"] == 7, "the event index continues after a restart"


def test_a_failed_anchor_keeps_the_events_for_a_retry(tmp_path):
    ledger = make_ledger(tmp_path, replace(load_policy(CONFIG / "policy.yaml"), anchor_interval=2))
    ledger.switches["node-b"].down = ledger.switches["node-c"].down = True
    assert ledger.client.note_event("e1") is False and ledger.client.note_event("e2") is False
    assert ledger.client.count() == 0
    ledger.switches["node-b"].down = False
    assert ledger.client.note_event("e3") is True
    assert ledger.client.ingest_anchors()[0]["count"] == 3


# ---------------------------------------------------------------- export and offline verify
def test_export_verifies_offline_and_tampering_is_found(ledger, tmp_path, capsys):
    fill(ledger.client)
    export = ledger.client.export()
    assert export["version"] == 1 and export["quorum"] == 2 and set(export["pubkeys"]) == set(ledger.policy.nodes)
    assert verify_export(export).ok
    path = tmp_path / "export.json"
    path.write_text(json.dumps(export))
    assert verify_cli([str(path)]) == 0
    assert capsys.readouterr().out.strip() == "OK checked=4"
    export["entries"][2]["payload"]["n"] = 999
    path.write_text(json.dumps(export))
    assert verify_cli([str(path)]) == 1
    assert "seq=2 reason=payload_hash_mismatch" in capsys.readouterr().out
    assert not verify_export(export).ok


def test_offline_verify_fails_closed(ledger, tmp_path, capsys):
    fill(ledger.client)
    export = ledger.client.export()
    del export["entries"][1]
    assert not verify_export(export).ok
    stripped = ledger.client.export()
    stripped["entries"][1]["signatures"] = stripped["entries"][1]["signatures"][:1]
    assert (1, "quorum_missing") in reasons(verify_export(stripped))
    assert not verify_export({}).ok and not verify_export({"quorum": 2}).ok
    (tmp_path / "bad.json").write_text("not json")
    assert verify_cli([str(tmp_path / "bad.json")]) == 1
    assert verify_cli([str(tmp_path / "missing.json")]) == 1
    assert verify_cli([]) == 1
    capsys.readouterr()


# ---------------------------------------------------------------- the nodes themselves
def test_node_rejects_bad_headers(ledger):
    node = ledger.nodes["node-a"]
    entry = ledger.client.append("detection", {"a": 1})
    good = {"seq": 1, "ts": "2026-03-04T00:10:00+00:00", "kind": "detection", "payload_hash": "a" * 64,
            "prev_hash": entry.entry_hash, "entry_hash": entry_hash(1, "2026-03-04T00:10:00+00:00", "detection", "a" * 64, entry.entry_hash)}
    assert node.propose(good)[0] == "ok"
    assert node.propose({**good, "entry_hash": "b" * 64})[0] == "fail", "entry_hash must recompute"
    assert node.propose({**good, "kind": "nonsense"})[0] == "fail"
    assert node.propose({**good, "ts": "2026-03-04T00:10:00"})[0] == "fail", "naive timestamps are refused"
    wrong_prev = {**good, "prev_hash": "c" * 64}
    wrong_prev["entry_hash"] = entry_hash(1, wrong_prev["ts"], "detection", "a" * 64, "c" * 64)
    assert node.propose(wrong_prev)[0] == "fail", "must extend the node's own chain"
    gap = {**good, "seq": 5}
    gap["entry_hash"] = entry_hash(5, gap["ts"], "detection", "a" * 64, entry.entry_hash)
    assert node.propose(gap)[0] == "gap"


def test_node_commit_is_idempotent_and_conflicts_are_refused(ledger):
    node = ledger.nodes["node-b"]
    header = ledger.client._header(ledger.client._rows()[0]) if ledger.client.count() else None
    entry = ledger.client.append("detection", {"a": 1})
    header = ledger.client._header(ledger.client._rows()[0])
    assert node.commit(header) is True and node.commit(header) is True
    other = {**header, "payload_hash": "d" * 64}
    other["entry_hash"] = entry_hash(0, header["ts"], "detection", "d" * 64, header["prev_hash"])
    assert node.propose(other)[0] == "fail", "a different entry at an existing seq is a conflict"
    assert entry.seq == 0


def test_node_keeps_its_key_across_restarts(tmp_path):
    from deconflicted.ledger.node import create_app
    first = create_app("node-a", tmp_path).state.store.pubkey
    assert create_app("node-a", tmp_path).state.store.pubkey == first
    assert create_app("node-b", tmp_path).state.store.pubkey != first


# ---------------------------------------------------------------- policy
def test_policy_loading_and_needed_signatures():
    policy = load_policy(CONFIG / "policy.yaml")
    assert policy.nodes == ("node-a", "node-b", "node-c") and policy.quorum == 2
    assert all(policy.needed(kind) == 2 for kind in policy.signatures_required), "the quorum is the floor"
    assert replace(policy, quorum=1).needed("policy_change") == 2, "a kind can ask for more than the quorum"


@pytest.mark.parametrize("edit", ["quorum: 2->5", "unknown kind", "bad interval"])
def test_bad_policy_is_refused(tmp_path, edit):
    text = (CONFIG / "policy.yaml").read_text()
    if edit == "quorum: 2->5":
        text = text.replace("quorum: 2 ", "quorum: 5 ")
    elif edit == "unknown kind":
        text = text.replace("  detection: 1", "  made_up: 1")
    else:
        text = text.replace("anchor_interval_events: 500", "anchor_interval_events: 0")
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_a_lost_ledger_store_gives_a_clear_error(ledger):
    fill(ledger.client, 2)
    fresh = LedgerClient(ledger.path / "new-store.db", ledger.nodes, ledger.policy)
    with pytest.raises(QuorumError) as err:
        fresh.append("detection", {"n": 0})
    text = str(err.value)
    assert "0 of 3 nodes signed" in text and "conflict" in text and "docker compose down -v" in text
    assert fresh.count() == 0


def test_a_quorum_error_names_the_unreachable_nodes(ledger):
    ledger.switches["node-b"].down = ledger.switches["node-c"].down = True
    with pytest.raises(QuorumError) as err:
        ledger.client.append("detection", {"n": 0})
    assert "node-b: node unreachable" in str(err.value) and "node-c: node unreachable" in str(err.value)
    assert "docker compose down" not in str(err.value), "the reset hint only appears for a store mismatch"
