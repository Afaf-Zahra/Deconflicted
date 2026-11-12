"""The ledger client: keeps the full entries, collects node signatures, verifies, exports.

Only hashes leave this process. Nodes receive headers (seq, ts, kind, payload_hash, prev_hash,
entry_hash) and never the payload.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from deconflicted.schema import LedgerEntry, LedgerKind, NodeStatus, Signature, VerifyError, VerifyReport

from .anchor import merkle_root
from .chain import GENESIS, entry_hash, payload_hash
from .policy import Policy
from .verify import check_entries, signature_ok


class QuorumError(RuntimeError):
    """Not enough nodes signed. The entry was not written and the action must not go ahead."""


class NodeHandle:
    """Talks to one node. `client` is an httpx.Client (or a Starlette TestClient) for that node."""

    def __init__(self, name: str, client: httpx.Client):
        self.name, self.client = name, client

    def _call(self, method: str, path: str, **kwargs):
        try:
            response = self.client.request(method, path, **kwargs)
        except httpx.HTTPError:
            return None
        return response

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if close:
            close()

    def health(self) -> bool:
        response = self._call("GET", "/health")
        return response is not None and response.status_code == 200

    def pubkey(self) -> str | None:
        response = self._call("GET", "/pubkey")
        return response.json()["pubkey"] if response is not None and response.status_code == 200 else None

    def head(self) -> dict | None:
        response = self._call("GET", "/head")
        return response.json() if response is not None and response.status_code == 200 else None

    def headers(self, start: int = 0) -> list[dict] | None:
        response = self._call("GET", "/headers", params={"from": start})
        return response.json() if response is not None and response.status_code == 200 else None

    def propose(self, header: dict) -> tuple[str, str]:
        """Returns ("ok", signature), ("gap", ""), or ("fail", reason)."""
        response = self._call("POST", "/propose", json=header)
        if response is None:
            return "fail", "node unreachable"
        if response.status_code == 200:
            return "ok", response.json()["sig"]
        detail = str(response.json().get("detail", "")) if response.headers.get("content-type", "").startswith("application/json") else ""
        return ("gap", detail) if response.status_code == 409 and detail.startswith("gap") else ("fail", detail)

    def commit(self, header: dict) -> bool:
        response = self._call("POST", "/commit", json=header)
        return response is not None and response.status_code == 200


def http_node(name: str, url: str, timeout: float = 2.0) -> NodeHandle:
    return NodeHandle(name, httpx.Client(base_url=url, timeout=timeout))


class LedgerClient:
    """Implements the Ledger protocol: append() and verify()."""

    def __init__(self, db_path: str | Path, nodes: dict[str, NodeHandle], policy: Policy,
                 clock: Callable[[], datetime] | None = None):
        self.nodes, self.policy = nodes, policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = threading.RLock()
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, payload TEXT, "
            "payload_hash TEXT, prev_hash TEXT, entry_hash TEXT);"
            "CREATE TABLE IF NOT EXISTS signatures (seq INTEGER, node TEXT, sig TEXT, PRIMARY KEY (seq, node));"
            "CREATE TABLE IF NOT EXISTS pubkeys (node TEXT PRIMARY KEY, pubkey TEXT);")
        self.db.commit()
        self._pending_ids: list[str] = []
        last = self.last_of_kind("ingest_anchor")
        self._next_event_index = last[1]["to_index"] + 1 if last else 0

    def close(self) -> None:
        """Close the connections to the nodes and the local store."""
        for node in self.nodes.values():
            node.close()
        with self.lock:
            self.db.close()

    # ------------------------------------------------------------------ reading
    def head(self) -> tuple[int, str]:
        with self.lock:
            row = self.db.execute("SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (-1, GENESIS)

    def _rows(self, where: str = "", args: tuple = ()) -> list[dict]:
        with self.lock:  # one connection is shared by the API's worker threads
            rows = self.db.execute("SELECT seq, ts, kind, payload, payload_hash, prev_hash, entry_hash FROM entries "
                                   f"{where} ORDER BY seq", args).fetchall()
            signatures = self.db.execute("SELECT seq, node, sig FROM signatures ORDER BY seq, node").fetchall()
        sigs: dict[int, list[dict]] = {}
        for seq, node, sig in signatures:
            sigs.setdefault(seq, []).append({"node": node, "sig": sig})
        return [{"seq": r[0], "ts": r[1], "kind": r[2], "payload": json.loads(r[3]), "payload_hash": r[4],
                 "prev_hash": r[5], "entry_hash": r[6], "signatures": sigs.get(r[0], [])} for r in rows]

    def entries(self, limit: int = 100, offset: int = 0) -> list[LedgerEntry]:
        rows = self._rows("WHERE seq >= ? AND seq < ?", (offset, offset + limit))
        return [LedgerEntry(**{k: v for k, v in row.items() if k != "payload"}) for row in rows]

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def payloads(self, *kinds: str) -> list[tuple[int, dict]]:
        marks = ",".join("?" for _ in kinds)
        return [(r["seq"], r["payload"]) for r in self._rows(f"WHERE kind IN ({marks})", kinds)]

    def last_of_kind(self, kind: str) -> tuple[int, dict] | None:
        found = self.payloads(kind)
        return found[-1] if found else None

    def ingest_anchors(self) -> list[dict]:
        return [payload for _, payload in self.payloads("ingest_anchor")]

    # ------------------------------------------------------------------ keys
    def _pubkey(self, node: str) -> str | None:
        row = self.db.execute("SELECT pubkey FROM pubkeys WHERE node=?", (node,)).fetchone()
        if row:
            return row[0]
        key = self.nodes[node].pubkey()  # first use: remember the node's key
        if key:
            self.db.execute("INSERT OR IGNORE INTO pubkeys VALUES (?,?)", (node, key))
            self.db.commit()
        return key

    def _pubkeys(self) -> dict[str, str]:
        with self.lock:
            return {node: key for node, key in self.db.execute("SELECT node, pubkey FROM pubkeys")}

    # ------------------------------------------------------------------ writing
    @staticmethod
    def _header(row: dict) -> dict:
        return {k: row[k] for k in ("seq", "ts", "kind", "payload_hash", "prev_hash", "entry_hash")}

    def _sync_node(self, node: NodeHandle) -> None:
        """Send the entries a node is missing, in order, so it can catch up."""
        head = node.head()
        if head is None:
            return
        for row in self._rows("WHERE seq > ?", (head["seq"],)):
            if not node.commit(self._header(row)):
                return

    def sync(self) -> dict[str, int]:
        """Catch every reachable node up. Returns each node's head sequence number afterwards."""
        with self.lock:
            result = {}
            for name, node in self.nodes.items():
                self._sync_node(node)
                head = node.head()
                result[name] = head["seq"] if head else -2
            return result

    def append(self, kind: LedgerKind, payload: dict[str, Any]) -> LedgerEntry:
        with self.lock:
            seq, prev = self.head()
            seq += 1
            ts = self._clock()
            digest = payload_hash(payload)
            row = {"seq": seq, "ts": ts.isoformat(), "kind": kind, "payload_hash": digest,
                   "prev_hash": prev, "entry_hash": entry_hash(seq, ts, kind, digest, prev)}
            header = self._header(row)
            valid: dict[str, str] = {}
            why: dict[str, str] = {}
            for name, node in self.nodes.items():
                status, sig = node.propose(header)
                if status == "gap":
                    self._sync_node(node)
                    status, sig = node.propose(header)
                if status == "ok" and signature_ok(self._pubkey(name), row["entry_hash"], sig):
                    valid[name] = sig
                else:
                    why[name] = sig if status != "ok" else "signature did not verify"
            needed = self.policy.needed(kind)
            if len(valid) < needed:
                detail = "; ".join(f"{n}: {r or status}" for n, r in why.items())
                hint = (" The nodes hold entries this ledger store does not have. If the store was deleted but the node "
                        "data was kept, remove both together (docker compose down -v).") if "conflict" in detail else ""
                raise QuorumError(f"{len(valid)} of {len(self.nodes)} nodes signed, {needed} needed for {kind} ({detail}).{hint}")
            self.db.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?)",
                            (seq, row["ts"], kind, json.dumps(payload, sort_keys=True), digest, prev, row["entry_hash"]))
            self.db.executemany("INSERT INTO signatures VALUES (?,?,?)", [(seq, n, s) for n, s in valid.items()])
            self.db.commit()
            for name in valid:  # best effort; a node that misses this catches up with sync()
                self.nodes[name].commit(header)
            return LedgerEntry(seq=seq, ts=ts, kind=kind, payload_hash=digest, prev_hash=prev,
                               entry_hash=row["entry_hash"],
                               signatures=[Signature(node=n, sig=s) for n, s in valid.items()])

    # ------------------------------------------------------------------ verifying
    def verify(self) -> VerifyReport:
        with self.lock:
            rows = self._rows()
            errors = check_entries(rows, self._pubkeys(), self.policy.needed)
            local = {r["seq"]: r["entry_hash"] for r in rows}
            heads: dict[str, str] = {}
            for name, node in self.nodes.items():
                headers = node.headers(0) if node.health() else None
                if headers is None:
                    continue  # a node that is down is shown as down, not as an error
                for item in headers:
                    if local.get(item["seq"]) != item["entry_hash"]:
                        errors.append(VerifyError(seq=item["seq"], reason="head_divergence"))
                        break
                head = node.head()
                if head:
                    heads[name] = head["hash"]
            errors.sort(key=lambda e: e.seq)
            return VerifyReport(ok=not errors, checked=len(rows), errors=errors, heads=heads)

    def node_status(self) -> list[NodeStatus]:
        status = []
        for name, node in self.nodes.items():
            up = node.health()
            head = node.head() if up else None
            with self.lock:
                signed = self.db.execute("SELECT COUNT(*) FROM signatures WHERE node=?", (name,)).fetchone()[0]
            status.append(NodeStatus(node=name, up=up, head=head["hash"] if head else "", signatures=signed))
        return status

    # ------------------------------------------------------------------ ingest anchoring
    def note_event(self, event_id: str) -> bool:
        """Count one ingested event. Anchors a Merkle root every `anchor_interval` events.

        Returns True when an anchor was written. A failed anchor (no quorum) is retried later.
        """
        with self.lock:
            self._pending_ids.append(event_id)
            if len(self._pending_ids) >= self.policy.anchor_interval:
                return self.flush_anchor()
            return False

    def flush_anchor(self) -> bool:
        with self.lock:
            if not self._pending_ids:
                return False
            start, count = self._next_event_index, len(self._pending_ids)
            try:
                self.append("ingest_anchor", {"from_index": start, "to_index": start + count - 1,
                                              "count": count, "root": merkle_root(self._pending_ids)})
            except QuorumError:
                return False
            self._next_event_index += count
            self._pending_ids = []
            return True

    # ------------------------------------------------------------------ export and tamper demo
    def export(self) -> dict:
        with self.lock:
            return {"version": 1, "generated_at": self._clock().isoformat(), "quorum": self.policy.quorum,
                    "signatures_required": dict(self.policy.signatures_required),
                    "pubkeys": self._pubkeys(), "entries": self._rows()}

    def tamper(self, seq: int | None = None) -> int:
        """Debug only: change one stored payload without fixing its hash."""
        with self.lock:
            last = self.head()[0]
            target = last if seq is None else seq
            row = self.db.execute("SELECT payload FROM entries WHERE seq=?", (target,)).fetchone()
            if row is None:
                raise LookupError(f"no entry with seq {target}")
            changed = {**json.loads(row[0]), "tampered": True}
            self.db.execute("UPDATE entries SET payload=? WHERE seq=?", (json.dumps(changed, sort_keys=True), target))
            self.db.commit()
            return target
