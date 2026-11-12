"""One ledger node: a small service that checks headers, signs them and keeps its own copy.

Nodes only ever see hashes. A node signs an entry only if it extends its own chain.
Run:  python -m deconflicted.ledger.node --id node-a --port 9101 --data data/ledger
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import get_args

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from deconflicted.schema import LedgerKind

from .chain import GENESIS, entry_hash

_KINDS = set(get_args(LedgerKind))


class Header(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int
    ts: str
    kind: str
    payload_hash: str
    prev_hash: str
    entry_hash: str


def _load_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption()))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


class NodeStore:
    def __init__(self, node_id: str, data_dir: str | Path):
        directory = Path(data_dir)
        directory.mkdir(parents=True, exist_ok=True)
        self.node_id = node_id
        self.key = _load_key(directory / f"{node_id}.key")
        self.pubkey = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.lock = threading.Lock()
        self.db = sqlite3.connect(directory / f"{node_id}.db", check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, "
                        "payload_hash TEXT, prev_hash TEXT, entry_hash TEXT, sig TEXT)")
        self.db.commit()

    def head(self) -> tuple[int, str]:
        row = self.db.execute("SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (-1, GENESIS)

    def stored(self, seq: int):
        return self.db.execute("SELECT entry_hash, sig FROM entries WHERE seq=?", (seq,)).fetchone()

    def check(self, header: Header) -> str:
        """Validate a header against this node's chain. Returns the signature, or raises HTTPException."""
        if header.kind not in _KINDS:
            raise HTTPException(422, f"unknown ledger kind {header.kind!r}")
        try:
            datetime.fromisoformat(header.ts)
        except ValueError:
            raise HTTPException(422, "ts is not an ISO timestamp") from None
        if datetime.fromisoformat(header.ts).tzinfo is None:
            raise HTTPException(422, "ts has no time zone")
        if entry_hash(header.seq, header.ts, header.kind, header.payload_hash, header.prev_hash) != header.entry_hash:
            raise HTTPException(422, "entry_hash does not match the header")
        head_seq, head_hash = self.head()
        if header.seq <= head_seq:
            known = self.stored(header.seq)
            if known and known[0] == header.entry_hash:
                return known[1]
            raise HTTPException(409, f"conflict: this node already has a different entry at seq {header.seq}")
        if header.seq != head_seq + 1:
            raise HTTPException(409, f"gap: this node's head is seq {head_seq}")
        if header.prev_hash != head_hash:
            raise HTTPException(409, "prev_hash does not extend this node's chain")
        return self.key.sign(header.entry_hash.encode("ascii")).hex()

    def save(self, header: Header, sig: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO entries VALUES (?,?,?,?,?,?,?)",
                        (header.seq, header.ts, header.kind, header.payload_hash, header.prev_hash,
                         header.entry_hash, sig))
        self.db.commit()


def create_app(node_id: str, data_dir: str | Path) -> FastAPI:
    store = NodeStore(node_id, data_dir)
    app = FastAPI(title=f"Deconflicted ledger {node_id}")
    app.state.store = store

    @app.get("/health")
    def health():
        return {"status": "ok", "node": node_id}

    @app.get("/pubkey")
    def pubkey():
        return {"node": node_id, "pubkey": store.pubkey}

    @app.get("/head")
    def head():
        seq, digest = store.head()
        return {"node": node_id, "seq": seq, "hash": digest}

    @app.get("/headers")
    def headers(first: int = Query(0, alias="from")):
        rows = store.db.execute("SELECT seq, ts, kind, payload_hash, prev_hash, entry_hash, sig "
                                "FROM entries WHERE seq >= ? ORDER BY seq", (first,)).fetchall()
        return [dict(zip(("seq", "ts", "kind", "payload_hash", "prev_hash", "entry_hash", "sig"), r)) for r in rows]

    @app.post("/propose")
    def propose(header: Header):
        with store.lock:
            return {"node": node_id, "sig": store.check(header)}

    @app.post("/commit")
    def commit(header: Header):
        with store.lock:
            sig = store.check(header)
            store.save(header, sig)
            return {"node": node_id, "sig": sig}

    return app


def main(argv: list[str] | None = None) -> None:
    import uvicorn
    parser = argparse.ArgumentParser(description="Run one Deconflicted ledger node")
    parser.add_argument("--id", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data", default="data/ledger")
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args(argv)
    uvicorn.run(create_app(args.id, args.data), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
