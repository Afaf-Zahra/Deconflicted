"""Offline verification of an audit export. It needs no running node and no ledger store."""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from deconflicted.schema import VerifyError, VerifyReport

from .chain import GENESIS, entry_hash, payload_hash

REASONS = ("payload_hash_mismatch", "entry_hash_mismatch", "prev_mismatch", "bad_signature",
           "quorum_missing", "head_divergence")


def signature_ok(pubkey_hex: str | None, entry_hash_: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex or "")).verify(
            bytes.fromhex(sig_hex), entry_hash_.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def check_entries(entries: list[dict], pubkeys: dict[str, str], needed) -> list[VerifyError]:
    """Check hashes, links, signatures and quorum. `needed(kind)` gives the signatures required."""
    errors: list[VerifyError] = []
    expected_prev = GENESIS
    for position, entry in enumerate(entries):
        seq = entry.get("seq")
        found: list[str] = []
        try:
            if payload_hash(entry["payload"]) != entry["payload_hash"]:
                found.append("payload_hash_mismatch")
            if entry_hash(seq, entry["ts"], entry["kind"], entry["payload_hash"], entry["prev_hash"]) != entry["entry_hash"]:
                found.append("entry_hash_mismatch")
            if seq != position or entry["prev_hash"] != expected_prev:
                found.append("prev_mismatch")
            valid, bad = set(), False
            for item in entry.get("signatures", []):
                if signature_ok(pubkeys.get(item.get("node")), entry["entry_hash"], item.get("sig", "")):
                    valid.add(item["node"])
                else:
                    bad = True
            if bad:
                found.append("bad_signature")
            if len(valid) < needed(entry["kind"]):
                found.append("quorum_missing")
            expected_prev = entry["entry_hash"]
        except (KeyError, TypeError, ValueError):
            found = ["entry_hash_mismatch"]
            expected_prev = entry.get("entry_hash", "") if isinstance(entry, dict) else ""
        errors.extend(VerifyError(seq=seq if isinstance(seq, int) else position, reason=r) for r in found)
    return errors


def verify_export(data: dict) -> VerifyReport:
    """Verify an export produced by LedgerClient.export(). Anything malformed fails."""
    try:
        quorum = int(data["quorum"])
        required = data.get("signatures_required") or {}
        pubkeys = dict(data["pubkeys"])
        entries = list(data["entries"])
    except (KeyError, TypeError, ValueError):
        return VerifyReport(ok=False, checked=0, errors=[VerifyError(seq=0, reason="entry_hash_mismatch")])
    errors = check_entries(entries, pubkeys, lambda kind: max(quorum, int(required.get(kind, 0))))
    heads = {"export": entries[-1]["entry_hash"]} if entries and not errors else {}
    return VerifyReport(ok=not errors, checked=len(entries), errors=errors, heads=heads)
