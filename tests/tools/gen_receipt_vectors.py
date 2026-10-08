#!/usr/bin/env python3
"""Regenerate the synthetic server-receipt test vectors, deterministically (fixed seeds, no randomness, no network).

A receipt is the service's signed statement about one accepted submission (ChainDBoM v2b_receipt.py, copied unchanged in
tests/tools/reference/v2b_receipt.py). Valid and damaged receipts are built here; the expected verdicts come from the
reference Python code, so the JavaScript check is compared with it. Needs: pip install cryptography rfc8785

    python tests/tools/gen_receipt_vectors.py
    python tests/tools/gen_receipt_vectors.py --check      # fail if files would change
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "receipt"
spec = importlib.util.spec_from_file_location("v2b_receipt_reference", Path(__file__).resolve().parent / "reference" / "v2b_receipt.py")
ref = importlib.util.module_from_spec(spec)
sys.modules["v2b_receipt_reference"] = ref
spec.loader.exec_module(ref)


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def keypair(name: str):
    private = Ed25519PrivateKey.from_private_bytes(sha(b"diadroma-verify synthetic receipt key " + name.encode()))
    return private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def uuid_for(label: str) -> str:
    return str(UUID(bytes=sha(b"diadroma-verify synthetic receipt id " + label.encode())[:16], version=4))


def receipt(private, public, key_id, client, submission, sequence, link_hash, received_at):
    body = {"format_version": 1, "client_id": client, "submission_id": submission, "client_sequence": sequence,
            "link_hash": link_hash, "received_at": received_at, "service_key_id": key_id,
            "service_public_key_hex": public.hex()}
    signature = private.sign(ref.RECEIPT_DOMAIN + ref.rfc8785.dumps(body))
    return {"body": body, "signature_b64": base64.b64encode(signature).decode()}


def sign_again(private, body):
    return {"body": body, "signature_b64": base64.b64encode(private.sign(ref.RECEIPT_DOMAIN + ref.rfc8785.dumps(body))).decode()}


def build():
    private, public = keypair("service-1")
    other_private, other_public = keypair("attacker")
    client = uuid_for("client")

    def item(n, **kw):
        link = kw.pop("link_hash", sha(f"link {n}".encode()).hex())
        return receipt(private, public, "receipt-2026-10", kw.pop("client", client), kw.pop("submission", uuid_for(f"submission {n}")),
                       n, link, kw.pop("at", f"2026-10-08T08:{n:02d}:30.123456Z"))

    good = item(1)
    vectors = {"valid": good}

    def changed(field, value):
        body = dict(good["body"]); body[field] = value
        return {"body": body, "signature_b64": good["signature_b64"]}   # signature no longer matches

    for field, value in [("client_id", uuid_for("other client")), ("submission_id", uuid_for("other submission")),
                         ("client_sequence", 2), ("link_hash", sha(b"other").hex()),
                         ("received_at", "2026-10-08T08:01:31.123456Z"), ("service_key_id", "other-key")]:
        vectors[f"tampered_{field}"] = changed(field, value)
    vectors["signed_by_another_key"] = receipt(other_private, other_public, "receipt-2026-10", client, uuid_for("submission 1"), 1,
                                               sha(b"link 1").hex(), "2026-10-08T08:01:30.123456Z")
    # an attacker swaps in the trusted public key without being able to sign: the signature is the attacker's
    swapped = dict(vectors["signed_by_another_key"]["body"], service_public_key_hex=public.hex())
    vectors["trusted_key_swapped_in"] = {"body": swapped, "signature_b64": vectors["signed_by_another_key"]["signature_b64"]}
    # well signed but malformed bodies: refused for their shape, not for their signature
    base = dict(good["body"])
    vectors["extra_body_field"] = sign_again(private, {**base, "extra": 1})
    vectors["missing_body_field"] = sign_again(private, {k: v for k, v in base.items() if k != "link_hash"})
    vectors["extra_top_field"] = {**good, "extra": 1}
    vectors["sequence_is_boolean"] = sign_again(private, {**base, "client_sequence": True})
    vectors["sequence_is_zero"] = sign_again(private, {**base, "client_sequence": 0})
    vectors["sequence_is_string"] = sign_again(private, {**base, "client_sequence": "1"})
    vectors["version_2"] = sign_again(private, {**base, "format_version": 2})
    vectors["uppercase_client_id"] = sign_again(private, {**base, "client_id": base["client_id"].upper()})
    vectors["uppercase_link_hash"] = sign_again(private, {**base, "link_hash": base["link_hash"].upper()})
    vectors["instant_without_microseconds"] = sign_again(private, {**base, "received_at": "2026-10-08T08:01:30Z"})
    vectors["instant_with_space"] = sign_again(private, {**base, "received_at": "2026-10-08 08:01:30.123456Z"})
    vectors["bad_key_id"] = sign_again(private, {**base, "service_key_id": "bad key!"})
    vectors["signature_not_base64"] = {**good, "signature_b64": "!!"}
    vectors["signature_too_short"] = {**good, "signature_b64": base64.b64encode(b"x" * 63).decode()}
    vectors["signature_null"] = {**good, "signature_b64": None}

    lists = {
        "list_consecutive": [item(1), item(2), item(3)],
        "list_with_gap": [item(1), item(2), item(5)],
        "list_conflict": [item(1), item(1, link_hash=sha(b"another link").hex())],
        "list_two_clients": [item(1), item(2), item(1, client=uuid_for("client b"))],
    }
    return vectors, lists, ref.fingerprint_of(public), (private, public)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    vectors, lists, fingerprint, _ = build()
    files, expected = {}, {"fingerprint": fingerprint, "single": {}, "lists": {}}
    for name, value in vectors.items():
        files[f"{name}.json"] = json.dumps(value, indent=2, sort_keys=True) + "\n"
        try:
            expected["single"][name] = {"ok": True, "body": ref.verify_receipt(value, trusted_fingerprint=fingerprint)}
        except ref.ReceiptError:
            expected["single"][name] = {"ok": False}
    for name, value in lists.items():
        files[f"{name}.json"] = json.dumps(value, indent=2, sort_keys=True) + "\n"
        bodies = [ref.verify_receipt(r, trusted_fingerprint=fingerprint) for r in value]
        problems = ref.find_sequence_gaps(bodies)
        kind = "conflict" if any("two different receipts" in p for p in problems) else "gap" if problems else "none"
        expected["lists"][name] = {"sequence": kind, "count": len(bodies)}
    files["expected.json"] = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    OUT.mkdir(parents=True, exist_ok=True)
    changed = []
    for filename, text in files.items():
        path = OUT / filename
        if not path.exists() or path.read_text() != text:
            changed.append(filename)
            if not args.check:
                path.write_text(text)
    stale = sorted(p.name for p in OUT.glob("*.json") if p.name not in files)
    if args.check and (changed or stale):
        print("receipt vectors out of date:", changed, stale)
        sys.exit(1)
    print(f"{len(vectors)} reçus, {sum(1 for e in expected['single'].values() if e['ok'])} valides, {len(lists)} listes ; fichiers mis à jour : {changed}")


if __name__ == "__main__":
    main()
