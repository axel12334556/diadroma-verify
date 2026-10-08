"""Signed receipt for an accepted v2b submission (review finding D5).

Without it, a third party (or the client itself) cannot prove that the server once accepted a submission: the history
is only what the server says it is. The receipt is the server's signed statement

    "client C, submission S, was given sequence N, link hash H, at time T"

signed with a service key (Ed25519, domain "ChainDBoM:v2:receipt"). The client keeps it. Later:
  * a record that disappears from the server's history, or a history cut short by a bad restore, contradicts a receipt
    the client holds (see compare_with_heads and the heads printed by v2b_restore_check);
  * a gap in the sequence numbers of the receipts a client holds is visible to the client (find_sequence_gaps);
  * a client that recomputes link hashes from its own record hashes can check the whole chain.

What a receipt is NOT: it does not say the content is true, readable or anchored on Bitcoin; it does not stop the
operator from refusing to serve data; and if the service key leaks, forged receipts become possible for new records
(never a change to one already held: the client's copy keeps its own signature). The key lives in a Docker secret
file readable by the app container only, never in the database, the environment or the backups, and its fingerprint
is published OFF the server (docs/RECEIPTS_V2B.md). A receipt cannot validate itself: the verifier must be given the
fingerprint it trusts.

No database access in this module; the verify functions need no secret.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PublicFormat, load_pem_private_key

RECEIPT_DOMAIN = b"ChainDBoM:v2:receipt\x00"
FORMAT_VERSION = 1
BODY_FIELDS = frozenset({"format_version", "client_id", "submission_id", "client_sequence", "link_hash",
                         "received_at", "service_key_id", "service_public_key_hex"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
ENV_KEY_FILE = "CHAINDBOM_RECEIPT_KEY_FILE"
ENV_KEY_ID = "CHAINDBOM_RECEIPT_KEY_ID"


class ReceiptError(ValueError):
    pass


def format_instant(value: datetime) -> str:
    """UTC, microseconds, trailing Z: one spelling, so the signed text never depends on a locale or driver."""
    if value.tzinfo is None:
        raise ReceiptError("received_at must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def fingerprint_of(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


@dataclass(frozen=True)
class ReceiptSigner:
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: bytes

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.public_key)


def load_signer(path: str, key_id: str) -> ReceiptSigner:
    """Read an unencrypted PKCS#8 PEM Ed25519 key (`openssl genpkey -algorithm ed25519`). Fails closed."""
    if not isinstance(key_id, str) or _KEY_ID.match(key_id) is None:
        raise ReceiptError(f"{ENV_KEY_ID} must be 1 to 64 characters among letters, digits, '.', '_' and '-'")
    try:
        with open(path, "rb") as handle:
            data = handle.read(16384)
        key = load_pem_private_key(data, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ReceiptError("receipt signing key unreadable or not an unencrypted PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReceiptError("receipt signing key must be Ed25519")
    return ReceiptSigner(key_id, key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def signer_from_env(environ=None) -> ReceiptSigner | None:
    """None when receipts are not configured (the service then answers `signed_receipt: false`, as before).
    If the file variable IS set, any problem raises: a service that was meant to sign must not start unsigned."""
    environ = os.environ if environ is None else environ
    path = environ.get(ENV_KEY_FILE)
    if not path:
        return None
    return load_signer(path, environ.get(ENV_KEY_ID, ""))


def _check_body(body) -> dict:
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise ReceiptError("unexpected receipt fields")
    if body["format_version"] != FORMAT_VERSION or type(body["format_version"]) is not int:
        raise ReceiptError("unsupported receipt version")
    for name in ("client_id", "submission_id"):
        value = body[name]
        try:
            ok = isinstance(value, str) and str(UUID(value)) == value
        except ValueError:
            ok = False
        if not ok:
            raise ReceiptError(f"{name} must be a canonical UUID")
    if type(body["client_sequence"]) is not int or not 1 <= body["client_sequence"] < 2**63:
        raise ReceiptError("client_sequence must be a positive integer")
    for name in ("link_hash", "service_public_key_hex"):
        if not isinstance(body[name], str) or _HEX64.match(body[name]) is None:
            raise ReceiptError(f"{name} must be 64 lowercase hex characters")
    if not isinstance(body["received_at"], str) or _INSTANT.match(body["received_at"]) is None:
        raise ReceiptError("received_at must be a UTC instant with microseconds")
    if not isinstance(body["service_key_id"], str) or _KEY_ID.match(body["service_key_id"]) is None:
        raise ReceiptError("service_key_id invalid")
    return body


def sign_receipt(signer: ReceiptSigner, accepted: dict) -> dict:
    """`accepted` is what accept_submission returned (after the commit). Returns {'body': {...}, 'signature_b64': ...}."""
    body = _check_body({
        "format_version": FORMAT_VERSION,
        "client_id": accepted["client_id"],
        "submission_id": accepted["submission_id"],
        "client_sequence": accepted["client_sequence"],
        "link_hash": accepted["link_hash"],
        "received_at": accepted["received_at"],
        "service_key_id": signer.key_id,
        "service_public_key_hex": signer.public_key.hex(),
    })
    signature = signer.private_key.sign(RECEIPT_DOMAIN + rfc8785.dumps(body))
    return {"body": body, "signature_b64": base64.b64encode(signature).decode("ascii")}


def verify_receipt(receipt, *, trusted_fingerprint: str) -> dict:
    """Return the body if and only if the receipt is well formed, carries the TRUSTED service key and verifies.

    `trusted_fingerprint` (SHA-256 of the raw public key, 64 hex) must come from outside the receipt: from the
    operator's published page, a paper copy, a contract. A receipt that names another key is refused."""
    if not isinstance(trusted_fingerprint, str) or _HEX64.match(trusted_fingerprint) is None:
        raise ReceiptError("trusted_fingerprint must be 64 lowercase hex characters")
    if not isinstance(receipt, dict) or set(receipt) != {"body", "signature_b64"}:
        raise ReceiptError("unexpected receipt structure")
    body = _check_body(receipt["body"])
    public = bytes.fromhex(body["service_public_key_hex"])
    if fingerprint_of(public) != trusted_fingerprint:
        raise ReceiptError("receipt is signed by a key other than the trusted one")
    try:
        signature = base64.b64decode(receipt["signature_b64"], validate=True)
        if len(signature) != 64:
            raise ValueError("length")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, RECEIPT_DOMAIN + rfc8785.dumps(body))
    except (binascii.Error, ValueError, TypeError, InvalidSignature) as exc:
        raise ReceiptError("receipt signature invalid") from exc
    return body


def find_sequence_gaps(receipts: list[dict]) -> list[str]:
    """Problems in the receipts one client holds, already verified: duplicates, conflicting hashes, missing numbers.
    Mixed clients are reported per client. Missing numbers BEFORE the first receipt held are not reported (the client
    may have started holding receipts later): pass the full set to check a whole history."""
    problems: list[str] = []
    by_client: dict[str, dict[int, dict]] = {}
    for body in receipts:
        seen = by_client.setdefault(body["client_id"], {})
        previous = seen.get(body["client_sequence"])
        if previous is not None and (previous["link_hash"] != body["link_hash"]
                                     or previous["submission_id"] != body["submission_id"]):
            problems.append(f"client {body['client_id']} sequence {body['client_sequence']}: two different receipts")
        seen[body["client_sequence"]] = body
    for client, seen in sorted(by_client.items()):
        numbers = sorted(seen)
        for low, high in zip(numbers, numbers[1:]):
            if high != low + 1:
                problems.append(f"client {client}: receipts missing between sequence {low} and {high}")
    return problems


def compare_with_heads(receipts: list[dict], heads: dict) -> list[str]:
    """Check verified receipts against the chain heads of a (restored) database, as printed by v2b_restore_check:
    {client_id: {'sequence': n, 'link_hash': h}}. A receipt NEWER than the head, or equal to it with another hash,
    proves that the history was cut or rewritten."""
    problems: list[str] = []
    newest: dict[str, dict] = {}
    for body in receipts:
        current = newest.get(body["client_id"])
        if current is None or body["client_sequence"] > current["client_sequence"]:
            newest[body["client_id"]] = body
    for client, body in sorted(newest.items()):
        head = heads.get(client)
        if head is None:
            problems.append(f"client {client}: receipts held up to sequence {body['client_sequence']} but the history has no record")
        elif body["client_sequence"] > head["sequence"]:
            problems.append(f"client {client}: receipt for sequence {body['client_sequence']} but the history stops at {head['sequence']}")
        elif body["client_sequence"] == head["sequence"] and body["link_hash"] != head["link_hash"]:
            problems.append(f"client {client}: sequence {body['client_sequence']} has another link hash than the receipt")
    return problems


def _show(args) -> int:
    signer = load_signer(args.key_file, args.key_id)
    print(json.dumps({"service_key_id": signer.key_id, "service_public_key_hex": signer.public_key.hex(),
                      "fingerprint_sha256": signer.fingerprint}, indent=2))
    return 0


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _verify(args) -> int:
    try:
        raw = _load_json(args.receipts)
        items = raw if isinstance(raw, list) else [raw]
        bodies = [verify_receipt(item, trusted_fingerprint=args.fingerprint.lower().replace(" ", "")) for item in items]
    except (OSError, ValueError) as exc:  # ReceiptError is a ValueError; so is a JSON error
        print(json.dumps({"ok": False, "problems": [str(exc)]}, indent=2))
        return 1
    problems = find_sequence_gaps(bodies)
    if args.heads:
        try:
            report = _load_json(args.heads)
            problems += compare_with_heads(bodies, report["heads"]["links"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"heads unreadable: {exc}")
    print(json.dumps({"ok": not problems, "receipts": len(bodies), "problems": problems}, indent=2))
    return 0 if not problems else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m chaindbom.v2b_receipt")
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("show", help="print the PUBLIC key and fingerprint of a service key file (never the private key)")
    show.add_argument("--key-file", default=os.environ.get(ENV_KEY_FILE))
    show.add_argument("--key-id", default=os.environ.get(ENV_KEY_ID, "check"))
    verify = sub.add_parser("verify", help="verify receipt(s) against a trusted fingerprint; optionally against restore heads")
    verify.add_argument("--receipts", required=True, help="JSON file: one receipt or a list of receipts")
    verify.add_argument("--fingerprint", required=True, help="trusted SHA-256 fingerprint of the service public key (64 hex)")
    verify.add_argument("--heads", help="JSON report printed by v2b_restore_check, to compare the chain heads")
    args = parser.parse_args(argv)
    try:
        return _show(args) if args.command == "show" else _verify(args)
    except ReceiptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
