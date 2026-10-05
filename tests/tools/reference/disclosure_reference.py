"""Reference check of a disclosure package, WITHOUT decryption (vendored and reduced from chaindbom
src/chaindbom/dbom_v2_disclosure.py, specification docs/DISCLOSURE_V1.md). The page never decrypts: it checks the
authorisation (structure, signature of the supplier's trusted key, ciphertext hash, proof binding, expiry).
Public material and synthetic data only."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DISCLOSURE_FORMAT = "chaindbom-disclosure-v1"
DOMAIN = b"ChainDBoM:v2:disclosure\x00"
PURPOSES = ("audit_independant", "controle_reglementaire", "relation_commerciale", "reparation_recyclage", "autre")
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
PACKAGE_KEYS = frozenset({"manifest", "signature_hex", "ciphertext_b64"})
MANIFEST_KEYS = frozenset({
    "format", "format_version", "disclosure_id", "client_id", "signing_key_id", "submission_id", "record_hash",
    "recipient_age_recipient", "recipient_label", "purpose", "created_at", "expires_at", "ciphertext_format",
    "ciphertext_hash"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SIG = re.compile(r"[0-9a-f]{128}\Z")
KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
AGE = re.compile(r"age1[0-9a-z]{58}\Z")
TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class DisclosureError(ValueError):
    pass


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def parse_time(value, name):
    if not isinstance(value, str) or not TS.fullmatch(value):
        raise DisclosureError(f"{name} must be UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise DisclosureError(f"{name} is not a real date") from None


def label_ok(value):
    return isinstance(value, str) and 1 <= len(value) <= 64 and value == value.strip() and all(c.isprintable() for c in value)


def validate_manifest(m):
    if not isinstance(m, dict) or set(m) != MANIFEST_KEYS:
        raise DisclosureError("manifest keys")
    if m["format"] != DISCLOSURE_FORMAT or type(m["format_version"]) is not int or m["format_version"] != 1:
        raise DisclosureError("format")
    for f in ("disclosure_id", "client_id", "submission_id"):
        if not canonical_uuid(m[f]):
            raise DisclosureError(f)
    if not isinstance(m["signing_key_id"], str) or not KEY_ID.fullmatch(m["signing_key_id"]):
        raise DisclosureError("signing_key_id")
    for f in ("record_hash", "ciphertext_hash"):
        if not isinstance(m[f], str) or not HEX64.fullmatch(m[f]):
            raise DisclosureError(f)
    if not isinstance(m["recipient_age_recipient"], str) or not AGE.fullmatch(m["recipient_age_recipient"]):
        raise DisclosureError("recipient")
    if m["recipient_label"] is not None and not label_ok(m["recipient_label"]):
        raise DisclosureError("label")
    if m["purpose"] not in PURPOSES:
        raise DisclosureError("purpose")
    created = parse_time(m["created_at"], "created_at")
    if m["expires_at"] is not None and parse_time(m["expires_at"], "expires_at") < created:
        raise DisclosureError("expires_at before created_at")
    if m["ciphertext_format"] != "age-v1-binary":
        raise DisclosureError("ciphertext_format")


def check(raw: bytes, card: dict, expected_fingerprint: str, proof_record_hash, proof_client_id, now: datetime) -> dict:
    """Mirrors open_disclosure up to the ciphertext hash; `card` must already be a verified key card."""
    if len(raw) > MAX_PACKAGE_BYTES:
        raise DisclosureError("too large")

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise DisclosureError("duplicate key")
        return dict(items)
    try:
        package = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as exc:
        raise (exc if isinstance(exc, DisclosureError) else DisclosureError("json")) from None
    if not isinstance(package, dict) or set(package) != PACKAGE_KEYS:
        raise DisclosureError("package keys")
    m = package["manifest"]
    validate_manifest(m)
    if not isinstance(package["signature_hex"], str) or not SIG.fullmatch(package["signature_hex"]):
        raise DisclosureError("signature format")
    if not isinstance(package["ciphertext_b64"], str):
        raise DisclosureError("ciphertext type")
    try:
        ciphertext = base64.b64decode(package["ciphertext_b64"].encode("ascii"), validate=True)
    except (binascii.Error, UnicodeError):
        raise DisclosureError("base64") from None
    wanted = re.sub(r"[\s:\-]", "", expected_fingerprint or "").lower()
    if not HEX64.fullmatch(wanted) or wanted != card["signing_key_fingerprint_sha256"]:
        raise DisclosureError("fingerprint")
    if m["client_id"] != card["client_id"] or m["signing_key_id"] != card["signing_key_id"]:
        raise DisclosureError("card/package mismatch")
    public = bytes.fromhex(card["signing_public_key_hex"])
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(package["signature_hex"]), DOMAIN + rfc8785.dumps(m))
    except InvalidSignature:
        raise DisclosureError("signature") from None
    if hashlib.sha256(ciphertext).hexdigest() != m["ciphertext_hash"]:
        raise DisclosureError("ciphertext_hash")
    if proof_record_hash is not None and proof_record_hash != m["record_hash"]:
        raise DisclosureError("record_hash differs from proof")
    if proof_client_id is not None and proof_client_id != m["client_id"]:
        raise DisclosureError("client differs from proof")
    expired = m["expires_at"] is not None and parse_time(m["expires_at"], "expires_at") < now
    return {"purpose": m["purpose"], "recipient_label": m["recipient_label"], "created_at": m["created_at"],
            "expires_at": m["expires_at"], "expired": expired, "record_hash": m["record_hash"], "client_id": m["client_id"]}
