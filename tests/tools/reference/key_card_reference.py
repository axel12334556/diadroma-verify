"""Reference check of a chaindbom-key-card-v1, vendored from the ChainDBoM repository
(src/chaindbom/key_card.py at commit f6613b9: fingerprint, _signed_bytes and verify_key_card, unchanged).
Only the verification half is kept (no key loading, no command line). Used to produce the expected verdicts
of the JavaScript key card check; it is a test tool, never shipped with the page."""
from __future__ import annotations

import hashlib
import re
from typing import Any
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CARD_FORMAT = "chaindbom-key-card-v1"
CARD_FORMAT_VERSION = 1
CARD_DOMAIN = b"ChainDBoM:v2:key-card\x00"
_CARD_KEYS = frozenset({
    "format", "format_version", "client_id", "signing_key_id", "signing_public_key_hex",
    "signing_key_fingerprint_sha256", "recipient_key_id", "age_recipient", "created_at", "signature_hex",
})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_AGE_RECIPIENT = re.compile(r"age1[0-9a-z]{58}\Z")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class KeyCardError(ValueError):
    pass


def fingerprint(public_key: bytes) -> str:
    """SHA-256 of the raw 32-byte Ed25519 public key, lowercase hex."""
    if len(public_key) != 32:
        raise KeyCardError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def signed_bytes(card: dict[str, Any]) -> bytes:
    return CARD_DOMAIN + rfc8785.dumps({k: v for k, v in card.items() if k != "signature_hex"})


def verify_key_card(card: object) -> dict[str, str]:
    """Strictly validate a card and its self-signature; return the facts to publish/compare."""
    if not isinstance(card, dict) or set(card) != _CARD_KEYS:
        raise KeyCardError("key card must be an object with exactly the expected fields")
    if card["format"] != CARD_FORMAT or card["format_version"] != CARD_FORMAT_VERSION \
            or type(card["format_version"]) is not int:
        raise KeyCardError("unsupported key card format")
    for field in ("client_id", "signing_key_id", "signing_public_key_hex", "signing_key_fingerprint_sha256",
                  "recipient_key_id", "age_recipient", "created_at", "signature_hex"):
        if not isinstance(card[field], str):
            raise KeyCardError(f"{field} must be a string")
    try:
        if str(UUID(card["client_id"])) != card["client_id"]:
            raise ValueError
    except ValueError:
        raise KeyCardError("client_id must be a canonical lowercase UUID") from None
    if not _KEY_ID.fullmatch(card["signing_key_id"]) or not _KEY_ID.fullmatch(card["recipient_key_id"]):
        raise KeyCardError("invalid key id")
    if not _HEX64.fullmatch(card["signing_public_key_hex"]) \
            or not _HEX64.fullmatch(card["signing_key_fingerprint_sha256"]):
        raise KeyCardError("public key and fingerprint must be 64 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{128}", card["signature_hex"]):
        raise KeyCardError("signature must be 128 lowercase hex characters")
    if not _AGE_RECIPIENT.fullmatch(card["age_recipient"]):
        raise KeyCardError("invalid age recipient")
    if not _TIMESTAMP.fullmatch(card["created_at"]):
        raise KeyCardError("created_at must be UTC, e.g. 2026-10-05T12:00:00Z")
    public = bytes.fromhex(card["signing_public_key_hex"])
    if fingerprint(public) != card["signing_key_fingerprint_sha256"]:
        raise KeyCardError("fingerprint does not match the public key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(card["signature_hex"]), signed_bytes(card))
    except InvalidSignature:
        raise KeyCardError("self-signature is invalid") from None
    return {"client_id": card["client_id"], "signing_key_id": card["signing_key_id"],
            "fingerprint_sha256": card["signing_key_fingerprint_sha256"],
            "created_at": card["created_at"]}
