#!/usr/bin/env python3
"""Regenerate the synthetic key card test vectors, deterministically (fixed seeds, no randomness, no network).

The card of the signing key used by the `valid_5_leaves` proof vector is built here, then valid and
tampered variants are derived. Expected verdicts come from the reference Python check
(tests/tools/reference/key_card_reference.py), so the JavaScript check is compared with it.
Needs: pip install cryptography rfc8785

    python tests/tools/gen_keycard_vectors.py
    python tests/tools/gen_keycard_vectors.py --check      # fail if files would change
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from uuid import UUID

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "keycard"
spec = importlib.util.spec_from_file_location("key_card_reference", Path(__file__).resolve().parent / "reference" / "key_card_reference.py")
ref = importlib.util.module_from_spec(spec)
sys.modules["key_card_reference"] = ref
spec.loader.exec_module(ref)

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def identity(name: str):
    """Same derivation as gen_v2b_vectors.build(): the seed and client id of the proof vector called `name`."""
    seed = sha(b"diadroma-verify synthetic vector " + name.encode())
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client = str(UUID(bytes=sha(b"client " + seed)[:16], version=4))
    return private, public, client, seed


def age_recipient(seed: bytes) -> str:
    """A well-formed synthetic age recipient (58 bech32 characters after 'age1'). It is never used to encrypt."""
    material = sha(b"age " + seed)
    return "age1" + "".join(BECH32[b % 32] for b in material[:29]) + "".join(BECH32[b % 32] for b in sha(material)[:29])


def card_for(name: str, created_at: str = "2026-10-05T12:00:00Z") -> dict:
    private, public, client, seed = identity(name)
    card = {
        "format": ref.CARD_FORMAT, "format_version": 1, "client_id": client, "signing_key_id": "sign-" + name[:20].replace("_", "-"),
        "signing_public_key_hex": public.hex(), "signing_key_fingerprint_sha256": ref.fingerprint(public),
        "recipient_key_id": "age-1", "age_recipient": age_recipient(seed), "created_at": created_at,
    }
    card["signature_hex"] = private.sign(ref.signed_bytes(card)).hex()
    return card


def resign(card: dict, name: str) -> dict:
    private, *_ = identity(name)
    card = dict(card)
    card["signature_hex"] = private.sign(ref.signed_bytes(card)).hex()
    return card


def flip(hexstr: str, pos: int = 0) -> str:
    return hexstr[:pos] + ("1" if hexstr[pos] == "0" else "0") + hexstr[pos + 1:]


def vectors() -> dict:
    good = card_for("valid_5_leaves")
    v = {"valid": good, "valid_other_client": card_for("valid_single")}
    v["tampered_field_after_signing"] = {**good, "signing_key_id": "sign-other"}
    v["tampered_signature"] = {**good, "signature_hex": flip(good["signature_hex"])}
    v["tampered_fingerprint"] = {**good, "signing_key_fingerprint_sha256": flip(good["signing_key_fingerprint_sha256"])}
    v["tampered_public_key"] = {**good, "signing_public_key_hex": flip(good["signing_public_key_hex"])}
    v["fingerprint_and_key_replaced_by_attacker"] = card_for("valid_single") | {"client_id": good["client_id"]}
    v["extra_field"] = {**good, "extra": "x"}
    v["missing_field"] = {k: val for k, val in good.items() if k != "age_recipient"}
    v["wrong_format"] = resign({**good, "format": "chaindbom-key-card-v2"}, "valid_5_leaves")
    v["wrong_version"] = resign({**good, "format_version": 2}, "valid_5_leaves")
    v["uppercase_client_id"] = resign({**good, "client_id": good["client_id"].upper()}, "valid_5_leaves")
    v["uppercase_fingerprint"] = resign({**good, "signing_key_fingerprint_sha256": good["signing_key_fingerprint_sha256"].upper()}, "valid_5_leaves")
    v["bad_age_recipient"] = resign({**good, "age_recipient": "age1short"}, "valid_5_leaves")
    v["bad_timestamp"] = resign({**good, "created_at": "2026-10-05 12:00:00"}, "valid_5_leaves")
    v["bad_key_id"] = resign({**good, "signing_key_id": "bad key!"}, "valid_5_leaves")
    v["signature_too_short"] = {**good, "signature_hex": good["signature_hex"][:-2]}
    v["version_is_boolean"] = resign({**good, "format_version": True}, "valid_5_leaves")
    return v


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files, expected = {}, {}
    for name, card in vectors().items():
        files[f"{name}.json"] = json.dumps(card, indent=2, sort_keys=True) + "\n"
        try:
            expected[name] = {"ok": True, "facts": ref.verify_key_card(card)}
        except ref.KeyCardError:
            expected[name] = {"ok": False}
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
        print("key card vectors out of date:", changed, stale)
        sys.exit(1)
    print(f"{len(files) - 1} cartes, {sum(1 for e in expected.values() if e['ok'])} valides ; fichiers mis à jour : {changed}")


if __name__ == "__main__":
    main()
