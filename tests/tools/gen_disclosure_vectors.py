#!/usr/bin/env python3
"""Regenerate the synthetic disclosure package vectors, deterministically (fixed seeds, no randomness, no network).

The package of the supplier whose key is used by the `valid_5_leaves` proof vector is built here, then valid and
tampered variants are derived. The "ciphertext" is an opaque synthetic byte string: the page never decrypts, it
checks only its SHA-256 (real age encryption is covered by the chaindbom tests). Expected verdicts come from the
reference Python check (tests/tools/reference/disclosure_reference.py), against which the JavaScript check is compared.

    python tests/tools/gen_disclosure_vectors.py
    python tests/tools/gen_disclosure_vectors.py --check      # fail if files would change
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "vectors" / "disclosure"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


keycards = load("gen_keycard_vectors", HERE / "gen_keycard_vectors.py")
ref = load("disclosure_reference", HERE / "reference" / "disclosure_reference.py")
NOW = datetime(2026, 12, 1, 12, 0, 0, tzinfo=timezone.utc)
PROOF = json.loads((ROOT / "vectors" / "v2b" / "valid_5_leaves.json").read_text())["proof_only"]["submission"]["signed_manifest"]
RECORD_HASH, PROOF_CLIENT = PROOF["record_hash"], PROOF["client_id"]


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def uuid_from(label: str) -> str:
    from uuid import UUID
    return str(UUID(bytes=sha(b"disclosure " + label.encode())[:16], version=4))


def build(name="valid_5_leaves", **changes):
    private, public, client, seed = keycards.identity(name)
    card = keycards.card_for(name)
    ciphertext = b"age-encryption.org/v1\n-> synthetic (opaque for the page)\n" + sha(b"ct " + name.encode()) * 8
    manifest = {
        "format": ref.DISCLOSURE_FORMAT, "format_version": 1, "disclosure_id": uuid_from("id " + name),
        "client_id": client, "signing_key_id": card["signing_key_id"], "submission_id": uuid_from("sub " + name),
        "record_hash": RECORD_HASH, "recipient_age_recipient": keycards.age_recipient(sha(b"recipient")),
        "recipient_label": "oem-pilote-1", "purpose": "audit_independant", "created_at": "2026-10-05T12:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z", "ciphertext_format": "age-v1-binary",
        "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest(),
    }
    manifest.update(changes)
    return {"manifest": manifest, "signature_hex": private.sign(ref.DOMAIN + rfc8785.dumps(manifest)).hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode()}


def flip(value: str) -> str:
    return ("1" if value[0] == "0" else "0") + value[1:]


def vectors():
    good = build()
    v = {"valid": (good, {}), "valid_no_expiry_no_label": (build(expires_at=None, recipient_label=None), {}),
         "valid_expired": (build(expires_at="2026-11-01T00:00:00Z"), {}),
         "valid_each_purpose_reparation": (build(purpose="reparation_recyclage"), {})}
    for field, value in {"purpose": "autre", "recipient_label": "autre-label", "created_at": "2026-10-06T12:00:00Z",
                         "expires_at": "2030-01-01T00:00:00Z", "record_hash": "ab" * 32, "submission_id": uuid_from("x"),
                         "disclosure_id": uuid_from("y"), "recipient_age_recipient": keycards.age_recipient(sha(b"other"))}.items():
        v[f"tampered_{field}_after_signing"] = ({"manifest": {**good["manifest"], field: value}, "signature_hex": good["signature_hex"],
                                                 "ciphertext_b64": good["ciphertext_b64"]}, {})
    v["tampered_signature"] = ({**good, "signature_hex": flip(good["signature_hex"])}, {})
    data = bytearray(base64.b64decode(good["ciphertext_b64"])); data[-1] ^= 1
    v["tampered_ciphertext"] = ({**good, "ciphertext_b64": base64.b64encode(bytes(data)).decode()}, {})
    v["extra_package_key"] = ({**good, "extra": 1}, {})
    v["missing_signature"] = ({k: x for k, x in good.items() if k != "signature_hex"}, {})
    v["extra_manifest_key"] = (build(extra="x"), {})
    v["purpose_not_in_list"] = (build(purpose="inconnu"), {})
    v["label_empty"] = (build(recipient_label=""), {})
    v["label_too_long"] = (build(recipient_label="x" * 65), {})
    v["label_with_control_character"] = (build(recipient_label="tab\tulation"), {})
    v["format_version_is_boolean"] = (build(format_version=True), {})
    v["format_version_two"] = (build(format_version=2), {})
    v["uppercase_disclosure_id"] = (build(disclosure_id=uuid_from("id valid_5_leaves").upper()), {})
    v["expires_before_created"] = (build(expires_at="2026-10-04T00:00:00Z"), {})
    v["created_at_not_utc"] = (build(created_at="2026-10-05"), {})
    v["impossible_date"] = (build(created_at="2026-13-45T00:00:00Z"), {})
    v["ciphertext_format_armor"] = (build(ciphertext_format="age-armor"), {})
    v["bad_base64"] = ({**good, "ciphertext_b64": "***"}, {})
    v["signed_by_another_supplier"] = (build("valid_single"), {})
    v["record_hash_differs_from_proof"] = (build(record_hash="ab" * 32), {})
    v["wrong_fingerprint"] = (good, {"fingerprint": "00" * 32})
    v["proof_hash_differs"] = (good, {"proof_record_hash": "cd" * 32})
    v["proof_from_another_client"] = (good, {"proof_client_id": uuid_from("other client")})
    v["card_of_another_supplier"] = (good, {"card": "valid_other_client"})
    return v


def render():
    files, expected = {}, {}
    cards = {"valid": keycards.card_for("valid_5_leaves"), "valid_other_client": keycards.card_for("valid_single")}
    for name, (package, options) in vectors().items():
        raw = json.dumps(package, indent=2, sort_keys=True).encode() + b"\n"
        files[name + ".json"] = raw
        card_name = options.get("card", "valid")
        card = cards[card_name]
        fingerprint = options.get("fingerprint", card["signing_key_fingerprint_sha256"])
        proof_hash = options.get("proof_record_hash", RECORD_HASH)
        proof_client = options.get("proof_client_id", PROOF_CLIENT)
        try:
            facts = ref.check(raw, card, fingerprint, proof_hash, proof_client, NOW)
            result = {"ok": True, "facts": {k: facts[k] for k in ("purpose", "recipient_label", "created_at", "expires_at", "expired")}}
        except ref.DisclosureError:
            result = {"ok": False}
        expected[name] = {"options": {"card": card_name, "fingerprint": fingerprint, "proof_record_hash": proof_hash,
                                      "proof_client_id": proof_client}, "expected": result}
    files["expected.json"] = (json.dumps({"now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "vectors": expected}, indent=2, sort_keys=True) + "\n").encode()
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = render()
    OUT.mkdir(parents=True, exist_ok=True)
    changed = [n for n, d in files.items() if not (OUT / n).exists() or (OUT / n).read_bytes() != d]
    stale = sorted(p.name for p in OUT.iterdir() if p.name not in files)
    if args.check:
        if changed or stale:
            print("fichiers à régénérer :", changed, "obsolètes :", stale)
            return 1
    else:
        for n in changed:
            (OUT / n).write_bytes(files[n])
        for n in stale:
            (OUT / n).unlink()
    ok = sum(1 for v in json.loads(files["expected.json"])["vectors"].values() if v["expected"]["ok"])
    print(f"{len(files) - 1} paquets, {ok} valides ; fichiers mis à jour : {changed if not args.check else []}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
