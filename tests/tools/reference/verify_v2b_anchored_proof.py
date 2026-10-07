#!/usr/bin/env python3
"""
verify_v2b_anchored_proof.py

Vérificateur AUTONOME d'une preuve ancrée ChainDBoM v2b (format
"chaindbom-anchored-proof-v2b", version 1), destiné à un auditeur.

Ce fichier n'importe rien de `chaindbom` : c'est une réimplémentation indépendante des
règles (signature de soumission, lien, Merkle, anchor_digest) et un lecteur minimal du
format OpenTimestamps (.ots), pour qu'un tiers puisse l'auditer seul. Dépendances :
    pip install cryptography rfc8785
Aucun paquet `opentimestamps`, aucun accès réseau, sauf --fetch-block (explorateur Bitcoin).

Aucune donnée métier n'est nécessaire ni lue : la preuve ne contient que des identifiants,
des empreintes (SHA-256), une signature Ed25519, la clé publique de signature et des
éléments d'ancrage. La vérification du contenu du DBoM n'est possible que si le client
fournit lui-même le DBoM clair (--dbom) ; sans lui, le verdict ne dit RIEN de la véracité
ni du contenu métier, seulement de l'intégrité et de l'antériorité de l'empreinte.

Vérifications (chacune rapportée séparément, jamais fusionnée) :
  format              structure et version du document (clés exactes, empreintes valides)
  manifest_signature  signature Ed25519 sur DOMAINE + JCS(manifeste) avec la clé fournie
  signing_key_trust   la clé de la preuve == --trusted-public-key et/ou dont l'empreinte SHA-256
                      == --trusted-key-fingerprint (sinon : non vérifié)
  manifest_link_binding  client, soumission et record_hash identiques manifeste/lien
  link_hash           recalcul du link_hash (client, séquence, lien précédent, record_hash)
  merkle_inclusion    link_hash appartient au lot : preuve d'inclusion -> merkle_root
  anchor_digest       recalcul de l'anchor_digest du lot (numéro, lot précédent, racine)
  ots_commitment      la preuve .ots s'engage bien sur cet anchor_digest
  ots_bitcoin_attestation  la preuve contient une attestation Bitcoin (sinon : en attente)
  bitcoin_block       digest atteste (octets inversés) == merkle root du bloc Bitcoin
                      (--block-merkle-root fourni hors ligne, ou --fetch-block)
  record_hash_vs_dbom  SHA-256(JCS(DBoM clair)) == record_hash (seulement avec --dbom)

Niveaux atteints : INVALIDE < INTEGRITE < ENGAGEMENT_OTS < ATTESTATION_BITCOIN < BLOC_CONFIRME.
Le champ "status" du document n'est qu'une déclaration : il n'est jamais cru.

Usage :
    python verify_v2b_anchored_proof.py --input proof.json [--trusted-public-key HEX]
        [--trusted-key-fingerprint SHA256]
        [--block-merkle-root HEX | --fetch-block] [--dbom dbom.json]
        [--require integrity|ots|attestation|bitcoin]

Niveaux : seul « bitcoin » (racine du bloc fournie ou lue, et concordante) établit une antériorité. « ots » et
« attestation » n'attestent que ce que le fichier déclare : un fichier fabriqué hors ligne les obtient aussi.

Codes de sortie : 0 niveau requis atteint ; 1 vérification échouée ou niveau insuffisant ;
2 fichier ou arguments inutilisables.

Note sur Bitcoin : une attestation OpenTimestamps porte une HAUTEUR de bloc, pas un txid. Le
digest atteste, octets inversés, doit égaler le merkle root de l'en-tête du bloc à cette hauteur.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import urllib.request
from uuid import UUID

PROOF_FORMAT = "chaindbom-anchored-proof-v2b"
PROOF_FORMAT_VERSION = 1
PROOF_ONLY_FORMAT = "chaindbom-proof-only-v2b-prototype"
SUBMISSION_DOMAIN = b"ChainDBoM:v2:submission\x00"
LINK_DOMAIN = b"ChainDBoM:v2:link\x00"
BATCH_DOMAIN = b"ChainDBoM:v2:batch\x00"
BLOCKSTREAM_API = "https://blockstream.info/api"

MAX_OTS_BYTES = 1_000_000
MAX_OTS_NODES = 50_000
MAX_OTS_DEPTH = 300
MAX_OTS_MESSAGE_BYTES = 4096  # a real proof's running message stays far below; hexlify (0xF3) doubles it at each step

LEVELS = ["INVALIDE", "INTEGRITE", "ENGAGEMENT_OTS", "ATTESTATION_BITCOIN", "BLOC_CONFIRME"]
LEVEL_MEANING = [
    "invalide",
    "intégrité interne seulement : aucune antériorité",
    "engagement OpenTimestamps déclaré par le fichier : aucune antériorité prouvée",
    "attestation Bitcoin déclarée par le fichier, bloc non contrôlé : aucune antériorité prouvée",
    "bloc Bitcoin contrôlé : antériorité établie",
]
REQUIRE_TO_LEVEL = {"integrity": 1, "ots": 2, "attestation": 3, "bitcoin": 4}

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ProofFormatError(ValueError):
    pass


class OtsError(ValueError):
    pass


# --------------------------------------------------------------------------- helpers

# The eight points of small order of Ed25519 (and their non-canonical encodings) validate forged signatures for any
# message. Only the y coordinate matters (the sign bit is ignored): 0, 1, -1 and the two order-8 values.
_P = 2**255 - 19
_WEAK_Y = frozenset({
    0, 1, _P - 1,
    int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little") & (2**255 - 1),
    int.from_bytes(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little") & (2**255 - 1),
})


def has_small_order(public_key: bytes) -> bool:
    return (int.from_bytes(public_key, "little") & (2**255 - 1)) % _P in _WEAK_Y



def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex64(value, name: str) -> bytes:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ProofFormatError(f"{name} doit être une empreinte SHA-256 en hexadécimal minuscule")
    return bytes.fromhex(value)


MAX_SAFE_INTEGER = 2**53 - 1  # same bound as the JavaScript verifier (Number.MAX_SAFE_INTEGER)


def _uint(value, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ProofFormatError(f"{name} doit être un entier >= {minimum}")
    if value > MAX_SAFE_INTEGER:
        raise ProofFormatError(f"{name} dépasse 2^53 - 1")
    return value


def _exact_keys(obj, keys: set, name: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != keys:
        raise ProofFormatError(f"{name} : clés attendues exactement {sorted(keys)}")
    return obj


# --------------------------------------------------------------------------- format

def parse_document(doc) -> dict:
    """Validate the exact structure of an anchored proof; return typed parts."""
    top = _exact_keys(doc, {"format", "format_version", "proof_only", "anchor"}, "document")
    if top["format"] != PROOF_FORMAT or top["format_version"] != PROOF_FORMAT_VERSION \
            or type(top["format_version"]) is not int:
        raise ProofFormatError("format ou version inconnus")
    proof_only = _exact_keys(
        top["proof_only"], {"format", "verification_state", "submission", "link"}, "proof_only")
    if proof_only["format"] != PROOF_ONLY_FORMAT:
        raise ProofFormatError("format proof_only inconnu")
    submission = _exact_keys(
        proof_only["submission"], {"signed_manifest", "signature_hex", "signing_public_key_hex"},
        "submission")
    link = _exact_keys(
        proof_only["link"],
        {"client_id", "submission_id", "client_sequence", "previous_link_hash", "record_hash", "link_hash"},
        "link")
    anchor = _exact_keys(
        top["anchor"],
        {"anchor_chain", "anchor_block_height", "anchor_digest", "batch_number", "merkle_index",
         "merkle_proof", "merkle_root", "ots_proof_b64", "previous_anchor_digest", "record_count",
         "status"},
        "anchor")

    manifest = submission["signed_manifest"]
    if not isinstance(manifest, dict):
        raise ProofFormatError("signed_manifest doit être un objet")
    try:
        signature = bytes.fromhex(submission["signature_hex"])
        public_key = bytes.fromhex(submission["signing_public_key_hex"])
    except (TypeError, ValueError) as exc:
        raise ProofFormatError("signature ou clé publique non hexadécimale") from exc
    if len(signature) != 64 or len(public_key) != 32:
        raise ProofFormatError("signature (64 octets) ou clé publique (32 octets) de mauvaise taille")
    if has_small_order(public_key):
        raise ProofFormatError("clé publique d'ordre faible refusée")

    _hex64(link["record_hash"], "link.record_hash")
    _hex64(link["link_hash"], "link.link_hash")
    if link["previous_link_hash"] is not None:
        _hex64(link["previous_link_hash"], "link.previous_link_hash")
    _uint(link["client_sequence"], "link.client_sequence", 1)

    _hex64(anchor["merkle_root"], "anchor.merkle_root")
    _hex64(anchor["anchor_digest"], "anchor.anchor_digest")
    if anchor["previous_anchor_digest"] is not None:
        _hex64(anchor["previous_anchor_digest"], "anchor.previous_anchor_digest")
    _uint(anchor["batch_number"], "anchor.batch_number", 1)
    _uint(anchor["record_count"], "anchor.record_count", 1)
    _uint(anchor["merkle_index"], "anchor.merkle_index", 0)
    if anchor["merkle_index"] >= anchor["record_count"]:
        raise ProofFormatError("anchor.merkle_index hors du lot")
    if anchor["anchor_chain"] != "bitcoin":
        raise ProofFormatError("anchor_chain non pris en charge")
    if anchor["anchor_block_height"] is not None:
        _uint(anchor["anchor_block_height"], "anchor.anchor_block_height", 1)
    if not isinstance(anchor["ots_proof_b64"], str):
        raise ProofFormatError("anchor.ots_proof_b64 doit être une chaîne base64")
    proof = anchor["merkle_proof"]
    if not isinstance(proof, list):
        raise ProofFormatError("anchor.merkle_proof doit être une liste")
    if len(proof) > 64:
        raise ProofFormatError("anchor.merkle_proof trop longue")
    for step in proof:
        _exact_keys(step, {"sibling", "position"}, "étape de preuve Merkle")
        _hex64(step["sibling"], "sibling")
        if step["position"] not in ("left", "right"):
            raise ProofFormatError("position de preuve Merkle invalide")
    return {"manifest": manifest, "signature": signature, "public_key": public_key,
            "link": link, "anchor": anchor}


# --------------------------------------------------------------------------- crypto rules

def jcs(value) -> bytes:
    import rfc8785
    return rfc8785.dumps(value)


def verify_signature(manifest: dict, signature: bytes, public_key: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, SUBMISSION_DOMAIN + jcs(manifest))
    except InvalidSignature as exc:
        raise ValueError("signature Ed25519 invalide") from exc


def compute_link_hash(client_id: str, sequence: int, record_hash: str, previous: str | None) -> str:
    client = UUID(client_id)
    if str(client) != client_id:
        raise ValueError("client_id non canonique")
    if (sequence == 1) != (previous is None):
        raise ValueError("seule la genèse peut omettre previous_link_hash")
    previous_bytes = bytes(32) if previous is None else bytes.fromhex(previous)
    return _sha256(LINK_DOMAIN + client.bytes + sequence.to_bytes(8, "big")
                   + previous_bytes + bytes.fromhex(record_hash)).hex()


def _leaf(link_hash: str) -> bytes:
    return _sha256(b"\x00" + bytes.fromhex(link_hash))


def merkle_root_from_proof(link_hash: str, proof: list) -> str:
    current = _leaf(link_hash)
    for step in proof:
        sibling = bytes.fromhex(step["sibling"])
        current = _sha256(b"\x01" + (current + sibling if step["position"] == "right" else sibling + current))
    return current.hex()


def compute_anchor_digest(batch_number: int, previous: str | None, merkle_root: str) -> str:
    previous_bytes = bytes(32) if previous is None else bytes.fromhex(previous)
    return _sha256(BATCH_DOMAIN + batch_number.to_bytes(8, "big") + previous_bytes
                   + bytes.fromhex(merkle_root)).hex()


# --------------------------------------------------------------------------- minimal .ots reader

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise OtsError("preuve .ots tronquée")
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def byte(self) -> int:
        return self.read(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            octet = self.byte()
            value |= (octet & 0x7F) << shift
            if not octet & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("varuint trop long")

    def varbytes(self, limit: int) -> bytes:
        length = self.varuint()
        if length > limit:
            raise OtsError("champ .ots trop grand")
        return self.read(length)


def _apply_unary(tag: int, msg: bytes) -> bytes:
    if tag == 0x08:
        return _sha256(msg)
    if tag == 0x02:
        return hashlib.sha1(msg).digest()
    if tag == 0x03:
        try:
            return hashlib.new("ripemd160", msg).digest()
        except ValueError as exc:
            raise OtsError("RIPEMD-160 indisponible sur ce système") from exc
    if tag == 0xF2:
        return msg[::-1]
    if tag == 0xF3:
        return msg.hex().encode("ascii")
    raise OtsError(f"opération .ots non prise en charge : 0x{tag:02x}")


def parse_ots(ots_bytes: bytes) -> dict:
    """Parse a detached .ots proof. Returns file digest and every attestation found with the
    digest it is attached to. Only the operations needed by Bitcoin proofs are evaluated."""
    if len(ots_bytes) > MAX_OTS_BYTES:
        raise OtsError("preuve .ots trop volumineuse")
    reader = _Reader(ots_bytes)
    if reader.read(len(OTS_MAGIC)) != OTS_MAGIC:
        raise OtsError("en-tête .ots inconnu")
    if reader.varuint() != 1:
        raise OtsError("version .ots non prise en charge")
    file_hash_op = reader.byte()
    if file_hash_op != 0x08:
        raise OtsError("l'opération de hachage du fichier n'est pas SHA-256")
    file_digest = reader.read(32)

    attestations: list[dict] = []
    nodes = 0

    def walk(msg: bytes, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_OTS_NODES or depth > MAX_OTS_DEPTH:
            raise OtsError("arbre .ots trop grand ou trop profond")
        if len(msg) > MAX_OTS_MESSAGE_BYTES:
            raise OtsError("message intermédiaire .ots trop grand")
        tag = reader.byte()
        while tag == 0xFF:
            handle(msg, reader.byte(), depth)
            tag = reader.byte()
        handle(msg, tag, depth)

    def handle(msg: bytes, tag: int, depth: int) -> None:
        if tag == 0x00:
            kind = reader.read(8)
            payload = _Reader(reader.varbytes(8192))
            if kind == BITCOIN_TAG:
                height = payload.varuint()
                attestations.append({"type": "bitcoin", "height": height, "digest": msg})
            elif kind == PENDING_TAG:
                uri = payload.varbytes(1000).decode("utf-8", errors="replace")
                attestations.append({"type": "pending", "uri": uri, "digest": msg})
            else:
                attestations.append({"type": "other", "tag": kind.hex(), "digest": msg})
        elif tag in (0xF0, 0xF1):
            argument = reader.varbytes(4096)
            if not argument:
                raise OtsError("opérande .ots vide")
            walk(msg + argument if tag == 0xF0 else argument + msg, depth + 1)
        else:
            walk(_apply_unary(tag, msg), depth + 1)

    previous_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous_limit, 3000))  # depth <= 300 uses ~2 frames per level
    try:
        walk(file_digest, 0)
    finally:
        sys.setrecursionlimit(previous_limit)
    if reader.pos != len(ots_bytes):
        raise OtsError("octets en trop après la preuve .ots")
    return {"file_digest": file_digest, "attestations": attestations}


# --------------------------------------------------------------------------- Bitcoin

def fetch_block_merkle_root(height: int) -> str:
    with urllib.request.urlopen(f"{BLOCKSTREAM_API}/block-height/{height}", timeout=15) as response:
        block_hash = response.read().decode("ascii").strip()
    with urllib.request.urlopen(f"{BLOCKSTREAM_API}/block/{block_hash}", timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))["merkle_root"]


# --------------------------------------------------------------------------- verification

def normalize_fingerprint(value: str) -> str:
    """SHA-256 fingerprint as 64 lowercase hex chars; spaces, colons and dashes are tolerated."""
    cleaned = re.sub(r"[\s:\-]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        raise ValueError("l'empreinte de confiance doit contenir 64 caractères hexadécimaux (SHA-256)")
    return cleaned


def verify(doc, *, trusted_public_key: str | None = None, block_merkle_root: str | None = None,
           fetch_block: bool = False, dbom_bytes: bytes | None = None,
           trusted_key_fingerprint: str | None = None) -> dict:
    checks: list[dict] = []

    def record(check_id: str, status: str, detail: str) -> bool:
        checks.append({"id": check_id, "status": status, "detail": detail})
        return status == "pass"

    def run(check_id: str, function, ok_detail: str) -> bool:
        try:
            function()
        except (ValueError, KeyError, TypeError, binascii.Error) as exc:
            return record(check_id, "fail", str(exc) or exc.__class__.__name__)
        return record(check_id, "pass", ok_detail)

    try:
        parts = parse_document(doc)
    except ProofFormatError as exc:
        record("format", "fail", str(exc))
        return _summary(checks)
    record("format", "pass", f"{PROOF_FORMAT} v{PROOF_FORMAT_VERSION}, structure valide")

    manifest, link, anchor = parts["manifest"], parts["link"], parts["anchor"]

    run("manifest_signature",
        lambda: verify_signature(manifest, parts["signature"], parts["public_key"]),
        "signature Ed25519 valide pour la clé publique de la preuve")

    if trusted_public_key is None and trusted_key_fingerprint is None:
        record("signing_key_trust", "skipped",
               "aucune clé de confiance fournie : la clé de la preuve n'est pas authentifiée "
               "(comparer avec le registre du client via --trusted-public-key ou --trusted-key-fingerprint)")
    else:
        problems, proof_key = [], parts["public_key"]
        if trusted_public_key is not None and proof_key.hex() != trusted_public_key.strip().lower():
            problems.append("la clé de la preuve diffère de la clé de confiance fournie")
        if trusted_key_fingerprint is not None:
            try:
                expected = normalize_fingerprint(trusted_key_fingerprint)
            except ValueError as exc:
                problems.append(str(exc))
            else:
                if hashlib.sha256(proof_key).hexdigest() != expected:
                    problems.append("l'empreinte SHA-256 de la clé de la preuve diffère de l'empreinte de confiance fournie")
        if problems:
            record("signing_key_trust", "fail", " ; ".join(problems))
        else:
            record("signing_key_trust", "pass", "la clé de la preuve correspond à la confiance fournie "
                   "(clé et/ou empreinte)")

    def binding():
        for field in ("client_id", "submission_id", "record_hash"):
            if manifest.get(field) != link[field]:
                raise ValueError(f"{field} différent entre le manifeste signé et le lien")
    run("manifest_link_binding", binding, "client, soumission et record_hash cohérents")

    run("link_hash",
        lambda: _expect(compute_link_hash(link["client_id"], link["client_sequence"],
                                          link["record_hash"], link["previous_link_hash"]),
                        link["link_hash"], "link_hash"),
        "link_hash recalculé identique")

    run("merkle_inclusion",
        lambda: _expect(merkle_root_from_proof(link["link_hash"], anchor["merkle_proof"]),
                        anchor["merkle_root"], "racine de Merkle"),
        "le lien appartient au lot (preuve d'inclusion valide)")

    run("anchor_digest",
        lambda: _expect(compute_anchor_digest(anchor["batch_number"], anchor["previous_anchor_digest"],
                                              anchor["merkle_root"]),
                        anchor["anchor_digest"], "anchor_digest"),
        "anchor_digest recalculé identique")

    attested_digests: list[bytes] = []
    ots_ok = False
    try:
        ots = parse_ots(base64.b64decode(anchor["ots_proof_b64"], validate=True))
    except (OtsError, binascii.Error, ValueError) as exc:
        record("ots_commitment", "fail", f"preuve .ots illisible : {exc}")
        ots = None
    if ots is not None:
        if ots["file_digest"].hex() == anchor["anchor_digest"]:
            ots_ok = record("ots_commitment", "pass", "la preuve .ots s'engage sur l'anchor_digest du lot")
        else:
            record("ots_commitment", "fail", "la preuve .ots s'engage sur un autre digest que l'anchor_digest")
        bitcoin = [a for a in ots["attestations"] if a["type"] == "bitcoin"]
        if not bitcoin:
            pending = sum(1 for a in ots["attestations"] if a["type"] == "pending")
            record("ots_bitcoin_attestation", "skipped",
                   f"aucune attestation Bitcoin dans la preuve ({pending} en attente) : pas encore ancrée")
        else:
            heights = sorted({a["height"] for a in bitcoin})
            declared = anchor["anchor_block_height"]
            if declared is not None and declared not in heights:
                record("ots_bitcoin_attestation", "fail",
                       f"hauteur déclarée {declared} absente de la preuve (hauteurs : {heights})")
            else:
                record("ots_bitcoin_attestation", "pass", f"le fichier déclare une attestation Bitcoin aux hauteurs {heights} (non vérifiée tant que le bloc n'est pas contrôlé)")
                attested_digests = [a["digest"] for a in bitcoin if declared is None or a["height"] == declared]
    if ots is None:
        record("ots_bitcoin_attestation", "skipped", "preuve .ots illisible")

    attestation_ok = any(c["id"] == "ots_bitcoin_attestation" and c["status"] == "pass" for c in checks)
    if not attestation_ok:
        record("bitcoin_block", "skipped", "pas d'attestation Bitcoin à contrôler")
    elif block_merkle_root is None and not fetch_block:
        record("bitcoin_block", "skipped",
               "merkle root du bloc non fourni (--block-merkle-root) ni demandé (--fetch-block)")
    else:
        height = anchor["anchor_block_height"] or next(
            a["height"] for a in ots["attestations"] if a["type"] == "bitcoin")
        root = block_merkle_root
        if root is None:
            try:
                root = fetch_block_merkle_root(height)
            except Exception as exc:  # réseau réel
                record("bitcoin_block", "skipped", f"explorateur injoignable : {exc}")
                root = ""
        if root:
            root = root.strip().lower()
            matches = [d for d in attested_digests if d[::-1].hex() == root]
            if matches:
                record("bitcoin_block", "pass",
                       f"digest atteste (octets inversés) == merkle root du bloc {height}")
            else:
                record("bitcoin_block", "fail",
                       f"le digest atteste ne correspond pas au merkle root fourni pour le bloc {height}")

    if dbom_bytes is None:
        record("record_hash_vs_dbom", "skipped",
               "aucun DBoM clair fourni : le contenu métier n'est ni lu ni vérifié")
    else:
        run("record_hash_vs_dbom",
            lambda: _expect(_sha256(jcs(json.loads(dbom_bytes.decode("utf-8")))).hex(),
                            link["record_hash"], "record_hash"),
            "SHA-256 du DBoM canonique (JCS) == record_hash")

    return _summary(checks)


def _expect(actual: str, expected: str, name: str) -> None:
    if actual != expected:
        raise ValueError(f"{name} : valeur recalculée différente de celle de la preuve")


def _summary(checks: list[dict]) -> dict:
    status = {c["id"]: c["status"] for c in checks}
    failed = [c["id"] for c in checks if c["status"] == "fail"]
    core = ("format", "manifest_signature", "manifest_link_binding", "link_hash",
            "merkle_inclusion", "anchor_digest")
    level = 0
    if not failed and all(status.get(i) == "pass" for i in core):
        level = 1
        if status.get("ots_commitment") == "pass":
            level = 2
            if status.get("ots_bitcoin_attestation") == "pass":
                level = 3
                if status.get("bitcoin_block") == "pass":
                    level = 4
    return {"checks": checks, "failed": failed, "level": LEVELS[level], "level_rank": level,
            # V3: ENGAGEMENT_OTS and ATTESTATION_BITCOIN only mean that the FILE declares them; a file fabricated offline
            # reaches them too. Only BLOC_CONFIRME (block checked against an explorer or a given Merkle root) is proof.
            "level_meaning": LEVEL_MEANING[level],
            "antecedence_established": level == 4,
            "signing_key_authenticated": status.get("signing_key_trust") == "pass",
            "dbom_checked": status.get("record_hash_vs_dbom") == "pass"}


# --------------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Vérifie une preuve ancrée ChainDBoM v2b.")
    parser.add_argument("--input", required=True, help="fichier JSON de la preuve ancrée")
    parser.add_argument("--trusted-public-key", help="clé publique Ed25519 du client (hex, 64 car.)")
    parser.add_argument("--trusted-key-fingerprint",
                        help="empreinte SHA-256 de la clé publique du client, publiée par le client (fiche de clé)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--block-merkle-root", help="merkle root du bloc Bitcoin (hex, tel qu'affiché par un explorateur)")
    group.add_argument("--fetch-block", action="store_true", help="interroger blockstream.info (réseau)")
    parser.add_argument("--dbom", help="DBoM clair fourni par le client (optionnel)")
    parser.add_argument("--require", choices=sorted(REQUIRE_TO_LEVEL), default="integrity",
                        help="niveau minimal exigé pour le code de sortie 0 (défaut : integrity). "
                             "ATTENTION : seul « bitcoin » (bloc contrôlé) vaut antériorité ; « ots » et « attestation » "
                             "reposent sur des déclarations du fichier, qu'un fichier fabriqué hors ligne satisfait aussi")
    args = parser.parse_args(argv)
    if args.require in ("ots", "attestation"):
        print(f"AVERTISSEMENT : --require {args.require} ne prouve aucune antériorité (le fichier se contente de la déclarer, "
              "un fichier fabriqué hors ligne y répond aussi) ; utilisez --require bitcoin avec --fetch-block ou "
              "--block-merkle-root.", file=sys.stderr)

    try:
        with open(args.input, "rb") as handle:
            doc = json.loads(handle.read().decode("utf-8"))
        dbom_bytes = open(args.dbom, "rb").read() if args.dbom else None
    except (OSError, ValueError) as exc:
        print(f"Fichier illisible : {exc}", file=sys.stderr)
        return 2

    try:
        result = verify(doc, trusted_public_key=args.trusted_public_key,
                        trusted_key_fingerprint=args.trusted_key_fingerprint,
                        block_merkle_root=args.block_merkle_root, fetch_block=args.fetch_block,
                        dbom_bytes=dbom_bytes)
    except ImportError as exc:
        print(f"Dépendance manquante (pip install cryptography rfc8785) : {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["level_rank"] >= REQUIRE_TO_LEVEL[args.require] and not result["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
