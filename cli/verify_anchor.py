"""
verify_anchor.py

Outil de vérification indépendant Diadroma en ligne de commande.
Permet de valider cryptographiquement qu'un hash est bien ancré 
sur la blockchain Bitcoin via une preuve OpenTimestamps, sans appel
à un serveur Diadroma.

Dépendances : pip install opentimestamps
Usage : python verify_anchor.py --input proof.json
"""

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from typing import Optional

BLOCKSTREAM_API = "https://blockstream.info/api"

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def recompute_merkle_root(leaf_hash_hex: str, proof: list[dict]) -> str:
    current = bytes.fromhex(leaf_hash_hex)
    for step in proof:
        sibling = bytes.fromhex(step["sibling"])
        position = step["position"]
        if position == "right":
            current = _sha256(current + sibling)
        elif position == "left":
            current = _sha256(sibling + current)
        else:
            raise ValueError(f"Position de preuve invalide : {position!r}")
    return current.hex()

def extract_attested_digest(ots_proof_b64: str, expected_root_hex: str) -> dict:
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext

    ots_bytes = base64.b64decode(ots_proof_b64)
    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(ots_bytes))
    root_matches_ots_proof = detached.timestamp.msg.hex() == expected_root_hex

    for msg, attestation in detached.timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            return {
                "found": True,
                "root_matches_ots_proof": root_matches_ots_proof,
                "attested_digest_hex": msg.hex(),
                "block_height": attestation.height,
            }
    return {"found": False, "root_matches_ots_proof": root_matches_ots_proof}

def fetch_block_at_height(height: int) -> Optional[dict]:
    try:
        hash_url = f"{BLOCKSTREAM_API}/block-height/{height}"
        with urllib.request.urlopen(hash_url, timeout=15) as response:
            block_hash = response.read().decode("utf-8").strip()

        block_url = f"{BLOCKSTREAM_API}/block/{block_hash}"
        with urllib.request.urlopen(block_url, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"[avertissement] Impossible d'interroger Blockstream : {exc}", file=sys.stderr)
        return None

def verify(proof_data: dict) -> dict:
    leaf_hash = proof_data["current_hash"]
    expected_root = proof_data["merkle_root"]
    proof = proof_data.get("merkle_proof", [])
    chain = proof_data.get("anchor_chain", "bitcoin")
    ots_proof_b64 = proof_data.get("ots_proof_b64")

    recomputed_root = recompute_merkle_root(leaf_hash, proof)
    root_matches = recomputed_root == expected_root

    result = {
        "on_chain_confirmed": False,
        "conclusion": ""
    }

    if not root_matches:
        result["conclusion"] = "Preuve non confirmée: la racine Merkle recalculée ne correspond pas."
        return result

    if chain != "bitcoin":
        result["conclusion"] = f"Preuve non confirmée: blockchain '{chain}' non supportée."
        return result

    if not ots_proof_b64:
        result["conclusion"] = "Preuve non confirmée: fichier .ots manquant."
        return result

    try:
        ots_result = extract_attested_digest(ots_proof_b64, recomputed_root)
    except ImportError:
        result["conclusion"] = "Preuve non confirmée: dépendance opentimestamps manquante."
        return result

    if not ots_result["root_matches_ots_proof"]:
        result["conclusion"] = "Preuve non confirmée: la preuve .ots ne correspond pas à ce lot."
        return result

    if not ots_result["found"]:
        result["conclusion"] = "Preuve non encore confirmée sur Bitcoin. Réessayez plus tard."
        return result

    block_height = ots_result["block_height"]
    attested_digest_hex = ots_result["attested_digest_hex"]
    block = fetch_block_at_height(block_height)
    
    if block is None:
        result["conclusion"] = "Preuve non confirmée: impossible de joindre l'explorateur de blocs."
        return result

    block_merkle_root = block.get("merkle_root", "")
    reversed_attested = bytes.fromhex(attested_digest_hex)[::-1].hex()
    
    if reversed_attested == block_merkle_root:
        result["on_chain_confirmed"] = True
        result["conclusion"] = f"Preuve confirmée: le hash fourni est relié par cette preuve au bloc Bitcoin n° {block_height}."
    else:
        result["conclusion"] = "Preuve non confirmée: le digest attesté ne correspond pas à la racine du bloc."

    return result

def main():
    parser = argparse.ArgumentParser(description="Vérification CLI Diadroma")
    parser.add_argument("--input", required=True, help="Fichier JSON de preuve")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            proof_data = json.load(f)
    except Exception as e:
        print(f"Preuve non confirmée: erreur de lecture du fichier ({e})")
        sys.exit(1)

    result = verify(proof_data)
    print(result["conclusion"])
    sys.exit(0 if result["on_chain_confirmed"] else 1)

if __name__ == "__main__":
    main()