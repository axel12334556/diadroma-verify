#!/usr/bin/env python3
"""Regenerate the synthetic ChainDBoM v2b anchored-proof test vectors, deterministically.

Every value is derived from fixed seeds (no randomness, no clock, no network, no real data).
The expected verdicts are produced by the reference Python verifier
(verify_v2b_anchored_proof.py of the ChainDBoM repository), so the JavaScript verifier is
checked against it. Needs: pip install cryptography rfc8785

    python tests/tools/gen_v2b_vectors.py --verifier PATH/TO/verify_v2b_anchored_proof.py
    python tests/tools/gen_v2b_vectors.py --verifier ... --check    # fail if files would change
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from uuid import UUID

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SUBMISSION_DOMAIN = b"ChainDBoM:v2:submission\x00"
LINK_DOMAIN = b"ChainDBoM:v2:link\x00"
BATCH_DOMAIN = b"ChainDBoM:v2:batch\x00"
HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OUT = Path(__file__).resolve().parents[1] / "vectors" / "v2b"


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---- RFC 6962 style tree, written independently of the verifier -------------------------
def _leaf(link_hash): return sha(b"\x00" + bytes.fromhex(link_hash))
def _node(left, right): return sha(b"\x01" + left + right)


def _subtree(nodes, base):
    if len(nodes) == 1:
        return nodes[0], {base: []}
    split = 1 << ((len(nodes) - 1).bit_length() - 1)
    lroot, lproofs = _subtree(nodes[:split], base)
    rroot, rproofs = _subtree(nodes[split:], base + split)
    proofs = {**lproofs, **rproofs}
    for i in range(base, base + split):
        proofs[i].append({"sibling": rroot.hex(), "position": "right"})
    for i in range(base + split, base + len(nodes)):
        proofs[i].append({"sibling": lroot.hex(), "position": "left"})
    return _node(lroot, rroot), proofs


def merkle(link_hashes):
    root, proofs = _subtree([_leaf(h) for h in link_hashes], 0)
    return root.hex(), [proofs[i] for i in range(len(link_hashes))]


# ---- .ots serializer (from the file format description) ---------------------------------
def varuint(value):
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def varbytes(data): return varuint(len(data)) + data
def bitcoin_att(height): return bytes.fromhex("0588960d73d71901") + varbytes(varuint(height))
def pending_att(uri): return bytes.fromhex("83dfe30d2ef90c8e") + varbytes(varbytes(uri.encode()))


def tnode(attestations=(), edges=()):
    items = [b"\x00" + a for a in attestations]
    for tag, arg, child in edges:
        items.append(bytes([tag]) + (b"" if arg is None else varbytes(arg)) + child)
    return b"".join(b"\xff" + i for i in items[:-1]) + items[-1]


def ots_file(digest_hex, tree): return HEADER + varuint(1) + b"\x08" + bytes.fromhex(digest_hex) + tree


def bitcoin_ots(anchor_digest, height, nonce=b"synthetic-nonce"):
    attested = sha(bytes.fromhex(anchor_digest) + nonce)
    tree = tnode(edges=[(0xF0, nonce, tnode(edges=[(0x08, None, tnode([bitcoin_att(height)]))]))])
    return ots_file(anchor_digest, tree), attested[::-1].hex()  # block merkle root as an explorer shows it


def b64(data): return base64.b64encode(data).decode()


def build(name, *, links=2, index=0, bitcoin=True, height=925847, previous_anchor=None,
          batch_number=1, dbom=None):
    seed = sha(b"diadroma-verify synthetic vector " + name.encode())
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client = str(UUID(bytes=sha(b"client " + seed)[:16], version=4))
    dbom = dbom or {"synthetic": "dbom", "name": name, "quantity": 3}

    link_hashes, records, manifests, previous = [], [], [], None
    for seq in range(1, links + 1):
        record = sha(rfc8785.dumps(dbom) if seq == index + 1 else f"other-{seq}-{client}".encode()).hex()
        prev_bytes = bytes(32) if previous is None else bytes.fromhex(previous)
        link = sha(LINK_DOMAIN + UUID(client).bytes + seq.to_bytes(8, "big") + prev_bytes
                   + bytes.fromhex(record)).hex()
        submission = str(UUID(bytes=sha(b"submission %d " % seq + seed)[:16], version=4))
        manifest = {"format_version": 2, "client_id": client, "submission_id": submission,
                    "record_hash": record, "inputs": [], "ciphertext_format": "age-encryption.org/v1",
                    "ciphertext_hash": sha(f"ct-{seq}".encode()).hex(),
                    "recipient_key_id": "age-1", "signing_key_id": "sign-1"}
        manifests.append((manifest, previous))
        records.append(record)
        link_hashes.append(link)
        previous = link

    root, proofs = merkle(link_hashes)
    prev_a = bytes(32) if previous_anchor is None else bytes.fromhex(previous_anchor)
    anchor_digest = sha(BATCH_DOMAIN + batch_number.to_bytes(8, "big") + prev_a + bytes.fromhex(root)).hex()
    if bitcoin:
        ots, block_root = bitcoin_ots(anchor_digest, height)
    else:
        ots, block_root = ots_file(anchor_digest, tnode([pending_att("https://calendar.synthetic.invalid")])), None

    manifest, previous_link = manifests[index]
    signature = private.sign(SUBMISSION_DOMAIN + rfc8785.dumps(manifest))
    doc = {
        "format": "chaindbom-anchored-proof-v2b", "format_version": 1,
        "proof_only": {
            "format": "chaindbom-proof-only-v2b-prototype",
            "verification_state": "signature-and-single-link-only;not-anchored",
            "submission": {"signed_manifest": manifest, "signature_hex": signature.hex(),
                           "signing_public_key_hex": public.hex()},
            "link": {"client_id": client, "submission_id": manifest["submission_id"],
                     "client_sequence": index + 1, "previous_link_hash": previous_link,
                     "record_hash": records[index], "link_hash": link_hashes[index]},
        },
        "anchor": {
            "anchor_chain": "bitcoin", "anchor_block_height": height if bitcoin else None,
            "anchor_digest": anchor_digest, "batch_number": batch_number, "merkle_index": index,
            "merkle_proof": proofs[index], "merkle_root": root, "ots_proof_b64": b64(ots),
            "previous_anchor_digest": previous_anchor, "record_count": links,
            "status": "anchored" if bitcoin else "submitted",
        },
    }
    return {"doc": doc, "public_key": public.hex(), "block_root": block_root, "dbom": dbom,
            "ots": ots, "anchor_digest": anchor_digest}


def flip(hexstr, pos=0):
    return hexstr[:pos] + ("0" if hexstr[pos] != "0" else "1") + hexstr[pos + 1:]


def vectors():
    """name -> (document, options). options: trusted_key (bool), block_root (bool|'wrong'), dbom (bool)."""
    out = {}
    base = build("valid_5_leaves", links=5, index=3, previous_anchor="ab" * 32, batch_number=7)
    out["valid_5_leaves"] = (base["doc"], {"base": base, "trusted_key": True, "block_root": True})
    single = build("valid_single", links=1, index=0)
    out["valid_single"] = (single["doc"], {"base": single, "trusted_key": True, "block_root": True})
    out["valid_no_trust_no_block"] = (copy.deepcopy(base["doc"]), {"base": base})
    out["valid_with_dbom"] = (copy.deepcopy(base["doc"]),
                              {"base": base, "trusted_key": True, "block_root": True, "dbom": True})
    out["valid_wrong_dbom"] = (copy.deepcopy(base["doc"]),
                               {"base": base, "trusted_key": True, "block_root": True, "dbom": "wrong"})
    out["wrong_trusted_key"] = (copy.deepcopy(base["doc"]),
                                {"base": base, "trusted_key": "wrong", "block_root": True})
    out["wrong_block_root"] = (copy.deepcopy(base["doc"]),
                               {"base": base, "trusted_key": True, "block_root": "wrong"})
    pend = build("pending", links=2, index=1, bitcoin=False)
    out["pending_ots"] = (pend["doc"], {"base": pend, "trusted_key": True})

    def mutated(key, mutate, **options):
        doc = copy.deepcopy(base["doc"])
        mutate(doc)
        out[key] = (doc, {"base": base, "trusted_key": True, "block_root": True, **options})

    sub = lambda d: d["proof_only"]["submission"]
    link = lambda d: d["proof_only"]["link"]
    anc = lambda d: d["anchor"]
    mutated("tampered_signature", lambda d: sub(d).__setitem__("signature_hex", flip(sub(d)["signature_hex"])))
    mutated("tampered_manifest", lambda d: sub(d)["signed_manifest"].__setitem__("recipient_key_id", "age-2"))
    mutated("binding_mismatch", lambda d: link(d).__setitem__("record_hash", flip(link(d)["record_hash"])))
    mutated("wrong_link_hash", lambda d: link(d).__setitem__("link_hash", flip(link(d)["link_hash"])))
    mutated("wrong_sequence", lambda d: link(d).__setitem__("client_sequence", 2))
    mutated("tampered_merkle_sibling",
            lambda d: anc(d)["merkle_proof"][0].__setitem__("sibling", flip(anc(d)["merkle_proof"][0]["sibling"])))
    mutated("swapped_merkle_position",
            lambda d: anc(d)["merkle_proof"][0].__setitem__("position", "left" if anc(d)["merkle_proof"][0]["position"] == "right" else "right"))
    mutated("tampered_anchor_digest", lambda d: anc(d).__setitem__("anchor_digest", flip(anc(d)["anchor_digest"])))
    mutated("wrong_previous_anchor", lambda d: anc(d).__setitem__("previous_anchor_digest", "cd" * 32))
    mutated("wrong_batch_number", lambda d: anc(d).__setitem__("batch_number", 8))
    other = build("other_digest", links=5, index=3, previous_anchor="ab" * 32, batch_number=7)
    mutated("ots_commits_to_other_digest",
            lambda d: anc(d).__setitem__("ots_proof_b64", b64(bitcoin_ots("ee" * 32, 925847)[0])))
    mutated("ots_truncated", lambda d: anc(d).__setitem__("ots_proof_b64", b64(base["ots"][:-3])))
    mutated("ots_trailing_bytes", lambda d: anc(d).__setitem__("ots_proof_b64", b64(base["ots"] + b"\x00")))
    mutated("ots_bad_base64", lambda d: anc(d).__setitem__("ots_proof_b64", "***not base64***"))
    mutated("declared_height_not_in_proof", lambda d: anc(d).__setitem__("anchor_block_height", 925848))
    mutated("declared_status_is_not_believed", lambda d: anc(d).__setitem__("status", "submitted"))
    mutated("extra_top_level_key", lambda d: d.__setitem__("note", "x"))
    mutated("extra_anchor_key", lambda d: anc(d).__setitem__("note", "x"))
    mutated("unknown_format", lambda d: d.__setitem__("format", "other"))
    mutated("unknown_chain", lambda d: anc(d).__setitem__("anchor_chain", "litecoin"))
    mutated("uppercase_hash", lambda d: anc(d).__setitem__("merkle_root", anc(d)["merkle_root"].upper()))
    mutated("merkle_index_out_of_batch", lambda d: anc(d).__setitem__("merkle_index", 5))
    mutated("short_public_key", lambda d: sub(d).__setitem__("signing_public_key_hex", "00" * 31))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("v2b_ref", args.verifier)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)

    files, expected = {}, {}
    for name, (doc, opt) in vectors().items():
        base = opt["base"]
        files[f"{name}.json"] = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        kwargs, options = {}, {}
        if opt.get("trusted_key"):
            key = base["public_key"] if opt["trusted_key"] is True else flip(base["public_key"])
            kwargs["trusted_public_key"] = key
            options["trusted_public_key"] = key
        if opt.get("block_root"):
            root = base["block_root"] if opt["block_root"] is True else flip(base["block_root"])
            kwargs["block_merkle_root"] = root
            options["block_merkle_root"] = root
        if opt.get("dbom"):
            dbom = base["dbom"] if opt["dbom"] is True else {**base["dbom"], "quantity": 4}
            text = json.dumps(dbom, sort_keys=True) + "\n"
            files[f"{name}.dbom.json"] = text
            kwargs["dbom_bytes"] = text.encode()
            options["dbom_file"] = f"{name}.dbom.json"
        result = ref.verify(doc, **kwargs)
        expected[name] = {
            "options": options,
            "expected": {
                "level": result["level"], "failed": result["failed"],
                "statuses": {c["id"]: c["status"] for c in result["checks"]},
                "signing_key_authenticated": result["signing_key_authenticated"],
                "dbom_checked": result["dbom_checked"],
            },
        }
    files["expected.json"] = json.dumps(expected, indent=2, sort_keys=True) + "\n"

    OUT.mkdir(parents=True, exist_ok=True)
    changed = []
    for filename, text in files.items():
        path = OUT / filename
        if not path.exists() or path.read_text() != text:
            changed.append(filename)
            if not args.check:
                path.write_text(text)
    known = set(files)
    stale = [p.name for p in OUT.glob("*.json") if p.name not in known]
    if args.check:
        if changed or stale:
            print("vectors out of date:", changed, "stale:", stale, file=sys.stderr)
            return 1
        print(f"{len(files)} vector files up to date")
        return 0
    for name in stale:
        (OUT / name).unlink()
    print(f"wrote {len(files)} files ({len(changed)} changed, {len(stale)} removed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
