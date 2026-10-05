#!/usr/bin/env python3
"""Check the real anchored proofs with the Python reference verifier (needs cryptography, rfc8785)."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOCK_ROOT = "9a434ade6091a562799a9cc4afd6427fa3333f2fec9058586ed6f0885dff2e05"  # Bitcoin block 970014

spec = importlib.util.spec_from_file_location("ref", ROOT / "tests/tools/reference/verify_v2b_anchored_proof.py")
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
for number in (1, 2):
    doc = json.loads((ROOT / f"tests/vectors/real/proof-{number}.json").read_text())
    result = ref.verify(doc, block_merkle_root=BLOCK_ROOT)
    if result["level"] != "BLOC_CONFIRME" or result["failed"]:
        sys.exit(f"proof-{number}.json: {result['level']} {result['failed']}")
print("real proofs: BLOC_CONFIRME with the Python reference verifier")
