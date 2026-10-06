import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verifier', ROOT / 'cli' / 'verify_anchor.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
proof = json.loads((ROOT / 'tests' / 'valid_single.json').read_text(encoding='utf-8'))
good = '673b88a49932c2d9d62bf9ed62c283a10a6b1c84c04ba7843dab92299c9a48b7'
root = 'b7489a9c2992ab3d84a74bc0841c6b0aa183c262edf92bd6d9c23299a4883b67'

def extractor(encoded, expected):
    return [('00' * 32, 969033), (good, 969034)]

def fetcher(height):
    return {'merkle_root': '00' * 32 if height == 969033 else root}

class HeightTests(unittest.TestCase):
    def test_declared_height_wins(self):
        result = verifier.verify(proof, fetcher=fetcher, extractor=extractor)
        self.assertTrue(result['on_chain_confirmed'])
        self.assertIn('969034', result['conclusion'])
        self.assertNotIn('969033', result['conclusion'])
        self.assertIn('sans signature', result['conclusion'])  # V1: a timestamp only, never presented as a confirmed proof
        self.assertNotIn('Preuve confirmée', result['conclusion'])

    def test_no_matching_attestation(self):
        other = dict(proof, anchor_block_height=969035)
        result = verifier.verify(other, fetcher=fetcher, extractor=extractor)
        self.assertFalse(result['on_chain_confirmed'])

if __name__ == '__main__':
    unittest.main()
