"""Vérification indépendante d'une preuve Diadroma via OpenTimestamps et Blockstream.
Usage: python cli/verify_anchor.py --input tests/valid_single.json
Dépendance: pip install opentimestamps
"""
import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.request

API = 'https://blockstream.info/api'
HEX = re.compile(r'^[0-9a-fA-F]{64}$')

def digest(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError('Digest SHA-256 invalide')
    return bytes.fromhex(value)

def merkle_root(leaf, path):
    current = digest(leaf)
    if not isinstance(path, list) or len(path) > 64:
        raise ValueError('Chemin Merkle invalide')
    for step in path:
        if not isinstance(step, dict) or step.get('position') not in ('left', 'right'):
            raise ValueError('Position Merkle invalide')
        sibling = digest(step.get('sibling'))
        data = current + sibling if step['position'] == 'right' else sibling + current
        current = hashlib.sha256(data).digest()
    return current.hex()

def ots_attestations(encoded, expected_root):
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    if not isinstance(encoded, str) or len(encoded) > 90000:
        raise ValueError('Preuve OTS invalide')
    raw = base64.b64decode(encoded, validate=True)
    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
    if detached.timestamp.msg.hex() != expected_root:
        raise ValueError('Racine OTS différente')
    found = []
    for msg, attestation in detached.timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            if len(msg) != 32 or not isinstance(attestation.height, int) or attestation.height < 0:
                raise ValueError('Attestation Bitcoin invalide')
            found.append((msg.hex(), attestation.height))
    return found

def fetch_block(height):
    with urllib.request.urlopen(f'{API}/block-height/{height}', timeout=15) as response:
        block_hash = response.read().decode('ascii').strip()
    if not HEX.fullmatch(block_hash):
        raise ValueError('Identifiant du bloc invalide')
    with urllib.request.urlopen(f'{API}/block/{block_hash}', timeout=15) as response:
        block = json.loads(response.read().decode('utf-8'))
    if (not isinstance(block, dict) or block.get('id') != block_hash or
            block.get('height') != height or not isinstance(block.get('merkle_root'), str) or
            not HEX.fullmatch(block['merkle_root'])):
        raise ValueError('Bloc incohérent')
    return block

def verify(proof, fetcher=fetch_block, extractor=ots_attestations):
    result = {'on_chain_confirmed': False, 'conclusion': 'Preuve non confirmée.'}
    try:
        if not isinstance(proof, dict) or proof.get('anchor_chain', 'bitcoin') != 'bitcoin':
            result['conclusion'] = 'Preuve non confirmée : blockchain non prise en charge.'
            return result
        expected = digest(proof['merkle_root']).hex()
        if merkle_root(proof['current_hash'], proof['merkle_proof']) != expected:
            result['conclusion'] = 'Preuve non confirmée : le hash ne correspond pas à la racine du lot.'
            return result
        attestations = extractor(proof['ots_proof_b64'], expected)
        if not attestations:
            result['conclusion'] = 'Preuve non encore confirmée sur Bitcoin.'
            return result
        declared_height = proof.get('anchor_block_height')
        if declared_height is not None:
            attestations = [(d, h) for d, h in attestations if h == declared_height]
            if not attestations:
                result['conclusion'] = 'Preuve non confirmée : le bloc annoncé est incohérent.'
                return result
        failed_network = False
        for attested, height in dict.fromkeys(attestations):
            try:
                block = fetcher(height)
                if bytes.fromhex(attested)[::-1].hex() == block['merkle_root']:
                    result['on_chain_confirmed'] = True
                    result['conclusion'] = f'Preuve confirmée: le hash fourni est relié par cette preuve au bloc Bitcoin n° {height}.'
                    return result
            except (OSError, TimeoutError, ValueError, KeyError, TypeError):
                failed_network = True
        result['conclusion'] = ('Vérification indisponible : explorateur injoignable ou bloc incohérent.' if failed_network
                                else 'Preuve non confirmée : digest différent de la racine du bloc.')
    except ImportError:
        result['conclusion'] = 'Vérification indisponible : paquet opentimestamps absent.'
    except (KeyError, TypeError, ValueError, OverflowError, base64.binascii.Error):
        result['conclusion'] = 'Preuve non confirmée : fichier ou preuve cryptographique invalide.'
    return result

def main():
    parser = argparse.ArgumentParser(description='Vérification CLI Diadroma')
    parser.add_argument('--input', required=True, help='Chemin du JSON de preuve')
    args = parser.parse_args()
    try:
        with open(args.input, encoding='utf-8') as f:
            proof = json.load(f)
        result = verify(proof)
    except (OSError, ValueError):
        print('Preuve non confirmée : impossible de lire ce fichier JSON.')
        return 1
    print(result['conclusion'])
    return 0 if result['on_chain_confirmed'] else 1

if __name__ == '__main__':
    sys.exit(main())
