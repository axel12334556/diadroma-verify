/* Merkle verification only. Bitcoin/OTS verification is NOT implemented. */
const HEX_256 = /^[a-fA-F0-9]{64}$/;
function bytesFromHex(hex) {
  if (typeof hex !== 'string' || !HEX_256.test(hex)) throw new Error('Invalid SHA-256 digest');
  return Uint8Array.from(hex.match(/../g), pair => parseInt(pair, 16));
}
function hexFromBytes(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
function concatBytes(left, right) {
  const both = new Uint8Array(left.length + right.length);
  both.set(left); both.set(right, left.length);
  return both;
}
async function recomputeMerkleRoot(leaf, proof) {
  if (!Array.isArray(proof) || proof.length > 64) throw new Error('Invalid Merkle path');
  let current = bytesFromHex(leaf);
  for (const step of proof) {
    if (!step || !['left', 'right'].includes(step.position)) throw new Error('Invalid Merkle position');
    const sibling = bytesFromHex(step.sibling);
    const input = step.position === 'right' ? concatBytes(current, sibling) : concatBytes(sibling, current);
    current = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  }
  return hexFromBytes(current);
}
async function verifyProof(proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) ||
      typeof proof.merkle_root !== 'string' || !HEX_256.test(proof.merkle_root) ||
      typeof proof.ots_proof_b64 !== 'string' || !proof.ots_proof_b64) {
    return { status: 'error', msg: 'Fichier de preuve invalide ou incomplet.' };
  }
  try {
    const root = await recomputeMerkleRoot(proof.current_hash, proof.merkle_proof);
    if (root !== proof.merkle_root.toLowerCase()) return { status: 'error', msg: 'Preuve Merkle non correspondante.' };
  } catch { return { status: 'error', msg: 'Chemin Merkle invalide.' }; }
  return { status: 'unsupported', msg: 'La racine du lot correspond, mais la vérification OpenTimestamps/Bitcoin est indisponible. Aucune preuve Bitcoin n’est confirmée.' };
}
