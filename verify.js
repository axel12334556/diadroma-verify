/* Fail closed: no Bitcoin confirmation until the complete OTS verifier is implemented. */
const HEX_256 = /^[a-fA-F0-9]{64}$/;
async function verifyProof(proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) ||
      !HEX_256.test(proof.current_hash || '') || !HEX_256.test(proof.merkle_root || '') ||
      !Array.isArray(proof.merkle_proof) || proof.merkle_proof.length > 64 ||
      proof.merkle_proof.some(step => !step || !HEX_256.test(step.sibling || '') || !['left', 'right'].includes(step.position)) ||
      typeof proof.ots_proof_b64 !== 'string' || !proof.ots_proof_b64) {
    return { status: 'error', msg: 'Fichier de preuve invalide ou incomplet.' };
  }
  return { status: 'unsupported', msg: 'Vérification cryptographique indisponible pour le moment. Cette page ne confirme encore aucune preuve.' };
}
