/* Diadroma verification: Merkle path + OpenTimestamps path + Bitcoin block header comparison. */
const HEX_256 = /^[a-fA-F0-9]{64}$/;
const BLOCKSTREAM_API = 'https://blockstream.info/api';
const FETCH_TIMEOUT_MS = 15000;
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
function reverseHex(hex) { return hexFromBytes(bytesFromHex(hex).reverse()); }
async function fetchText(fetchImpl, url) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS) : null;
  try {
    const response = await fetchImpl(url, controller ? { signal: controller.signal, cache: 'no-store' } : { cache: 'no-store' });
    if (!response || !response.ok) throw new Error('HTTP error');
    return await response.text();
  } finally { if (timer) clearTimeout(timer); }
}
async function fetchBlock(fetchImpl, height) {
  if (!Number.isSafeInteger(height) || height < 0) throw new Error('Invalid height');
  const hash = (await fetchText(fetchImpl, `${BLOCKSTREAM_API}/block-height/${height}`)).trim();
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error('Invalid block hash');
  const block = JSON.parse(await fetchText(fetchImpl, `${BLOCKSTREAM_API}/block/${hash}`));
  if (!block || block.id !== hash || block.height !== height || !/^[a-f0-9]{64}$/.test(block.merkle_root || '') || !Number.isFinite(block.timestamp)) throw new Error('Inconsistent block');
  return block;
}
async function verifyProof(proof, fetchImpl) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) ||
      typeof proof.merkle_root !== 'string' || !HEX_256.test(proof.merkle_root) ||
      typeof proof.ots_proof_b64 !== 'string' || !proof.ots_proof_b64) {
    return { status: 'error', msg: 'Fichier de preuve invalide ou incomplet.' };
  }
  if (proof.anchor_chain !== undefined && proof.anchor_chain !== 'bitcoin') {
    return { status: 'error', msg: 'Preuve non confirmée : blockchain non prise en charge.' };
  }
  fetchImpl = fetchImpl || (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
  const expectedRoot = proof.merkle_root.toLowerCase();
  try {
    const root = await recomputeMerkleRoot(proof.current_hash, proof.merkle_proof);
    if (root !== expectedRoot) return { status: 'error', msg: 'Preuve non confirmée : le hash ne correspond pas à la racine du lot.' };
  } catch { return { status: 'error', msg: 'Preuve non confirmée : chemin de vérification invalide.' }; }
  let ots;
  try { ots = await parseOts(proof.ots_proof_b64); }
  catch { return { status: 'error', msg: 'Preuve non confirmée : le fichier de preuve Bitcoin est illisible ou non pris en charge.' }; }
  if (ots.root !== expectedRoot) return { status: 'error', msg: 'Preuve non confirmée : la preuve Bitcoin ne correspond pas à ce lot.' };
  if (!ots.attestations.length) return { status: 'pending', msg: 'Preuve non encore confirmée sur Bitcoin. Réessayez plus tard.' };
  let candidates = ots.attestations;
  if (proof.anchor_block_height !== undefined && proof.anchor_block_height !== null) {
    candidates = candidates.filter(a => a.height === proof.anchor_block_height);
    if (!candidates.length) return { status: 'error', msg: 'Preuve non confirmée : le bloc annoncé ne correspond pas à la preuve.' };
  }
  if (!fetchImpl) return { status: 'unsupported', msg: 'Vérification indisponible : accès réseau impossible.' };
  let networkFailure = false;
  const seen = new Set();
  for (const attestation of candidates) {
    const key = attestation.height + ':' + attestation.digest;
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      const block = await fetchBlock(fetchImpl, attestation.height);
      if (reverseHex(attestation.digest) === block.merkle_root) {
        const date = new Date(block.timestamp * 1000).toLocaleString('fr-FR', { timeZone: 'UTC' });
        return { status: 'success', msg: `Preuve confirmée : ce hash est relié à un lot inscrit dans le bloc Bitcoin n° ${attestation.height}, daté du ${date} UTC.` };
      }
    } catch { networkFailure = true; }
  }
  if (networkFailure) return { status: 'unsupported', msg: 'Vérification indisponible : impossible de consulter ou de valider les informations du bloc. Réessayez plus tard.' };
  return { status: 'error', msg: 'Preuve non confirmée : la preuve ne correspond pas au bloc Bitcoin annoncé.' };
}
