/* ChainDBoM v2b anchored-proof verifier (format "chaindbom-anchored-proof-v2b", version 1).
 *
 * Runs entirely in the browser (or Node >= 20): nothing but block identifiers is ever sent anywhere,
 * and only when the caller asks for the Bitcoin block to be fetched. It is an independent port of
 * verify_v2b_anchored_proof.py (ChainDBoM repository) and is checked against it with shared vectors
 * (tests/vectors/v2b). Every check is reported separately; the "status" field of the document is
 * only a declaration and is never believed.
 *
 * Levels: INVALIDE < INTEGRITE < ENGAGEMENT_OTS < ATTESTATION_BITCOIN < BLOC_CONFIRME.
 * A proof says nothing about the truth of the business data, nor that the public key belongs to the
 * client unless a trusted key or fingerprint obtained elsewhere is supplied.
 */
(function (root) {
  'use strict';
  const PROOF_FORMAT = 'chaindbom-anchored-proof-v2b';
  const PROOF_ONLY_FORMAT = 'chaindbom-proof-only-v2b-prototype';
  const enc = new TextEncoder();
  const SUBMISSION_DOMAIN = enc.encode('ChainDBoM:v2:submission\0');
  const LINK_DOMAIN = enc.encode('ChainDBoM:v2:link\0');
  const BATCH_DOMAIN = enc.encode('ChainDBoM:v2:batch\0');
  const BLOCKSTREAM_API = 'https://blockstream.info/api';
  const FETCH_TIMEOUT_MS = 15000;
  const MAX_OTS_BYTES = 1000000, MAX_OTS_NODES = 50000, MAX_OTS_DEPTH = 300;
  const LEVELS = ['INVALIDE', 'INTEGRITE', 'ENGAGEMENT_OTS', 'ATTESTATION_BITCOIN', 'BLOC_CONFIRME'];
  const HEX64 = /^[0-9a-f]{64}$/;
  const KEYCARD_FORMAT = 'chaindbom-key-card-v1';
  const KEYCARD_DOMAIN = enc.encode('ChainDBoM:v2:key-card\0');
  const KEYCARD_KEYS = ['format', 'format_version', 'client_id', 'signing_key_id', 'signing_public_key_hex',
    'signing_key_fingerprint_sha256', 'recipient_key_id', 'age_recipient', 'created_at', 'signature_hex'];
  const KEY_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
  const AGE_RECIPIENT_RE = /^age1[0-9a-z]{58}$/;
  const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  class FormatError extends Error {}
  class OtsError extends Error {}

  // ------------------------------------------------------------------ bytes helpers
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  function fromHex(text, name) {
    if (typeof text !== 'string' || text.length % 2 || !/^[0-9a-fA-F]*$/.test(text)) throw new FormatError(name + ' doit être hexadécimal');
    const out = new Uint8Array(text.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(text.substr(2 * i, 2), 16);
    return out;
  }
  function hex64(value, name) {
    if (typeof value !== 'string' || !HEX64.test(value)) throw new FormatError(name + ' doit être une empreinte SHA-256 en hexadécimal minuscule');
    return fromHex(value, name);
  }
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }
  const sha256 = async data => new Uint8Array(await root.crypto.subtle.digest('SHA-256', data));
  const be64 = n => {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(n));
    return out;
  };
  const isObject = v => typeof v === 'object' && v !== null && !Array.isArray(v);
  const isInt = (v, min) => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
  function exactKeys(obj, keys, name) {
    const got = isObject(obj) ? Object.keys(obj).sort() : null;
    if (!got || got.length !== keys.length || got.some((k, i) => k !== keys.slice().sort()[i])) {
      throw new FormatError(name + ' : clés attendues exactement ' + JSON.stringify(keys.slice().sort()));
    }
    return obj;
  }

  // ------------------------------------------------------------------ RFC 8785 (JCS)
  function jcs(value) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER)) {
        throw new FormatError('nombre non représentable en JCS');
      }
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
    if (isObject(value)) {
      return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
    }
    throw new FormatError('valeur non sérialisable');
  }

  // ------------------------------------------------------------------ document structure
  function parseDocument(doc) {
    const top = exactKeys(doc, ['format', 'format_version', 'proof_only', 'anchor'], 'document');
    if (top.format !== PROOF_FORMAT || top.format_version !== 1) throw new FormatError('format ou version inconnus');
    const proofOnly = exactKeys(top.proof_only, ['format', 'verification_state', 'submission', 'link'], 'proof_only');
    if (proofOnly.format !== PROOF_ONLY_FORMAT) throw new FormatError('format proof_only inconnu');
    const submission = exactKeys(proofOnly.submission, ['signed_manifest', 'signature_hex', 'signing_public_key_hex'], 'submission');
    const link = exactKeys(proofOnly.link,
      ['client_id', 'submission_id', 'client_sequence', 'previous_link_hash', 'record_hash', 'link_hash'], 'link');
    const anchor = exactKeys(top.anchor,
      ['anchor_chain', 'anchor_block_height', 'anchor_digest', 'batch_number', 'merkle_index', 'merkle_proof',
       'merkle_root', 'ots_proof_b64', 'previous_anchor_digest', 'record_count', 'status'], 'anchor');
    if (!isObject(submission.signed_manifest)) throw new FormatError('signed_manifest doit être un objet');
    const signature = fromHex(submission.signature_hex, 'signature');
    const publicKey = fromHex(submission.signing_public_key_hex, 'clé publique');
    if (signature.length !== 64 || publicKey.length !== 32) throw new FormatError('signature (64 octets) ou clé publique (32 octets) de mauvaise taille');
    hex64(link.record_hash, 'link.record_hash');
    hex64(link.link_hash, 'link.link_hash');
    if (link.previous_link_hash !== null) hex64(link.previous_link_hash, 'link.previous_link_hash');
    if (!isInt(link.client_sequence, 1)) throw new FormatError('link.client_sequence doit être un entier >= 1');
    hex64(anchor.merkle_root, 'anchor.merkle_root');
    hex64(anchor.anchor_digest, 'anchor.anchor_digest');
    if (anchor.previous_anchor_digest !== null) hex64(anchor.previous_anchor_digest, 'anchor.previous_anchor_digest');
    if (!isInt(anchor.batch_number, 1)) throw new FormatError('anchor.batch_number doit être un entier >= 1');
    if (!isInt(anchor.record_count, 1)) throw new FormatError('anchor.record_count doit être un entier >= 1');
    if (!isInt(anchor.merkle_index, 0)) throw new FormatError('anchor.merkle_index doit être un entier >= 0');
    if (anchor.merkle_index >= anchor.record_count) throw new FormatError('anchor.merkle_index hors du lot');
    if (anchor.anchor_chain !== 'bitcoin') throw new FormatError('anchor_chain non pris en charge');
    if (anchor.anchor_block_height !== null && !isInt(anchor.anchor_block_height, 1)) throw new FormatError('anchor.anchor_block_height invalide');
    if (typeof anchor.ots_proof_b64 !== 'string') throw new FormatError('anchor.ots_proof_b64 doit être une chaîne base64');
    if (!Array.isArray(anchor.merkle_proof)) throw new FormatError('anchor.merkle_proof doit être une liste');
    if (anchor.merkle_proof.length > 64) throw new FormatError('anchor.merkle_proof trop longue');
    for (const step of anchor.merkle_proof) {
      exactKeys(step, ['sibling', 'position'], 'étape de preuve Merkle');
      hex64(step.sibling, 'sibling');
      if (step.position !== 'left' && step.position !== 'right') throw new FormatError('position de preuve Merkle invalide');
    }
    return { manifest: submission.signed_manifest, signature, publicKey, link, anchor };
  }

  // ------------------------------------------------------------------ cryptographic rules
  async function verifySignature(manifest, signature, publicKey) {
    const subtle = root.crypto.subtle;
    let key;
    try {
      key = await subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    } catch (error) {
      if (error && error.name === 'NotSupportedError') { const e = new Error('Ed25519 non pris en charge par ce navigateur'); e.unsupported = true; throw e; }
      throw new Error('clé publique Ed25519 invalide');
    }
    const message = concat(SUBMISSION_DOMAIN, enc.encode(jcs(manifest)));
    if (!(await subtle.verify({ name: 'Ed25519' }, key, signature, message))) throw new Error('signature Ed25519 invalide');
  }
  async function computeLinkHash(clientId, sequence, recordHash, previous) {
    if (typeof clientId !== 'string' || !UUID_RE.test(clientId)) throw new Error('client_id non canonique');
    if ((sequence === 1) !== (previous === null)) throw new Error('seule la genèse peut omettre previous_link_hash');
    return hex(await sha256(concat(LINK_DOMAIN, fromHex(clientId.replace(/-/g, ''), 'client_id'), be64(sequence),
      previous === null ? new Uint8Array(32) : fromHex(previous, 'previous'), fromHex(recordHash, 'record_hash'))));
  }
  async function merkleRootFromProof(linkHash, proof) {
    let current = await sha256(concat(Uint8Array.of(0), fromHex(linkHash, 'link_hash')));
    for (const step of proof) {
      const sibling = fromHex(step.sibling, 'sibling');
      current = await sha256(concat(Uint8Array.of(1), step.position === 'right' ? concat(current, sibling) : concat(sibling, current)));
    }
    return hex(current);
  }
  async function computeAnchorDigest(batchNumber, previous, merkleRoot) {
    return hex(await sha256(concat(BATCH_DOMAIN, be64(batchNumber),
      previous === null ? new Uint8Array(32) : fromHex(previous, 'previous'), fromHex(merkleRoot, 'merkle_root'))));
  }

  // ------------------------------------------------------------------ minimal .ots reader
  const OTS_MAGIC = fromHex('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'magic');
  const BITCOIN_TAG = '0588960d73d71901', PENDING_TAG = '83dfe30d2ef90c8e';

  class Reader {
    constructor(data) { this.data = data; this.pos = 0; }
    read(count) {
      if (!Number.isSafeInteger(count) || count < 0 || this.pos + count > this.data.length) throw new OtsError('preuve .ots tronquée');
      const chunk = this.data.slice(this.pos, this.pos + count);
      this.pos += count;
      return chunk;
    }
    byte() { return this.read(1)[0]; }
    varuint() {
      let value = 0n, shift = 0n;
      for (;;) {
        const octet = this.byte();
        value |= BigInt(octet & 0x7f) << shift;
        if (!(octet & 0x80)) {
          if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new OtsError('entier .ots trop grand');
          return Number(value);
        }
        shift += 7n;
        if (shift > 63n) throw new OtsError('varuint trop long');
      }
    }
    varbytes(limit) {
      const length = this.varuint();
      if (length > limit) throw new OtsError('champ .ots trop grand');
      return this.read(length);
    }
  }

  async function applyUnary(tag, msg) {
    if (tag === 0x08) return sha256(msg);
    if (tag === 0x02) return new Uint8Array(await root.crypto.subtle.digest('SHA-1', msg));
    if (tag === 0xf2) return msg.slice().reverse();
    if (tag === 0xf3) return enc.encode(hex(msg));
    if (tag === 0x03) throw new OtsError('RIPEMD-160 non pris en charge dans le navigateur');
    throw new OtsError('opération .ots non prise en charge : 0x' + tag.toString(16).padStart(2, '0'));
  }

  function decodeBase64(text) {
    if (typeof text !== 'string' || text.length > Math.ceil(MAX_OTS_BYTES / 3) * 4 + 4) throw new OtsError('preuve .ots trop volumineuse');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new OtsError('base64 invalide');
    const raw = root.atob(text);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  async function parseOts(bytes) {
    if (bytes.length > MAX_OTS_BYTES) throw new OtsError('preuve .ots trop volumineuse');
    const reader = new Reader(bytes);
    if (hex(reader.read(OTS_MAGIC.length)) !== hex(OTS_MAGIC)) throw new OtsError('en-tête .ots inconnu');
    if (reader.varuint() !== 1) throw new OtsError('version .ots non prise en charge');
    if (reader.byte() !== 0x08) throw new OtsError("l'opération de hachage du fichier n'est pas SHA-256");
    const fileDigest = reader.read(32);
    const attestations = [];
    let nodes = 0;
    async function walk(msg, depth) {
      nodes++;
      if (nodes > MAX_OTS_NODES || depth > MAX_OTS_DEPTH) throw new OtsError('arbre .ots trop grand ou trop profond');
      let tag = reader.byte();
      while (tag === 0xff) { await handle(msg, reader.byte(), depth); tag = reader.byte(); }
      await handle(msg, tag, depth);
    }
    async function handle(msg, tag, depth) {
      if (tag === 0x00) {
        const kind = hex(reader.read(8));
        const payload = new Reader(reader.varbytes(8192));
        if (kind === BITCOIN_TAG) attestations.push({ type: 'bitcoin', height: payload.varuint(), digest: msg });
        else if (kind === PENDING_TAG) attestations.push({ type: 'pending', digest: msg });
        else attestations.push({ type: 'other', digest: msg });
      } else if (tag === 0xf0 || tag === 0xf1) {
        const argument = reader.varbytes(4096);
        if (!argument.length) throw new OtsError('opérande .ots vide');
        await walk(tag === 0xf0 ? concat(msg, argument) : concat(argument, msg), depth + 1);
      } else {
        await walk(await applyUnary(tag, msg), depth + 1);
      }
    }
    await walk(fileDigest, 0);
    if (reader.pos !== bytes.length) throw new OtsError('octets en trop après la preuve .ots');
    return { fileDigest, attestations };
  }

  // ------------------------------------------------------------------ Bitcoin block (optional network)
  async function fetchText(fetchImpl, url) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS) : null;
    try {
      const response = await fetchImpl(url, controller ? { signal: controller.signal, cache: 'no-store' } : { cache: 'no-store' });
      if (!response || !response.ok) throw new Error('HTTP error');
      return await response.text();
    } finally { if (timer) clearTimeout(timer); }
  }
  async function fetchBlockMerkleRoot(fetchImpl, height) {
    const blockHash = (await fetchText(fetchImpl, BLOCKSTREAM_API + '/block-height/' + height)).trim();
    if (!HEX64.test(blockHash)) throw new Error('empreinte de bloc invalide');
    const block = JSON.parse(await fetchText(fetchImpl, BLOCKSTREAM_API + '/block/' + blockHash));
    if (!block || block.id !== blockHash || block.height !== height || !HEX64.test(block.merkle_root || '')) throw new Error('bloc incohérent');
    return block.merkle_root;
  }

  function normalizeFingerprint(value) {
    const cleaned = String(value).replace(/[\s:\-]/g, '').toLowerCase();
    if (!HEX64.test(cleaned)) throw new Error("l'empreinte de confiance doit contenir 64 caractères hexadécimaux (SHA-256)");
    return cleaned;
  }

  // ------------------------------------------------------------------ key card (chaindbom-key-card-v1)
  // Strict validation of a client's self-signed public key card, mirroring the Python reference
  // (chaindbom/key_card.py verify_key_card). Returns the facts to compare; throws on any defect.
  // The card proves POSSESSION of the key, never the client's identity: that comes from the channel
  // on which the auditor obtained the card.
  function formatFingerprint(value) {
    return normalizeFingerprint(value).replace(/(.{8})(?=.)/g, '$1 ');
  }
  async function checkKeyCard(card) {
    exactKeys(card, KEYCARD_KEYS, 'fiche de clé');
    if (card.format !== KEYCARD_FORMAT || card.format_version !== 1) throw new FormatError('format de fiche de clé non pris en charge');
    for (const field of KEYCARD_KEYS.slice(2)) {
      if (typeof card[field] !== 'string') throw new FormatError(field + ' doit être une chaîne de caractères');
    }
    if (!UUID_RE.test(card.client_id)) throw new FormatError("client_id doit être un UUID canonique en minuscules");
    if (!KEY_ID_RE.test(card.signing_key_id) || !KEY_ID_RE.test(card.recipient_key_id)) throw new FormatError("identifiant de clé invalide");
    if (!HEX64.test(card.signing_public_key_hex) || !HEX64.test(card.signing_key_fingerprint_sha256)) {
      throw new FormatError("la clé publique et l'empreinte doivent compter 64 caractères hexadécimaux minuscules");
    }
    if (!/^[0-9a-f]{128}$/.test(card.signature_hex)) throw new FormatError('la signature doit compter 128 caractères hexadécimaux minuscules');
    if (!AGE_RECIPIENT_RE.test(card.age_recipient)) throw new FormatError('destinataire age invalide');
    if (!TIMESTAMP_RE.test(card.created_at)) throw new FormatError('created_at doit être en UTC, par exemple 2026-10-05T12:00:00Z');
    const publicKey = fromHex(card.signing_public_key_hex, 'signing_public_key_hex');
    if (hex(await sha256(publicKey)) !== card.signing_key_fingerprint_sha256) throw new FormatError("l'empreinte ne correspond pas à la clé publique");
    const unsigned = {};
    for (const key of KEYCARD_KEYS) if (key !== 'signature_hex') unsigned[key] = card[key];
    const message = concat(KEYCARD_DOMAIN, enc.encode(jcs(unsigned)));
    let selfSignature = 'verified';
    try {
      const key = await root.crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
      if (!(await root.crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(card.signature_hex, 'signature_hex'), message))) {
        throw new Error('auto-signature de la fiche invalide');
      }
    } catch (error) {
      if (error && error.name === 'NotSupportedError') selfSignature = 'unsupported';
      else if (error && error.message === 'auto-signature de la fiche invalide') throw error;
      else throw new Error('clé publique de la fiche invalide');
    }
    return { client_id: card.client_id, signing_key_id: card.signing_key_id,
      fingerprint_sha256: card.signing_key_fingerprint_sha256, created_at: card.created_at, self_signature: selfSignature };
  }

  // ------------------------------------------------------------------ verification
  async function verify(doc, options) {
    options = options || {};
    const checks = [];
    const record = (id, status, detail) => { checks.push({ id, status, detail }); return status === 'pass'; };
    const run = async (id, fn, okDetail) => {
      try { await fn(); } catch (error) {
        if (error && error.unsupported) return record(id, 'skipped', error.message);
        return record(id, 'fail', (error && error.message) || 'erreur');
      }
      return record(id, 'pass', okDetail);
    };
    const expect = (actual, expected, name) => { if (actual !== expected) throw new Error(name + ' : valeur recalculée différente de celle de la preuve'); };

    let parts;
    try { parts = parseDocument(doc); } catch (error) {
      if (!(error instanceof FormatError)) throw error;
      record('format', 'fail', error.message);
      return summary(checks);
    }
    record('format', 'pass', PROOF_FORMAT + ' v1, structure valide');
    const { manifest, link, anchor } = parts;

    await run('manifest_signature', () => verifySignature(manifest, parts.signature, parts.publicKey),
      'signature Ed25519 valide pour la clé publique de la preuve');

    const trustedKey = options.trustedPublicKey, trustedFingerprint = options.trustedKeyFingerprint;
    if (!trustedKey && !trustedFingerprint) {
      record('signing_key_trust', 'skipped', "aucune clé de confiance fournie : la clé de la preuve n'est pas authentifiée");
    } else {
      const problems = [];
      const proofKey = hex(parts.publicKey);
      if (trustedKey && proofKey !== String(trustedKey).trim().toLowerCase()) problems.push('la clé de la preuve diffère de la clé de confiance fournie');
      if (options.trustedClientId && manifest.client_id !== String(options.trustedClientId).trim().toLowerCase()) {
        problems.push("l'identifiant client de la fiche de clé diffère de celui de la preuve");
      }
      if (trustedFingerprint) {
        try {
          if (hex(await sha256(parts.publicKey)) !== normalizeFingerprint(trustedFingerprint)) problems.push("l'empreinte SHA-256 de la clé de la preuve diffère de l'empreinte de confiance fournie");
        } catch (error) { problems.push(error.message); }
      }
      if (problems.length) record('signing_key_trust', 'fail', problems.join(' ; '));
      else record('signing_key_trust', 'pass', 'la clé de la preuve correspond à la confiance fournie (clé et/ou empreinte)');
    }

    await run('manifest_link_binding', () => {
      for (const field of ['client_id', 'submission_id', 'record_hash']) {
        if (manifest[field] !== link[field]) throw new Error(field + ' différent entre le manifeste signé et le lien');
      }
    }, 'client, soumission et record_hash cohérents');
    await run('link_hash', async () => expect(await computeLinkHash(link.client_id, link.client_sequence, link.record_hash, link.previous_link_hash), link.link_hash, 'link_hash'),
      'link_hash recalculé identique');
    await run('merkle_inclusion', async () => expect(await merkleRootFromProof(link.link_hash, anchor.merkle_proof), anchor.merkle_root, 'racine de Merkle'),
      "le lien appartient au lot (preuve d'inclusion valide)");
    await run('anchor_digest', async () => expect(await computeAnchorDigest(anchor.batch_number, anchor.previous_anchor_digest, anchor.merkle_root), anchor.anchor_digest, 'anchor_digest'),
      'anchor_digest recalculé identique');

    let ots = null, attestedDigests = [];
    try { ots = await parseOts(decodeBase64(anchor.ots_proof_b64)); } catch (error) {
      record('ots_commitment', 'fail', 'preuve .ots illisible : ' + error.message);
    }
    if (ots) {
      if (hex(ots.fileDigest) === anchor.anchor_digest) record('ots_commitment', 'pass', "la preuve .ots s'engage sur l'anchor_digest du lot");
      else record('ots_commitment', 'fail', "la preuve .ots s'engage sur un autre digest que l'anchor_digest");
      const bitcoin = ots.attestations.filter(a => a.type === 'bitcoin');
      if (!bitcoin.length) {
        const pending = ots.attestations.filter(a => a.type === 'pending').length;
        record('ots_bitcoin_attestation', 'skipped', 'aucune attestation Bitcoin dans la preuve (' + pending + ' en attente) : pas encore ancrée');
      } else {
        const heights = Array.from(new Set(bitcoin.map(a => a.height))).sort((a, b) => a - b);
        const declared = anchor.anchor_block_height;
        if (declared !== null && !heights.includes(declared)) {
          record('ots_bitcoin_attestation', 'fail', 'hauteur déclarée ' + declared + ' absente de la preuve (hauteurs : ' + heights.join(', ') + ')');
        } else {
          record('ots_bitcoin_attestation', 'pass', 'attestation(s) Bitcoin aux hauteurs ' + heights.join(', '));
          attestedDigests = bitcoin.filter(a => declared === null || a.height === declared).map(a => a.digest);
        }
      }
    } else {
      record('ots_bitcoin_attestation', 'skipped', 'preuve .ots illisible');
    }

    const attested = checks.some(c => c.id === 'ots_bitcoin_attestation' && c.status === 'pass');
    if (!attested) {
      record('bitcoin_block', 'skipped', 'pas d\'attestation Bitcoin à contrôler');
    } else if (!options.blockMerkleRoot && !options.fetchBlock) {
      record('bitcoin_block', 'skipped', 'merkle root du bloc non fourni ni demandé');
    } else {
      const height = anchor.anchor_block_height || ots.attestations.find(a => a.type === 'bitcoin').height;
      let blockRoot = options.blockMerkleRoot || null;
      if (!blockRoot) {
        const fetchImpl = options.fetchImpl || (typeof root.fetch === 'function' ? root.fetch.bind(root) : null);
        try {
          if (!fetchImpl) throw new Error('accès réseau indisponible');
          blockRoot = await fetchBlockMerkleRoot(fetchImpl, height);
        } catch (error) { record('bitcoin_block', 'skipped', 'explorateur injoignable ou réponse invalide : ' + error.message); }
      }
      if (blockRoot) {
        const wanted = String(blockRoot).trim().toLowerCase();
        if (attestedDigests.some(d => hex(d.slice().reverse()) === wanted)) record('bitcoin_block', 'pass', 'digest atteste (octets inversés) == merkle root du bloc ' + height);
        else record('bitcoin_block', 'fail', 'le digest atteste ne correspond pas au merkle root fourni pour le bloc ' + height);
      }
    }

    if (!options.dbomBytes) {
      record('record_hash_vs_dbom', 'skipped', "aucun DBoM clair fourni : le contenu métier n'est ni lu ni vérifié");
    } else {
      await run('record_hash_vs_dbom', async () => {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(options.dbomBytes);
        expect(hex(await sha256(enc.encode(jcs(JSON.parse(text))))), link.record_hash, 'record_hash');
      }, 'SHA-256 du DBoM canonique (JCS) == record_hash');
    }
    return summary(checks);
  }

  function summary(checks) {
    const status = {};
    for (const c of checks) status[c.id] = c.status;
    const failed = checks.filter(c => c.status === 'fail').map(c => c.id);
    const core = ['format', 'manifest_signature', 'manifest_link_binding', 'link_hash', 'merkle_inclusion', 'anchor_digest'];
    let level = 0;
    if (!failed.length && core.every(id => status[id] === 'pass')) {
      level = 1;
      if (status.ots_commitment === 'pass') {
        level = 2;
        if (status.ots_bitcoin_attestation === 'pass') { level = 3; if (status.bitcoin_block === 'pass') level = 4; }
      }
    }
    return { checks, failed, level: LEVELS[level], level_rank: level,
      signing_key_authenticated: status.signing_key_trust === 'pass', dbom_checked: status.record_hash_vs_dbom === 'pass' };
  }

  root.ChainDBoMV2b = { verify, checkKeyCard, formatFingerprint, jcs, parseOts, normalizeFingerprint, LEVELS, KEYCARD_FORMAT };
})(typeof globalThis !== 'undefined' ? globalThis : this);
