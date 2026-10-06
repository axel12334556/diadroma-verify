/* ChainDBoM — création des clés du client (lot 1 : module pur, sans interface, sans réseau, sans dépendance).
 *
 * Produit, en mémoire, EXACTEMENT les trois fichiers que crée `dbom_v2_seal keygen` et la fiche de clé de
 * `key_card create` (format chaindbom-key-card-v1) : client.json, signing.pem (Ed25519, PKCS#8), age-identity.txt
 * (X25519, format age), key-card.json. Rien n'est écrit ni envoyé : l'appelant décide quoi faire des octets.
 *
 * Aucune cryptographie n'est réécrite ici : les clés viennent de WebCrypto (Ed25519, X25519) ; seul l'encodage
 * Bech32 de l'identité age est implémenté, et il est vérifié contre l'outil age lui-même (tests/keys-core.test.cjs).
 * Le chiffrement par phrase secrète (sauvegarde) n'est pas dans ce lot. */
(function (root) {
  'use strict';
  const enc = new TextEncoder();
  const KEY_ID = /^[A-Za-z0-9._-]{1,128}$/;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const CARD_FORMAT = 'chaindbom-key-card-v1';
  const CARD_DOMAIN = enc.encode('ChainDBoM:v2:key-card\u0000');
  const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

  class KeysError extends Error {}

  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const subtle = () => {
    if (!root.crypto || !root.crypto.subtle) throw new KeysError("ce navigateur n'offre pas WebCrypto");
    return root.crypto.subtle;
  };
  function fromBase64Url(text) {
    const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  }
  const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

  // ---- Bech32 (BIP-173), as used by age for recipients ("age1…") and identities ("AGE-SECRET-KEY-1…") ----
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }
  function bech32Encode(hrp, data) {
    const words = [];
    let acc = 0, bits = 0;
    for (const byte of data) {
      acc = (acc << 8) | byte; bits += 8;
      while (bits >= 5) { bits -= 5; words.push((acc >>> bits) & 31); }
      acc &= (1 << bits) - 1;
    }
    if (bits > 0) words.push((acc << (5 - bits)) & 31);
    const expanded = [...Array.from(hrp, c => c.charCodeAt(0) >>> 5), 0, ...Array.from(hrp, c => c.charCodeAt(0) & 31)];
    const mod = polymod([...expanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
    const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
    return hrp + '1' + [...words, ...checksum].map(w => CHARSET[w]).join('');
  }

  // ---- RFC 8785 for the key card: only strings and small integers occur, anything else is refused ----
  function jcsCard(value) {
    if (typeof value === 'string') return JSON.stringify(value);
    if (Number.isSafeInteger(value)) return String(value);
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + jcsCard(value[k])).join(',') + '}';
    }
    throw new KeysError('valeur non prise en charge dans la fiche de clé');
  }
  // Same layout as Python's json.dumps(indent=2, sort_keys=True) + "\n" for flat objects of ASCII keys with string/int values.
  function pythonJson(object) {
    const keys = Object.keys(object).sort();
    return '{\n' + keys.map(k => '  ' + JSON.stringify(k) + ': ' + (typeof object[k] === 'string' ? JSON.stringify(object[k]) : String(object[k]))).join(',\n') + '\n}\n';
  }

  function uuid4(randomBytes) {
    const b = Uint8Array.from(randomBytes);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = hex(b);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  function utcSeconds(date) {
    if (Object.prototype.toString.call(date) !== '[object Date]' || Number.isNaN(date.getTime())) throw new KeysError('date invalide');
    return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  function pem(der) {
    const lines = toBase64(der).match(/.{1,64}/g).join('\n');
    return '-----BEGIN PRIVATE KEY-----\n' + lines + '\n-----END PRIVATE KEY-----\n';
  }

  /* Crée les clés d'un client. Options :
   *   signingKeyId, recipientKeyId : identifiants (a-z A-Z 0-9 . _ -, 128 max), obligatoires (aucune valeur « demo »)
   *   clientId : UUID minuscule canonique ; tiré au hasard si absent
   *   now : Date de création (défaut : maintenant)
   *   seeds : { signing: 32 octets, age: 32 octets, client: 16 octets } — POUR LES VECTEURS DE TEST UNIQUEMENT
   * Retourne { files, card, cardText, publicFacts } ; files contient des chaînes (les secrets y figurent). */
  async function generateClientKeys(options) {
    const o = options || {};
    for (const field of ['signingKeyId', 'recipientKeyId']) {
      if (typeof o[field] !== 'string' || !KEY_ID.test(o[field])) throw new KeysError(`${field} invalide`);
    }
    const now = o.now || new Date();
    const seeds = o.seeds || {};
    const random = n => root.crypto.getRandomValues(new Uint8Array(n));
    const clientId = o.clientId !== undefined ? o.clientId : uuid4(seeds.client || random(16));
    if (typeof clientId !== 'string' || !UUID.test(clientId)) throw new KeysError('clientId doit être un UUID minuscule canonique');
    const s = subtle();

    const edSeed = seeds.signing ? Uint8Array.from(seeds.signing) : random(32);
    if (edSeed.length !== 32) throw new KeysError('graine de signature : 32 octets attendus');
    const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
    pkcs8.set(PKCS8_ED25519_PREFIX); pkcs8.set(edSeed, PKCS8_ED25519_PREFIX.length);
    let signingKey;
    try { signingKey = await s.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']); }
    catch { throw new KeysError("ce navigateur ne gère pas la signature Ed25519 : utilisez un navigateur récent"); }
    const signingJwk = await s.exportKey('jwk', signingKey);
    const publicKey = fromBase64Url(signingJwk.x);
    const fingerprint = hex(new Uint8Array(await s.digest('SHA-256', publicKey)));

    let agePrivate, agePublic;
    try {
      let key;
      if (seeds.age) {
        const secret = Uint8Array.from(seeds.age);
        if (secret.length !== 32) throw new KeysError("graine age : 32 octets attendus");
        key = await importX25519(s, secret);  // fixed scalar, tests only
      } else {
        key = await s.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      }
      const jwk = await s.exportKey('jwk', key.privateKey);
      agePrivate = fromBase64Url(jwk.d); agePublic = fromBase64Url(jwk.x);
    } catch (error) {
      if (error instanceof KeysError) throw error;
      throw new KeysError("ce navigateur ne gère pas X25519 : utilisez un navigateur récent");
    }
    const recipient = bech32Encode('age', agePublic);
    const secretLine = bech32Encode('age-secret-key-', agePrivate).toUpperCase();

    const client = { client_id: clientId, signing_key_id: o.signingKeyId, recipient_key_id: o.recipientKeyId,
      signing_public_key_hex: hex(publicKey), age_recipient: recipient };
    const card = { format: CARD_FORMAT, format_version: 1, client_id: clientId, signing_key_id: o.signingKeyId,
      signing_public_key_hex: hex(publicKey), signing_key_fingerprint_sha256: fingerprint,
      recipient_key_id: o.recipientKeyId, age_recipient: recipient, created_at: utcSeconds(now) };
    const message = new Uint8Array([...CARD_DOMAIN, ...enc.encode(jcsCard(card))]);
    card.signature_hex = hex(new Uint8Array(await s.sign('Ed25519', signingKey, message)));

    return {
      files: {
        'client.json': pythonJson(client),
        'signing.pem': pem(pkcs8),
        'age-identity.txt': `# created: ${utcSeconds(now)}\n# public key: ${recipient}\n${secretLine}\n`,
      },
      card,
      cardText: pythonJson(card),
      publicFacts: { client_id: clientId, signing_key_fingerprint_sha256: fingerprint, age_recipient: recipient },
    };
  }

  // X25519 private key from a fixed 32-byte scalar (tests only): PKCS#8 (RFC 8410 prefix); WebCrypto derives the public key.
  async function importX25519(s, secret) {
    const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
    const der = new Uint8Array(48); der.set(prefix); der.set(secret, 16);
    const privateKey = await s.importKey('pkcs8', der, { name: 'X25519' }, true, ['deriveBits']);
    const jwk = await s.exportKey('jwk', privateKey);
    return { privateKey, jwk };
  }

  root.ChainDBoMKeys = { generateClientKeys, bech32Encode, KeysError, CARD_FORMAT };
})(typeof globalThis !== 'undefined' ? globalThis : this);
