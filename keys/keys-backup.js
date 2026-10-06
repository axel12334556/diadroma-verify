/* ChainDBoM — sauvegarde et test de restauration des clés du client (lot 2 : module pur, sans interface, sans réseau).
 *
 * Produit et lit EXACTEMENT le format de `python -m chaindbom.v2b_key_backup` : UN fichier age protégé par phrase secrète,
 * qui contient une archive tar (USTAR) de backup-manifest.json, client.json, signing.pem et age-identity.txt. Le fichier
 * se restaure aussi avec l'outil standard seul : `age -d fichier | tar -xf -`.
 *
 * Rien n'est écrit, stocké ni envoyé : les fonctions reçoivent et rendent des octets ou des chaînes ; l'appelant décide quoi en
 * faire. ChainDBoM ne garde aucune copie et n'a pas de clé de récupération : qui perd le fichier ET la phrase perd les clés.
 * Le chiffrement vient de la bibliothèque age vendorée (keys/vendor, global AgeEncryption) ; la cryptographie de signature
 * vient de WebCrypto. Aucune cryptographie n'est réécrite ici.
 *
 * Une sauvegarde n'est « valide » que si elle a été rouverte : `backup()` la rouvre elle-même avec la même phrase et vérifie
 * les clés avant de rendre le fichier ; `restoreTest()` fait la même chose pour un fichier existant. */
(function (root) {
  'use strict';
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: true });
  const BACKUP_FORMAT = 'chaindbom-key-backup-v1';
  const MANIFEST = 'backup-manifest.json';
  const KEY_FILES = ['client.json', 'signing.pem', 'age-identity.txt'];
  const MAX_MEMBER_BYTES = 32 * 1024;
  const MAX_BACKUP_BYTES = 256 * 1024;
  const AGE_HEADER = enc.encode('age-encryption.org/v1\n-> scrypt ');
  // K1: the strength of the backup is exactly that of its passphrase (scrypt 2^18 costs an attacker about 2.5 s per guess
  // on one core). A chosen phrase must therefore be long and made of several words; its strength stays "not estimated".
  const MIN_PASSPHRASE_CHARS = 20, MIN_PASSPHRASE_WORDS = 4, MIN_DISTINCT_CHARS = 8;
  // K3: the only scrypt cost accepted when a backup is opened (age's default, and what this tool writes). A lower one
  // means the file was weakened; a higher one can lock a modest computer.
  const SCRYPT_LOG_N = 18;
  const DEFAULT_WORDS = 7;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

  class BackupError extends Error {}

  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const subtle = () => {
    if (!root.crypto || !root.crypto.subtle) throw new BackupError("ce navigateur n'offre pas WebCrypto");
    return root.crypto.subtle;
  };
  const age = () => {
    if (!root.AgeEncryption) throw new BackupError("la bibliothèque age n'est pas chargée");
    return root.AgeEncryption;
  };
  async function sha256Hex(bytes) { return hex(new Uint8Array(await subtle().digest('SHA-256', bytes))); }
  const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  function fromBase64(text) {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) throw new BackupError('clé de signature illisible');
    return Uint8Array.from(atob(text), c => c.charCodeAt(0));
  }
  function fromBase64Url(text) {
    return fromBase64(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
  }

  // json.dumps(obj, indent=2, sort_keys=True) + "\n" for objects of ASCII keys with string / integer values, one nested level.
  function pythonJson(object, depth) {
    const level = depth || 0;
    const pad = '  '.repeat(level + 1);
    const keys = Object.keys(object).sort();
    const body = keys.map(key => {
      const value = object[key];
      const text = typeof value === 'string' ? JSON.stringify(value)
        : Number.isSafeInteger(value) ? String(value) : pythonJson(value, level + 1).replace(/\n$/, '');
      return pad + JSON.stringify(key) + ': ' + text;
    }).join(',\n');
    return '{\n' + body + '\n' + '  '.repeat(level) + '}' + (level === 0 ? '\n' : '');
  }

  // ---- tar (USTAR): writer for our four files, strict reader ----
  function octal(value, width) { return value.toString(8).padStart(width - 1, '0') + '\u0000'; }
  function tarHeader(name, size) {
    const block = new Uint8Array(512);
    const put = (offset, text) => block.set(enc.encode(text), offset);
    put(0, name); put(100, '0000600\u0000'); put(108, '0000000\u0000'); put(116, '0000000\u0000');
    put(124, octal(size, 12)); put(136, octal(0, 12)); put(148, '        '); block[156] = 0x30;
    put(257, 'ustar\u0000'); put(263, '00'); put(329, '0000000\u0000'); put(337, '0000000\u0000');
    put(148, octal(block.reduce((sum, v) => sum + v, 0), 7).slice(0, 6) + '\u0000 ');
    return block;
  }
  function tarEncode(entries) {
    const parts = [];
    for (const [name, content] of entries) {
      parts.push(tarHeader(name, content.length), content, new Uint8Array((512 - (content.length % 512)) % 512));
    }
    parts.push(new Uint8Array(1024));
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(Math.ceil(total / 10240) * 10240);  // same 10 KiB record padding as tar and Python
    let offset = 0;
    for (const p of parts) { out.set(p, offset); offset += p.length; }
    return out;
  }
  function field(block, from, to) {
    const slice = block.subarray(from, to);
    const end = slice.indexOf(0);
    return dec.decode(end < 0 ? slice : slice.subarray(0, end));
  }
  function tarDecode(data) {
    const members = {};
    let offset = 0;
    const isZero = block => block.every(v => v === 0);
    for (;;) {
      if (offset + 512 > data.length) throw new BackupError('backup content is not a valid archive');
      const block = data.subarray(offset, offset + 512);
      if (isZero(block)) break;
      let name, sizeText, size;
      try { name = field(block, 0, 100); sizeText = field(block, 124, 136).trim(); } catch { throw new BackupError('unexpected content in backup'); }
      const stored = field(block, 148, 156).trim();
      const check = Uint8Array.from(block); check.fill(0x20, 148, 156);
      if (!/^[0-7]{1,8}$/.test(stored) || parseInt(stored, 8) !== check.reduce((sum, v) => sum + v, 0)) throw new BackupError('backup content is not a valid archive');
      if (!/^[0-7]+$/.test(sizeText)) throw new BackupError('backup content is not a valid archive');
      size = parseInt(sizeText, 8);
      const type = block[156];
      if ((type !== 0x30 && type !== 0) || ![MANIFEST, ...KEY_FILES].includes(name) || name in members || size > MAX_MEMBER_BYTES
          || field(block, 345, 500) !== '') throw new BackupError('unexpected content in backup');
      offset += 512;
      if (offset + size > data.length) throw new BackupError('backup content is not a valid archive');
      members[name] = data.slice(offset, offset + size);
      offset += Math.ceil(size / 512) * 512;
    }
    for (let i = offset; i < data.length; i++) if (data[i] !== 0) throw new BackupError('unexpected content in backup');  // nothing after the end marker
    return members;
  }

  function parseArchive(plain) {
    if (plain.length > MAX_BACKUP_BYTES) throw new BackupError('backup content too large');
    const members = tarDecode(plain);
    if (Object.keys(members).length !== 4) throw new BackupError('backup is incomplete');
    let manifest;
    try { manifest = JSON.parse(dec.decode(members[MANIFEST])); } catch { throw new BackupError('unreadable backup manifest'); }
    delete members[MANIFEST];
    return { manifest, members };
  }
  async function checkManifestHashes(manifest, members) {
    const files = manifest && manifest.files;
    const ok = manifest && typeof manifest === 'object' && manifest.format === BACKUP_FORMAT && manifest.format_version === 1
      && files && typeof files === 'object' && !Array.isArray(files) && Object.keys(files).sort().join() === KEY_FILES.slice().sort().join();
    if (!ok) throw new BackupError('backup manifest does not match its files');
    for (const name of KEY_FILES) if (files[name] !== await sha256Hex(members[name])) throw new BackupError('backup manifest does not match its files');
  }

  // ---- identity (age X25519 secret) -> recipient, via the vendored library ----
  const secretLine = text => {
    const lines = text.split('\n').map(l => l.trim()).filter(l => l.startsWith('AGE-SECRET-KEY-'));
    if (lines.length !== 1) throw new BackupError('age identity is missing');
    return lines[0];
  };

  /* Prouve que les clés fonctionnent encore. `files` : trois chaînes ; `card` : fiche publiée (objet) ou absente.
   * Retourne des faits PUBLICS uniquement. Lève BackupError au premier échec. */
  async function checkKeys(manifest, files, card) {
    const s = subtle();
    let publicInfo, signingDer;
    try {
      publicInfo = JSON.parse(files['client.json']);
      const body = files['signing.pem'].trim().split('\n').map(l => l.trim());
      if (body[0] !== '-----BEGIN PRIVATE KEY-----' || body[body.length - 1] !== '-----END PRIVATE KEY-----') throw new Error('pem');
      signingDer = fromBase64(body.slice(1, -1).join(''));
    } catch { throw new BackupError('restored key files are unreadable'); }
    if (!publicInfo || typeof publicInfo !== 'object' || typeof publicInfo.age_recipient !== 'string'
        || typeof publicInfo.client_id !== 'string' || !UUID.test(publicInfo.client_id)) throw new BackupError('restored key files are unreadable');
    if (signingDer.length !== 48 || !sameBytes(signingDer.subarray(0, 16), PKCS8_ED25519_PREFIX)) throw new BackupError('restored signing key is not Ed25519');
    let signing, publicBytes, verifier;
    try {
      signing = await s.importKey('pkcs8', signingDer, 'Ed25519', true, ['sign']);
      publicBytes = fromBase64Url((await s.exportKey('jwk', signing)).x);
      verifier = await s.importKey('raw', publicBytes, 'Ed25519', false, ['verify']);
    } catch { throw new BackupError('restored signing key is not Ed25519'); }
    if (hex(publicBytes) !== publicInfo.signing_public_key_hex) throw new BackupError('signing key does not match client.json');
    const fp = await sha256Hex(publicBytes);
    if (manifest.signing_key_fingerprint_sha256 !== fp || manifest.client_id !== publicInfo.client_id) throw new BackupError('backup manifest does not match the keys');
    const challenge = root.crypto.getRandomValues(new Uint8Array(32));  // the signing key still signs, and verifies under its public half
    if (!await s.verify('Ed25519', verifier, await s.sign('Ed25519', signing, challenge), challenge)) throw new BackupError('signing key does not sign correctly');

    const A = age();
    const identity = secretLine(files['age-identity.txt']);
    let derived;
    try { derived = await A.identityToRecipient(identity); } catch { throw new BackupError('age identity is missing'); }
    if (derived !== publicInfo.age_recipient) throw new BackupError('age identity does not match the recipient in client.json');
    const probe = root.crypto.getRandomValues(new Uint8Array(32));  // the identity still decrypts a fresh synthetic message
    try {
      const sealer = new A.Encrypter(); sealer.addRecipient(publicInfo.age_recipient);
      const opener = new A.Decrypter(); opener.addIdentity(identity);
      if (!sameBytes(await opener.decrypt(await sealer.encrypt(probe)), probe)) throw new Error('mismatch');
    } catch { throw new BackupError('age identity does not decrypt'); }

    if (card !== undefined && card !== null) {
      const check = root.ChainDBoMV2b && root.ChainDBoMV2b.checkKeyCard;
      if (!check) throw new BackupError('key card verifier not loaded');
      let facts;
      try { facts = await check(card); } catch { throw new BackupError('key card is not valid'); }
      if (facts.fingerprint_sha256 !== fp || facts.client_id !== publicInfo.client_id) throw new BackupError('restored keys do not match the published key card');
    }
    return { client_id: publicInfo.client_id, signing_key_fingerprint_sha256: fp, recipient: publicInfo.age_recipient,
      backup_created_at: String(manifest.created_at), key_card_matched: card !== undefined && card !== null };
  }

  // K2: the same phrase can be typed with a composed accent (é) or a decomposed one (e + ́) depending on the keyboard and the
  // system. It is always normalised to NFC before use; a backup made by an older version of the tool is still tried as typed.
  const nfc = text => text.normalize('NFC');
  function checkPassphrase(passphrase) {
    if (typeof passphrase !== 'string') throw new BackupError('phrase secrète absente');
    const phrase = nfc(passphrase);
    if (Array.from(phrase).length < MIN_PASSPHRASE_CHARS) {
      throw new BackupError(`la phrase secrète doit faire au moins ${MIN_PASSPHRASE_CHARS} caractères`);
    }
    if (/[\u0000-\u001f\u007f]/.test(phrase) || phrase !== phrase.trim()) {
      throw new BackupError('la phrase secrète ne doit contenir ni saut de ligne, ni caractère de contrôle, ni espace au début ou à la fin');
    }
    if (phrase.split(/[\s-]+/).filter(Boolean).length < MIN_PASSPHRASE_WORDS) {
      throw new BackupError(`la phrase secrète doit compter au moins ${MIN_PASSPHRASE_WORDS} mots (séparés par des espaces ou des tirets)`);
    }
    if (new Set(Array.from(phrase.toLowerCase())).size < MIN_DISTINCT_CHARS) {
      throw new BackupError('la phrase secrète est trop répétitive : utilisez des mots différents');
    }
    return phrase;
  }
  // The scrypt stanza of an age file: "age-encryption.org/v1\n-> scrypt <salt> <log2 N>\n".
  function scryptLogN(bytes) {
    const line = new TextDecoder('latin1').decode(bytes.subarray(0, 200)).split('\n')[1] || '';
    const match = /^-> scrypt [A-Za-z0-9+/]+ (\d{1,2})$/.exec(line);
    if (!match) throw new BackupError('not a passphrase-protected age file');
    return Number(match[1]);
  }

  async function openBackup(bytes, passphrase) {
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BACKUP_BYTES || !sameBytes(bytes.subarray(0, AGE_HEADER.length), AGE_HEADER)) {
      throw new BackupError('not a passphrase-protected age file');
    }
    if (typeof passphrase !== 'string' || passphrase === '') throw new BackupError('phrase secrète absente');
    if (scryptLogN(bytes) !== SCRYPT_LOG_N) throw new BackupError(`unsupported scrypt cost: only 2^${SCRYPT_LOG_N} is accepted (coût scrypt non pris en charge)`);
    let plain;
    for (const attempt of new Set([nfc(passphrase), passphrase])) { // normalised first, then as typed (backups of earlier versions)
      try { const d = new (age().Decrypter)(); d.addPassphrase(attempt); plain = await d.decrypt(bytes); break; } catch { /* next */ }
    }
    if (!plain) throw new BackupError('cannot open the backup: wrong passphrase, or the file is damaged (phrase secrète incorrecte, ou fichier abîmé)');
    const { manifest, members } = parseArchive(plain);
    await checkManifestHashes(manifest, members);
    const files = {};
    try { for (const name of KEY_FILES) files[name] = dec.decode(members[name]); } catch { throw new BackupError('restored key files are unreadable'); }
    return { manifest, files };
  }

  /* Crée la sauvegarde. `files` : { 'client.json', 'signing.pem', 'age-identity.txt' } (chaînes, comme rendues par
   * generateClientKeys). Vérifie les clés avant de chiffrer, puis rouvre le fichier produit avec la même phrase et revérifie.
   * Retourne { bytes, facts } ; bytes n'est rendu que si la réouverture a réussi. */
  async function backup(files, passphrase, options) {
    const o = options || {};
    passphrase = checkPassphrase(passphrase); // normalised to NFC
    for (const name of KEY_FILES) {
      if (typeof files[name] !== 'string' || enc.encode(files[name]).length > MAX_MEMBER_BYTES) throw new BackupError('unexpectedly large or missing key file');
    }
    const raw = Object.fromEntries(KEY_FILES.map(name => [name, enc.encode(files[name])]));
    const publicInfo = (() => { try { return JSON.parse(files['client.json']); } catch { throw new BackupError('restored key files are unreadable'); } })();
    const signingPem = files['signing.pem'];
    let publicBytes;
    try {
      const der = fromBase64(signingPem.trim().split('\n').slice(1, -1).join(''));
      publicBytes = fromBase64Url((await subtle().exportKey('jwk', await subtle().importKey('pkcs8', der, 'Ed25519', true, ['sign']))).x);
    } catch { throw new BackupError('restored key files are unreadable'); }
    const created = (o.now || new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const manifest = {
      format: BACKUP_FORMAT, format_version: 1, created_at: created,
      client_id: publicInfo.client_id, signing_key_id: publicInfo.signing_key_id, recipient_key_id: publicInfo.recipient_key_id,
      signing_key_fingerprint_sha256: await sha256Hex(publicBytes),
      files: Object.fromEntries(await Promise.all(KEY_FILES.map(async name => [name, await sha256Hex(raw[name])]))),
    };
    await checkKeys(manifest, files);  // never back up keys that do not work
    const archive = tarEncode([[MANIFEST, enc.encode(pythonJson(manifest))], ...KEY_FILES.map(name => [name, raw[name]])]);
    const encrypter = new (age().Encrypter)();
    encrypter.setPassphrase(passphrase);
    const bytes = await encrypter.encrypt(archive);
    if (bytes.length > MAX_BACKUP_BYTES) throw new BackupError('backup content too large');
    const reopened = await openBackup(bytes, passphrase);  // the backup is only returned if it really reopens
    return { bytes, facts: await checkKeys(reopened.manifest, reopened.files) };
  }

  /* Rouvre une sauvegarde : déchiffre, vérifie les empreintes, prouve que les clés signent et déchiffrent encore, et les
   * compare à la fiche publiée si elle est fournie. Retourne des faits publics ; ne rend aucun secret. */
  async function restoreTest(bytes, passphrase, options) {
    const { manifest, files } = await openBackup(bytes, passphrase);
    return checkKeys(manifest, files, (options || {}).card);
  }

  /* Comme restoreTest, mais rend aussi les fichiers (chaînes) : l'appelant les propose en téléchargement. */
  async function restore(bytes, passphrase, options) {
    const { manifest, files } = await openBackup(bytes, passphrase);
    const facts = await checkKeys(manifest, files, (options || {}).card);
    return { files, facts };
  }

  /* Phrase secrète générée : `words` mots tirés au hasard (sans biais) dans la liste, séparés par des tirets. */
  function generatePassphrase(options) {
    const o = options || {};
    const list = o.wordlist || root.ChainDBoMWordlist;
    const count = o.words === undefined ? DEFAULT_WORDS : o.words;
    if (!Array.isArray(list) && !(list && typeof list.length === 'number')) throw new BackupError('liste de mots absente');
    if (!Number.isInteger(count) || count < 6 || count > 20) throw new BackupError('nombre de mots invalide (6 à 20)');
    if (list.length < 2048 || list.length > 0x10000) throw new BackupError('liste de mots invalide');
    const limit = 0x100000000 - (0x100000000 % list.length);
    const picked = [];
    const buffer = new Uint32Array(1);
    while (picked.length < count) {
      root.crypto.getRandomValues(buffer);
      if (buffer[0] < limit) picked.push(list[buffer[0] % list.length]);
    }
    return { passphrase: picked.join('-'), entropyBits: Math.floor(count * Math.log2(list.length)) };
  }

  root.ChainDBoMKeysBackup = { backup, restoreTest, restore, checkKeys, generatePassphrase, BackupError, BACKUP_FORMAT, MIN_PASSPHRASE_CHARS, MIN_PASSPHRASE_WORDS,
    _internals: { tarEncode, tarDecode, parseArchive, pythonJson, checkPassphrase, scryptLogN } };
})(typeof globalThis !== 'undefined' ? globalThis : this);
