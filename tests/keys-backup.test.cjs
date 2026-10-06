// Key backup and restore test (lot 2): the format is the one of `python -m chaindbom.v2b_key_backup`, checked against
// independent tools (the age program, tar, a backup made by the Python tool). Synthetic data only, no network.
// The age checks need the age CLI, tar and python3: with REQUIRE_AGE=1 (CI) their absence is a failure, never a silent skip.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { webcrypto } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { OPTIONS } = require('./tools/gen_keys_vectors.js');

const PASSPHRASE = 'synthetic test passphrase 7F3A-91C2';  // public test value, protects nothing
const hasTools = ['age', 'age-keygen', 'tar', 'python3'].every(t => spawnSync(t, ['--version']).status === 0 || (t === 'tar' && spawnSync('tar', ['--help']).status === 0));
if (!hasTools && process.env.REQUIRE_AGE === '1') { console.error('age, tar and python3 required (REQUIRE_AGE=1)'); process.exit(1); }

function makeContext(crypto) {
  const ctx = vm.createContext({ crypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt, Promise, Date, atob, btoa,
    setTimeout, clearTimeout, queueMicrotask, ReadableStream, WritableStream, TransformStream, Blob, Response, structuredClone });
  for (const file of ['keys/keys-core.js', 'keys/wordlist.js', 'v2b.js', 'keys/vendor/age-encryption.bundle.js', 'keys/keys-backup.js']) {
    vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  }
  return ctx;
}
const ctx = makeContext(webcrypto);
const K = ctx.ChainDBoMKeys, B = ctx.ChainDBoMKeysBackup, A = ctx.AgeEncryption;
const plain = v => JSON.parse(JSON.stringify(v));
const vector = name => fs.readFileSync('tests/vectors/keys/' + name);
const rejects = (promise, message) => assert.rejects(promise, error => error instanceof B.BackupError && (!message || message.test(error.message)), message && String(message));
const sha = data => createHash('sha256').update(data).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-backup-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));

// A seal around a crafted archive. 2^18 is the only cost the tool accepts when it opens a backup (K3), so the many
// strictness cases use it too; a different one is passed explicitly by the K3 cases.
async function sealRaw(archive, workFactor, passphrase) {
  const e = new A.Encrypter(); e.setPassphrase(passphrase === undefined ? PASSPHRASE : passphrase); e.setScryptWorkFactor(workFactor || 18);
  return e.encrypt(archive);
}
const enc = new TextEncoder();

(async () => {
  const keys = await K.generateClientKeys(OPTIONS);          // the lot-1 vectors, deterministic
  const other = await K.generateClientKeys({ signingKeyId: 'sign-other', recipientKeyId: 'age-other' });
  const card = plain(keys.card);

  // 1. Generated passphrase: words from the list, enough entropy, not repeated, rejection sampling really removes the bias.
  const list = ctx.ChainDBoMWordlist;
  const wordlistSource = fs.readFileSync('keys/wordlist.js', 'utf8');
  assert.equal(sha(list.join('\n') + '\n'), /SHA-256[^:]*: ([0-9a-f]{64})/.exec(wordlistSource)[1]);   // the file is the one its header describes
  assert.equal(list.length, 7772); assert.equal(new Set(list).size, list.length); assert.ok(list.every(w => /^[a-z]{3,10}$/.test(w)));
  assert.ok(Object.isFrozen(list));
  const g1 = B.generatePassphrase(), g2 = B.generatePassphrase();
  assert.notEqual(g1.passphrase, g2.passphrase);
  assert.equal(g1.passphrase.split('-').length, 7); assert.ok(g1.passphrase.split('-').every(w => list.includes(w)));
  assert.ok(g1.entropyBits >= 90, `entropy ${g1.entropyBits}`);
  assert.equal(B.generatePassphrase({ words: 10 }).passphrase.split('-').length, 10);
  for (const words of [0, 5, 21, 7.5, '7']) assert.throws(() => B.generatePassphrase({ words }), B.BackupError);
  assert.throws(() => B.generatePassphrase({ wordlist: ['a', 'b'] }), B.BackupError);
  {  // a draw >= the largest multiple of the list size must be thrown away, not folded in
    const limit = 0x100000000 - (0x100000000 % list.length);
    const draws = [];   // filled after loading: some libraries draw random bytes while loading
    const stub = makeContext({ subtle: webcrypto.subtle, getRandomValues: a => { a[0] = draws.length ? draws.shift() : webcrypto.getRandomValues(new Uint32Array(1))[0]; return a; } });
    draws.push(limit, 0xFFFFFFFF, 0, 1, 2, 3, 4, 5, 6);
    assert.equal(stub.ChainDBoMKeysBackup.generatePassphrase().passphrase, list.slice(0, 7).join('-'));
  }

  // 2. Round trip: backup, restore test (with the published card), restore returns the very same files.
  const made = await B.backup(keys.files, PASSPHRASE, { now: new Date('2026-10-06T08:00:00Z') });
  assert.ok(made.bytes instanceof Uint8Array && made.bytes.length < 256 * 1024);
  assert.ok(Buffer.from(made.bytes).subarray(0, 32).toString().startsWith('age-encryption.org/v1\n-> scrypt '));
  assert.equal(made.facts.client_id, keys.publicFacts.client_id);
  assert.equal(made.facts.signing_key_fingerprint_sha256, keys.publicFacts.signing_key_fingerprint_sha256);
  assert.equal(made.facts.recipient, keys.publicFacts.age_recipient);
  assert.equal(made.facts.backup_created_at, '2026-10-06T08:00:00Z'); assert.equal(made.facts.key_card_matched, false);
  const noCard = await B.restoreTest(made.bytes, PASSPHRASE);
  assert.equal(noCard.key_card_matched, false);
  const withCard = await B.restoreTest(made.bytes, PASSPHRASE, { card });
  assert.equal(withCard.key_card_matched, true);
  const restored = await B.restore(made.bytes, PASSPHRASE, { card });
  assert.deepEqual(plain(restored.files), plain(keys.files));
  assert.ok(!JSON.stringify(withCard).includes('AGE-SECRET-KEY') && !JSON.stringify(withCard).includes('PRIVATE KEY'), 'facts are public only');
  // Two backups of the same keys differ (fresh random salt) but both restore.
  const again = await B.backup(keys.files, PASSPHRASE);
  assert.notDeepEqual(Buffer.from(again.bytes), Buffer.from(made.bytes));

  // 3. The wrong card, a forged card, the wrong passphrase, damage.
  await rejects(B.restoreTest(made.bytes, PASSPHRASE, { card: plain(other.card) }), /do not match the published key card/);
  const forged = plain(keys.card); forged.age_recipient = other.card.age_recipient;
  await rejects(B.restoreTest(made.bytes, PASSPHRASE, { card: forged }), /key card is not valid/);
  await rejects(B.restoreTest(made.bytes, PASSPHRASE + 'x'), /wrong passphrase/);
  await rejects(B.restoreTest(made.bytes, ''), /absente/);
  const damaged = Uint8Array.from(made.bytes); damaged[damaged.length - 20] ^= 1;
  await rejects(B.restoreTest(damaged, PASSPHRASE), /wrong passphrase, or the file is damaged/);
  await rejects(B.restoreTest(made.bytes.slice(0, 400), PASSPHRASE), /wrong passphrase, or the file is damaged/);
  await rejects(B.restoreTest(enc.encode('not an age file at all, just text'), PASSPHRASE), /not a passphrase-protected age file/);
  await rejects(B.restoreTest(new Uint8Array(0), PASSPHRASE), /not a passphrase-protected age file/);
  await rejects(B.restoreTest(Buffer.alloc(256 * 1024 + 1, 1), PASSPHRASE), /not a passphrase-protected age file/);
  await rejects(B.restoreTest('text', PASSPHRASE), /not a passphrase-protected age file/);
  const toRecipient = new A.Encrypter(); toRecipient.addRecipient(keys.card.age_recipient);   // an age file, but not passphrase-protected
  await rejects(B.restoreTest(await toRecipient.encrypt(enc.encode('x')), PASSPHRASE), /not a passphrase-protected age file/);

  {  // the backup is only handed over if it really reopens: an encrypter that corrupts its output must yield no bytes at all
    const broken = makeContext(webcrypto);
    const Real = broken.AgeEncryption.Encrypter;
    broken.AgeEncryption = { ...broken.AgeEncryption, Encrypter: class extends Real { async encrypt(data) { const out = await super.encrypt(data); if (data.length > 1000) out[out.length - 3] ^= 1; return out; }   /* only the archive, not the 32-byte probe */ } };
    await assert.rejects(broken.ChainDBoMKeysBackup.backup(keys.files, PASSPHRASE), error => /wrong passphrase, or the file is damaged/.test(error.message));
  }

  // 4. Passphrase rules, and no backup is returned when it is refused or when the keys are not usable.
  for (const bad of ['short', '', 'x'.repeat(11), ' leading space is refused here', 'trailing space is refused here ', 'line\nbreak is refused here', 'tab\there is refused', undefined, 12345678901234,
    // K1: the phrases of the security review (12 characters, or a single repeated one) and a long one that is not several words
    'aaaaaaaaaaaa', 'motdepasse12', '123456789012', 'a'.repeat(40), 'abcabc abcabc abcabc abcabc', 'unseulmotbeaucouptroplongmaisunseulmot', 'one two three']) {
    await rejects(B.backup(keys.files, bad), /phrase secrète/);
  }
  await B.backup(keys.files, 'quatre mots font vingt');   // 4 words, 22 characters: accepted
  await B.backup(keys.files, 'phrase accentuée très sûre 😀');
  // K2: composed or decomposed accents are the same phrase. The backup is written with the NFC form and opens with either.
  const composed = 'café éléphant àçè famille', decomposed = composed.normalize('NFD');
  assert.notEqual(composed, decomposed);
  const accented = await B.backup(keys.files, decomposed);                   // typed decomposed, stored as NFC
  await B.restoreTest(accented.bytes, composed); await B.restoreTest(accented.bytes, decomposed);
  const viaAge = new A.Decrypter(); viaAge.addPassphrase(composed);          // the standard tool, given the NFC form, opens it too
  assert.ok((await viaAge.decrypt(accented.bytes)).length > 0);
  const unsealed = new A.Decrypter(); unsealed.addPassphrase(PASSPHRASE);
  const archiveBytes = await unsealed.decrypt(made.bytes);
  const legacy = await sealRaw(archiveBytes, 18, decomposed);                // an earlier version sealed with the phrase as typed
  await B.restoreTest(legacy, decomposed);
  await rejects(B.restoreTest(accented.bytes, composed + ' '), /wrong passphrase/);
  // K3: only the scrypt cost 2^18 is accepted when a backup is opened: a weakened file is not "valid", a costly one is not tried.
  for (const cost of [1, 10, 17, 19, 20]) {
    await rejects(B.restoreTest(await sealRaw(archiveBytes, cost), PASSPHRASE), /unsupported scrypt cost/);
  }
  await B.restoreTest(await sealRaw(archiveBytes, 18), PASSPHRASE);          // control: 2^18 is accepted
  assert.equal(B._internals.scryptLogN(made.bytes), 18);
  for (const broken of ['age-encryption.org/v1\n-> scrypt \n', 'age-encryption.org/v1\n-> scrypt c2FsdA 18x\n', 'age-encryption.org/v1\n-> X25519 abc\n']) {
    assert.throws(() => B._internals.scryptLogN(enc.encode(broken)), /not a passphrase-protected age file/);
  }
  await rejects(B.backup({ ...keys.files, 'signing.pem': other.files['signing.pem'] }, PASSPHRASE), /does not match client.json/);
  await rejects(B.backup({ ...keys.files, 'age-identity.txt': other.files['age-identity.txt'] }, PASSPHRASE), /does not match the recipient/);
  await rejects(B.backup({ ...keys.files, 'age-identity.txt': '# no secret here\n' }, PASSPHRASE), /age identity is missing/);
  await rejects(B.backup({ ...keys.files, 'signing.pem': 'garbage' }, PASSPHRASE), /unreadable/);
  await rejects(B.backup({ 'client.json': keys.files['client.json'] }, PASSPHRASE), /missing/);
  await rejects(B.backup({ ...keys.files, 'client.json': 'x'.repeat(40000) }, PASSPHRASE), /large/);

  // 5. The archive reader is strict. Each crafted archive is sealed with the right passphrase and must still be refused.
  const { tarEncode, tarDecode, parseArchive, pythonJson } = B._internals;
  const manifestFor = async (files, extra) => ({ format: B.BACKUP_FORMAT, format_version: 1, created_at: '2026-10-06T08:00:00Z',
    client_id: JSON.parse(files['client.json']).client_id, signing_key_id: 'sign-synthetic-1', recipient_key_id: 'age-synthetic-1',
    signing_key_fingerprint_sha256: keys.publicFacts.signing_key_fingerprint_sha256,
    files: Object.fromEntries(Object.keys(files).map(n => [n, sha(enc.encode(files[n]))])), ...extra });
  const entries = async (files, manifestExtra) => [['backup-manifest.json', enc.encode(pythonJson(await manifestFor(files, manifestExtra)))],
    ...['client.json', 'signing.pem', 'age-identity.txt'].map(n => [n, enc.encode(files[n])])];
  const good = tarEncode(await entries(keys.files));
  assert.equal((await B.restoreTest(await sealRaw(good), PASSPHRASE, { card })).key_card_matched, true);   // control: the crafting itself is fine
  const refuse = async (archive, message) => rejects(B.restoreTest(await sealRaw(archive), PASSPHRASE), message);
  const base = await entries(keys.files);
  await refuse(tarEncode([...base, ['extra.txt', enc.encode('x')]]), /unexpected content/);
  await refuse(tarEncode([...base, ['client.json', enc.encode(keys.files['client.json'])]]), /unexpected content/);          // duplicate member
  await refuse(tarEncode([...base, ['../escape', enc.encode('x')]]), /unexpected content/);
  await refuse(tarEncode(base.slice(0, 3)), /incomplete/);
  await refuse(tarEncode([...base.slice(0, 3), ['age-identity.txt', enc.encode('x'.repeat(33 * 1024))]]), /unexpected content/);  // member over 32 KiB
  await refuse(tarEncode(base.map(([n, c]) => (n === 'client.json' ? [n, enc.encode(keys.files['client.json'].replace('a', 'b'))] : [n, c]))), /manifest does not match its files/);
  for (const bad of [{ format: 'other' }, { format_version: 2 }, { files: { 'client.json': sha(enc.encode('x')) } }]) {
    await refuse(tarEncode(await entries(keys.files, bad)), /manifest does not match its files/);
  }
  await refuse(tarEncode(base.map(([n, c]) => (n === 'backup-manifest.json' ? [n, enc.encode('{ not json')] : [n, c]))), /unreadable backup manifest/);
  await refuse(tarEncode(await entries(keys.files, { client_id: other.publicFacts.client_id })), /manifest does not match the keys/);
  await refuse(tarEncode(await entries(keys.files, { signing_key_fingerprint_sha256: other.publicFacts.signing_key_fingerprint_sha256 })), /manifest does not match the keys/);
  {  // header-level tampering: link type, bad checksum, garbage after the end marker, truncation, prefix path
    const withBlock = (mutate) => { const copy = Uint8Array.from(good); mutate(copy); return copy; };
    const resum = (copy, offset) => { copy.fill(0x20, offset + 148, offset + 156); const sum = copy.subarray(offset, offset + 512).reduce((s, v) => s + v, 0); copy.set(enc.encode(sum.toString(8).padStart(6, '0') + '\u0000 '), offset + 148); };
    await refuse(withBlock(c => { c[156] = 0x32; resum(c, 0); }), /unexpected content/);                    // symlink
    await refuse(withBlock(c => { c[156] = 0x35; resum(c, 0); }), /unexpected content/);                    // directory
    await refuse(withBlock(c => { c[0] ^= 1; }), /not a valid archive/);                                       // checksum no longer matches
    await refuse(withBlock(c => { c.set(enc.encode('dir'), 345); resum(c, 0); }), /unexpected content/);     // ustar prefix
    await refuse(withBlock(c => { c[good.length - 3] = 1; }), /unexpected content/);                          // data after the end marker
    await refuse(good.slice(0, 700), /not a valid archive/);
    await refuse(good.slice(0, 1100), /not a valid archive/);
    await refuse(new Uint8Array(0), /not a valid archive/);
    await refuse(enc.encode('x'.repeat(100)), /not a valid archive/);
    await refuse(new Uint8Array(300 * 1024), /not a passphrase-protected age file/);   // the sealed file itself exceeds the 256 KiB cap
  }
  // The reader accepts what `tar` itself (ustar format) writes, not only what our writer writes.
  if (hasTools) {
    const dir = path.join(tmp, 'tarsrc'); fs.mkdirSync(dir);
    for (const [name, content] of await entries(keys.files)) fs.writeFileSync(path.join(dir, name), content);
    const tarFile = path.join(tmp, 'by-tar.tar');
    const made2 = spawnSync('tar', ['--format=ustar', '--owner=0', '--group=0', '--numeric-owner', '--mtime=@0', '-cf', tarFile, '-C', dir, 'backup-manifest.json', 'client.json', 'signing.pem', 'age-identity.txt']);
    assert.equal(made2.status, 0, String(made2.stderr));
    const parsed = parseArchive(fs.readFileSync(tarFile));
    assert.deepEqual(Object.keys(parsed.members).sort(), ['age-identity.txt', 'client.json', 'signing.pem']);
    assert.equal((await B.restoreTest(await sealRaw(fs.readFileSync(tarFile)), PASSPHRASE, { card })).client_id, keys.publicFacts.client_id);
  }

  // 6. Interoperability with the other tools.
  if (hasTools) {
    const tty = (command) => spawnSync('python3', ['tests/tools/age_tty.py', PASSPHRASE, command], { encoding: 'utf8', timeout: 120000 });
    // 6a. A backup made here opens with the standard tools alone: `age -d file | tar -xf -`, as the documentation promises.
    const backupFile = path.join(tmp, 'made-here.age'); fs.writeFileSync(backupFile, made.bytes);
    const outDir = path.join(tmp, 'extracted'); fs.mkdirSync(outDir);
    const r = tty(`age -d '${backupFile}' | tar -xf - -C '${outDir}'`);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(fs.readdirSync(outDir).sort(), ['age-identity.txt', 'backup-manifest.json', 'client.json', 'signing.pem']);
    for (const name of ['client.json', 'signing.pem', 'age-identity.txt']) assert.equal(fs.readFileSync(path.join(outDir, name), 'utf8'), keys.files[name]);
    const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'backup-manifest.json'), 'utf8'));
    assert.equal(manifest.format, 'chaindbom-key-backup-v1'); assert.equal(manifest.created_at, '2026-10-06T08:00:00Z');
    assert.equal(fs.readFileSync(path.join(outDir, 'backup-manifest.json'), 'utf8'), pythonJson(manifest));   // same layout as Python's json.dumps(indent=2, sort_keys=True)
    // 6b. A backup made by the age program itself (passphrase typed at its prompt) from a ustar archive opens here.
    const cliFile = path.join(tmp, 'made-by-cli.age');
    const mk = tty(`age -p -o '${cliFile}' < '${path.join(tmp, 'by-tar.tar')}'`);
    assert.equal(mk.status, 0, mk.stderr);
    assert.equal((await B.restoreTest(new Uint8Array(fs.readFileSync(cliFile)), PASSPHRASE, { card })).key_card_matched, true);
    await rejects(B.restoreTest(new Uint8Array(fs.readFileSync(cliFile)), 'another passphrase of mine'), /wrong passphrase/);
  } else console.log('age/tar/python3 absents : interopérabilité ignorée (REQUIRE_AGE=1 la rend obligatoire)');
  // 6c. A backup made by the ChainDBoM Python tool (committed, synthetic keys, public test passphrase) opens here and is complete.
  const python = new Uint8Array(vector('backup-python.age'));
  const fromPython = await B.restore(python, PASSPHRASE, { card });
  assert.equal(fromPython.facts.key_card_matched, true);
  for (const name of ['client.json', 'signing.pem', 'age-identity.txt']) assert.equal(fromPython.files[name], vector(name).toString('utf8'));
  await rejects(B.restoreTest(python, 'not the passphrase at all'), /wrong passphrase/);
  // The vectors a ChainDBoM test can restore in the other direction (made here, same keys, same public passphrase).
  const fixture = vector('backup-js.age');
  assert.equal((await B.restoreTest(new Uint8Array(fixture), PASSPHRASE, { card })).client_id, keys.publicFacts.client_id);

  // 7. The module ships no network, storage, dynamic loading or logging of secrets.
  {  // the word list is data only: nothing but the array of words (its words may legitimately include "document" or "console")
    const code = fs.readFileSync('keys/wordlist.js', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.match(code, /^\s*\(function \(root\) \{\s*'use strict';\s*root\.ChainDBoMWordlist = Object\.freeze\(\[(\s*"[a-z]+",?)+\s*\]\.slice\(\)\);\s*\}\)\(typeof globalThis !== 'undefined' \? globalThis : this\);\s*$/);
  }
  for (const file of ['keys/keys-backup.js']) {
    const code = fs.readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon|importScripts|EventSource|localStorage|sessionStorage|indexedDB|document|console|eval)\b/.test(code), file + ': forbidden API');
    assert.ok(!/\bimport\s*\(|\brequire\s*\(|\bnew Function\b|\bFunction\s*\(/.test(code), file + ': dynamic loading');
  }
  console.log('sauvegarde des clés : format, restauration, rejets stricts, phrase générée et interopérabilité (age, tar, outil Python) vérifiés');
})().catch(e => { console.error(e); process.exit(1); });
