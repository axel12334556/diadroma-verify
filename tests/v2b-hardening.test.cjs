// Security review 2026-10-06, V4 (wording), V7 (small-order keys) and V8 (numbers). Synthetic data only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
for (const f of ['v2b.js', 'v2b-text.js']) vm.runInContext(fs.readFileSync(f, 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b, T = ctx.ChainDBoMV2bText;
const plain = value => JSON.parse(JSON.stringify(value));
const bytes = hex => Uint8Array.from(hex.match(/../g).map(pair => parseInt(pair, 16)));
const clone = name => JSON.parse(fs.readFileSync('tests/vectors/v2b/' + name, 'utf8'));

(async () => {
  // V4: the green level is reserved to an authenticated key.
  assert.equal(T.levelText('BLOC_CONFIRME', true).cls, 'success');
  const unknownAuthor = T.levelText('BLOC_CONFIRME', false);
  assert.equal(unknownAuthor.cls, 'unsupported');
  assert.match(unknownAuthor.title, /auteur non authentifié/);
  for (const level of ['INVALIDE', 'INTEGRITE', 'ENGAGEMENT_OTS', 'ATTESTATION_BITCOIN']) assert.equal(T.levelText(level, false), T.LEVEL_TEXT[level]);

  // V7: the eight small-order points, their sign variants and non-canonical encodings are refused; a normal key is not.
  const weak = ['01' + '00'.repeat(31), '00'.repeat(32), '00'.repeat(31) + '80', '01' + '00'.repeat(30) + '80', 'ec' + 'ff'.repeat(30) + '7f',
    'ec' + 'ff'.repeat(31), 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + '7f',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'];
  for (const key of weak) assert.equal(V2B.hasSmallOrder(bytes(key)), true, key);
  assert.equal(V2B.hasSmallOrder(bytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')), false);
  // The reviewer's proof: a real proof, public key and signature replaced by the identity point. It is now refused at the format step.
  const forged = clone('valid_5_leaves.json');
  forged.proof_only.submission.signing_public_key_hex = '01' + '00'.repeat(31);
  forged.proof_only.submission.signature_hex = '01' + '00'.repeat(31) + '00'.repeat(32);
  const verdict = plain(await V2B.verify(forged, {}));
  assert.equal(verdict.level, 'INVALIDE');
  assert.ok(verdict.failed.includes('format'), 'refused as a format error: ' + verdict.failed);
  assert.match(verdict.checks.find(c => c.id === 'format').detail, /ordre faible/);

  // The same refusal on a key card, before any signature is looked at (the fingerprint is made consistent on purpose).
  const card = JSON.parse(fs.readFileSync('tests/vectors/keycard/valid.json', 'utf8'));
  await V2B.checkKeyCard(card); // control: the genuine card is accepted
  const weakCard = { ...card, signing_public_key_hex: '01' + '00'.repeat(31) };
  weakCard.signing_key_fingerprint_sha256 = Buffer.from(await webcrypto.subtle.digest('SHA-256', Buffer.from(weakCard.signing_public_key_hex, 'hex'))).toString('hex');
  await assert.rejects(V2B.checkKeyCard(weakCard), /ordre faible/);

  // V8: an integer written as a decimal is refused on the text of the file; ordinary documents are untouched.
  for (const text of ['{"batch_number": 80.0}', '{"format_version":1.0}', '{"a":[1e2]}', '{"a":8E1}', '{"a":-0}']) {
    assert.throws(() => V2B.checkNumberLiterals(text), /entier écrit comme un décimal|décimal/, text);
  }
  for (const text of ['{"batch_number": 80}', '{"a":"80.0"}', '{"a":"x\\"1.0"}', '{"a":1.5}', '{"a":[0,-5,12]}', '{"a":true,"b":null}']) {
    V2B.checkNumberLiterals(text);
  }
  for (const name of ['valid_5_leaves.json', 'valid_single.json']) V2B.checkNumberLiterals(fs.readFileSync('tests/vectors/v2b/' + name, 'utf8'));
  for (const name of ['proof-1.json', 'proof-2.json']) V2B.checkNumberLiterals(fs.readFileSync('tests/vectors/real/' + name, 'utf8'));
  // V8, inside verify() itself: the raw text (or bytes) of a proof written with 80.0 is refused at the format step, a direct
  // caller no longer depends on the page; the same file written with 80 is accepted.
  const rawGood = fs.readFileSync('tests/vectors/v2b/valid_5_leaves.json', 'utf8');
  const rawBad = rawGood.replace(/"batch_number": ?(\d+)/, '"batch_number": $1.0');
  assert.notEqual(rawBad, rawGood, 'the vector has a batch_number to rewrite');
  for (const input of [rawBad, new TextEncoder().encode(rawBad)]) {
    const refused = plain(await V2B.verify(input, {}));
    assert.equal(refused.level, 'INVALIDE');
    assert.match(refused.checks.find(c => c.id === 'format').detail, /décimal/);
  }
  assert.notEqual(plain(await V2B.verify(rawGood, {})).level, 'INVALIDE');
  assert.notEqual(plain(await V2B.verify(new TextEncoder().encode(rawGood), {})).level, 'INVALIDE');
  assert.equal(plain(await V2B.verify('{not json', {})).level, 'INVALIDE');
  assert.equal(plain(await V2B.verify(Uint8Array.from([0xff, 0xfe]), {})).level, 'INVALIDE');
  console.log('v2b hardening : bandeau vert réservé à une clé authentifiée, clés d\'ordre faible refusées, entiers écrits en décimal refusés');
})().catch(e => { console.error(e); process.exitCode = 1; });
