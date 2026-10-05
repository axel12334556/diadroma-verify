// Contrôle JavaScript du paquet de divulgation, comparé au verdict de la référence Python
// (tests/vectors/disclosure/expected.json, régénéré par tests/tools/gen_disclosure_vectors.py). Hors réseau.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
const dir = 'tests/vectors/disclosure';
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
const load = (d, name) => JSON.parse(fs.readFileSync(path.join(d, name + '.json'), 'utf8'));
const plain = v => JSON.parse(JSON.stringify(v));
const NOW = new Date(expected.now);

(async () => {
  assert.ok(Object.keys(expected.vectors).length >= 30);
  for (const [name, { options, expected: want }] of Object.entries(expected.vectors)) {
    const got = await V2B.checkDisclosure(load(dir, name), {
      keyCard: load('tests/vectors/keycard', options.card), trustedFingerprint: options.fingerprint,
      proofRecordHash: options.proof_record_hash, proofClientId: options.proof_client_id, now: NOW });
    assert.equal(got.ok, want.ok, name + ': accepted/refused like the reference');
    if (want.ok) assert.deepEqual(plain(got.facts), want.facts, name + ': facts');
    else assert.equal(got.facts, null, name + ': no facts on refusal');
  }

  const base = expected.vectors.valid.options;
  const card = load('tests/vectors/keycard', 'valid');
  const run = (name, extra) => V2B.checkDisclosure(load(dir, name), { keyCard: card, trustedFingerprint: base.fingerprint, now: NOW, ...extra });

  // Without a proof the binding is reported as skipped, never as passed.
  const noProof = await run('valid');
  assert.equal(noProof.ok, true);
  assert.equal(noProof.checks.find(c => c.id === 'proof_binding').status, 'skipped');
  // With the matching proof it is passed.
  const withProof = await run('valid', { proofRecordHash: base.proof_record_hash, proofClientId: base.proof_client_id });
  assert.equal(withProof.checks.find(c => c.id === 'proof_binding').status, 'pass');
  // Expiry is a warning on the contractual date, never a failure, and says so.
  const late = await run('valid_expired');
  assert.equal(late.ok, true);
  const expiry = late.checks.find(c => c.id === 'expiry');
  assert.equal(expiry.status, 'warn');
  assert.match(expiry.detail, /aucun accès n'est retiré/);
  assert.equal((await run('valid_no_expiry_no_label')).checks.find(c => c.id === 'expiry').detail, "pas d'échéance indiquée");
  // Fingerprint with separators and capitals is accepted; no card means no verdict of trust.
  const spaced = base.fingerprint.toUpperCase().match(/../g).join(':');
  assert.equal((await run('valid', { trustedFingerprint: spaced })).ok, true);
  const noCard = await V2B.checkDisclosure(load(dir, 'valid'), { trustedFingerprint: base.fingerprint, now: NOW });
  assert.equal(noCard.ok, false);
  assert.deepEqual(plain(noCard.failed), ['signing_key_trust']);
  // Junk never throws.
  for (const junk of [null, [], 'text', 42, {}, { manifest: {}, signature_hex: '', ciphertext_b64: '' }]) {
    const result = await V2B.checkDisclosure(junk, { keyCard: card, trustedFingerprint: base.fingerprint, now: NOW });
    assert.equal(result.ok, false);
    assert.deepEqual(plain(result.failed), ['structure']);
  }

  console.log('disclosure: ' + Object.keys(expected.vectors).length + ' paquets identiques à la référence Python ; échéance signalée, jamais bloquante');
})().catch(error => { console.error(error); process.exitCode = 1; });
