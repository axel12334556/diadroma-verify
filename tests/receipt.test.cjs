// Contrôle JavaScript des reçus signés (D5), comparé à la référence Python
// (tests/vectors/receipt/expected.json, régénéré par tests/tools/gen_receipt_vectors.py). Hors réseau.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
const dir = 'tests/vectors/receipt';
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
const load = name => JSON.parse(fs.readFileSync(path.join(dir, name + '.json'), 'utf8'));
const status = (r, id) => (r.checks.find(c => c.id === id) || {}).status;
const FP = expected.fingerprint;

(async () => {
  assert.ok(Object.keys(expected.single).length >= 20);
  for (const [name, want] of Object.entries(expected.single)) {
    const text = fs.readFileSync(path.join(dir, name + '.json'), 'utf8');
    if (!want.needs_raw_text) {
      let accepted = true;
      try { await V2B.checkReceipt(load(name), FP); } catch (e) { accepted = false; }
      assert.equal(accepted, want.ok, name + ': accepted/refused like the reference');
    }
    // The page passes the raw text: integers written like decimals (1.0, 1e0) are refused, like the Python reference (R1).
    const list = await V2B.checkReceipts(JSON.parse(text), { trustedFingerprint: FP, rawText: text });
    assert.equal(list.ok, want.ok, name + ': same verdict through checkReceipts with the raw text');
  }
  // The three decimal-written files do parse (JSON.parse reads 1.0 as 1): only the raw text gives them away.
  for (const name of ['client_sequence_1_0', 'client_sequence_1e0', 'format_version_1_0']) {
    assert.equal(expected.single[name].needs_raw_text, true);
    const text = fs.readFileSync(path.join(dir, name + '.json'), 'utf8');
    const refused = await V2B.checkReceipts(JSON.parse(text), { trustedFingerprint: FP, rawText: text });
    assert.equal(refused.ok, false);
    assert.match(refused.checks[0].detail, /entier écrit comme un décimal/);
  }

  // Same receipt, no trusted fingerprint: never "ok", trust reported as skipped.
  const noFp = await V2B.checkReceipts(load('valid'), {});
  assert.equal(noFp.ok, false);
  assert.equal(status(noFp, 'service_key_trust'), 'skipped');
  assert.equal(status(noFp, 'signature'), 'pass');
  // Wrong fingerprint: refused.
  const wrong = await V2B.checkReceipts(load('valid'), { trustedFingerprint: '00'.repeat(32) });
  assert.equal(wrong.ok, false);
  assert.equal(status(wrong, 'service_key_trust'), 'fail');
  // Malformed fingerprint: refused, not thrown.
  const junkFp = await V2B.checkReceipts(load('valid'), { trustedFingerprint: 'zz' });
  assert.equal(junkFp.ok, false);

  // Lists.
  const kinds = { none: 'pass', gap: 'warn', conflict: 'fail' };
  for (const [name, want] of Object.entries(expected.lists)) {
    const r = await V2B.checkReceipts(load(name), { trustedFingerprint: FP });
    assert.equal(r.facts && r.facts.count, want.count, name + ': count');
    assert.equal(status(r, 'sequence'), kinds[want.sequence], name + ': sequence');
    assert.equal(r.ok, want.sequence !== 'conflict', name + ': ok');
  }

  // Binding to a proof.
  const body = load('valid').body;
  const proof = { clientId: body.client_id, submissionId: body.submission_id, clientSequence: body.client_sequence, linkHash: body.link_hash };
  assert.equal(status(await V2B.checkReceipts(load('valid'), { trustedFingerprint: FP, proof }), 'proof_binding'), 'pass');
  assert.equal(status(await V2B.checkReceipts(load('valid'), { trustedFingerprint: FP, proof: { ...proof, linkHash: 'a'.repeat(64) } }), 'proof_binding'), 'fail');
  assert.equal(status(await V2B.checkReceipts(load('valid'), { trustedFingerprint: FP, proof: { ...proof, submissionId: '11111111-1111-4111-8111-111111111111' } }), 'proof_binding'), 'skipped');

  // Junk inputs never throw.
  for (const junk of [null, 42, 'x', [], {}, [null], [{}], { body: 1, signature_b64: 2 }]) {
    const r = await V2B.checkReceipts(junk, { trustedFingerprint: FP });
    assert.equal(r.ok, false);
  }
  // Too many receipts refused.
  const many = Array.from({ length: 5001 }, () => load('valid'));
  assert.equal((await V2B.checkReceipts(many, { trustedFingerprint: FP })).ok, false);
  console.log('receipt.test.cjs ok');
})().catch(e => { console.error(e); process.exit(1); });
