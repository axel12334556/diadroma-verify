// The exportable verification report: stable structure, no cleartext, honest wording. Offline, synthetic vectors only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
for (const f of ['v2b.js', 'v2b-text.js', 'report.js']) vm.runInContext(fs.readFileSync(f, 'utf8'), ctx);
const { ChainDBoMV2b: V2B, ChainDBoMV2bText: T, ChainDBoMReport: R } = ctx;
const dir = 'tests/vectors/v2b/';
const expected = JSON.parse(fs.readFileSync(dir + 'expected.json', 'utf8'));
const plain = v => JSON.parse(JSON.stringify(v));
const NOW = new Date('2026-10-06T09:00:00Z');

(async () => {
  const opts = expected.valid_with_dbom.options;
  const doc = JSON.parse(fs.readFileSync(dir + 'valid_with_dbom.json', 'utf8'));
  const dbomBytes = new Uint8Array(fs.readFileSync(dir + opts.dbom_file));
  const result = await V2B.verify(doc, { trustedPublicKey: opts.trusted_public_key, blockMerkleRoot: opts.block_merkle_root, dbomBytes });
  const bytes = new Uint8Array(fs.readFileSync(dir + 'valid_with_dbom.json'));
  const sha = await R.sha256Hex(bytes);
  assert.match(sha, /^[0-9a-f]{64}$/);
  assert.equal(sha, require('node:crypto').createHash('sha256').update(bytes).digest('hex'));

  const report = plain(R.buildReport({ result, proofDoc: doc, proofSha256: sha, generatedAt: NOW,
    inputs: { trustedFingerprintProvided: true, blockRootProvided: true, dbomProvided: true } }));
  assert.deepEqual(Object.keys(report), ['format', 'format_version', 'generated_at', 'statement', 'proof', 'verdict', 'inputs', 'checks', 'limits']);
  assert.equal(report.format, 'diadroma-verification-report-v1');
  assert.equal(report.generated_at, '2026-10-06T09:00:00.000Z');
  assert.equal(report.verdict.level, result.level);
  assert.equal(report.verdict.level_title, T.LEVEL_TEXT[result.level].title);
  assert.equal(report.proof.file_sha256, sha);
  assert.match(report.proof.client_id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(Object.keys(report.proof), ['format', 'file_sha256', 'client_id', 'submission_id', 'record_hash', 'batch_number']);
  assert.equal(report.checks.length, result.checks.length);
  for (const c of report.checks) { assert.ok(c.label && c.status_text && typeof c.detail === 'string'); assert.notEqual(c.label, c.id); }
  assert.deepEqual(report.inputs, { trusted_fingerprint_provided: true, key_card_provided: false, block_root_provided: true, block_read_from_blockstream: false, dbom_provided: true });
  assert.match(report.statement, /non signé/);
  assert.match(report.statement, /n'est pas un certificat/);
  assert.equal(R.reportFileName(report), 'rapport-verification-' + sha.slice(0, 8) + '.json');

  // Never any cleartext: no value of the DBoM may appear in the report, and no key material or token field name.
  const dbom = JSON.parse(Buffer.from(dbomBytes).toString('utf8'));
  const leaves = [];
  (function walk(v) { if (v && typeof v === 'object') Object.values(v).forEach(walk); else if (typeof v === 'string' && v.length >= 8) leaves.push(v); })(dbom);
  assert.ok(leaves.length > 0);
  const text = JSON.stringify(report);
  for (const leaf of leaves) if (!/^[0-9a-f]{64}$/.test(leaf)) assert.ok(!text.includes(leaf), 'cleartext value leaked: ' + leaf);
  assert.ok(!/token|private|passphrase|cdb_v2b_/i.test(text));

  // Deterministic: same inputs, same bytes.
  assert.equal(JSON.stringify(R.buildReport({ result, proofDoc: doc, proofSha256: sha, generatedAt: NOW, inputs: {} })).length > 0, true);
  assert.equal(JSON.stringify(R.buildReport({ result, proofDoc: doc, proofSha256: sha, generatedAt: NOW })), JSON.stringify(R.buildReport({ result, proofDoc: doc, proofSha256: sha, generatedAt: NOW })));

  // An invalid proof still gives a report, and it says so; hostile ids in the file are not copied.
  const bad = JSON.parse(fs.readFileSync(dir + 'tampered_signature.json', 'utf8'));
  const badResult = await V2B.verify(bad, {});
  const hostile = JSON.parse(JSON.stringify(bad));
  hostile.proof_only.submission.signed_manifest.client_id = '<script>alert(1)</script>';
  const badReport = plain(R.buildReport({ result: badResult, proofDoc: hostile, proofSha256: sha, generatedAt: NOW }));
  assert.equal(badReport.verdict.level, 'INVALIDE');
  assert.equal(badReport.proof.client_id, null);
  assert.ok(badReport.checks.some(c => c.status === 'fail'));
  assert.equal(badReport.verdict.signing_key_authenticated, false);

  // Every check id the verifier can emit has a human label in the report.
  for (const { expected: e } of Object.values(expected)) for (const id of Object.keys(e.statuses)) assert.ok(T.CHECK_LABELS[id], id);

  // Refusals.
  assert.throws(() => R.buildReport({ result: null, proofDoc: doc, proofSha256: sha, generatedAt: NOW }));
  assert.throws(() => R.buildReport({ result, proofDoc: doc, proofSha256: 'xyz', generatedAt: NOW }));
  assert.throws(() => R.buildReport({ result, proofDoc: doc, proofSha256: sha, generatedAt: new Date('x') }));
  console.log('rapport de vérification : structure, absence de clair, formulation et refus contrôlés');
})().catch(e => { console.error(e); process.exit(1); });
