const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder });
vm.runInContext(fs.readFileSync('ots.js', 'utf8'), ctx);
const parse = vm.runInContext('parseOts', ctx);
const proof = JSON.parse(fs.readFileSync('tests/valid_single.json', 'utf8'));
(async () => {
  const decoded = await parse(proof.ots_proof_b64);
  assert.equal(decoded.root, proof.merkle_root);
  assert.equal(decoded.attestations.length, 2);
  for (const a of decoded.attestations) {
    assert.equal(a.height, 969034);
    assert.equal(a.digest, '673b88a49932c2d9d62bf9ed62c283a10a6b1c84c04ba7843dab92299c9a48b7');
  }
  const raw = Buffer.from(proof.ots_proof_b64, 'base64');
  await assert.rejects(parse(raw.subarray(0, raw.length - 5).toString('base64')));
  assert.throws(() => parse('AA=='));
  assert.throws(() => parse('%%%'));
  const tampered = Buffer.from(raw); tampered[33] ^= 1;
  const changed = await parse(tampered.toString('base64'));
  assert.notEqual(changed.root, proof.merkle_root);
  console.log('OTS: racine, 2 attestations, digest, bloc 969034 et rejets de preuves altérées OK');
})().catch(e => { console.error(e); process.exitCode = 1; });
