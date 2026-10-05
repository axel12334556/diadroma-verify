// Key card drop: the JavaScript checker must agree with the Python reference on every vector,
// and a card must prefill the trusted fingerprint without ever weakening the verdict. Offline only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
const dir = 'tests/vectors/keycard';
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
const load = name => JSON.parse(fs.readFileSync(path.join(dir, name + '.json'), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));

(async () => {
  assert.ok(Object.keys(expected).length >= 18);
  for (const [name, want] of Object.entries(expected)) {
    let got = null, error = null;
    try { got = await V2B.checkKeyCard(load(name)); } catch (e) { error = e; }
    assert.equal(error === null, want.ok, name + ': accepted/refused like the reference' + (error ? ' (' + error.message + ')' : ''));
    if (want.ok) {
      assert.equal(got.self_signature, 'verified', name + ': self-signature');
      assert.equal(got.client_id, want.facts.client_id, name + ': client_id');
      assert.equal(got.fingerprint_sha256, want.facts.fingerprint_sha256, name + ': fingerprint');
      assert.equal(got.signing_key_id, want.facts.signing_key_id, name + ': key id');
    }
  }

  // Junk is refused without crashing.
  for (const junk of [null, [], 'text', 42, {}]) await assert.rejects(() => V2B.checkKeyCard(junk));

  // The fingerprint read from a card authenticates the signing key of the matching proof...
  const proof = JSON.parse(fs.readFileSync('tests/vectors/v2b/valid_5_leaves.json', 'utf8'));
  const card = await V2B.checkKeyCard(load('valid'));
  const ok = await V2B.verify(proof, { trustedKeyFingerprint: V2B.formatFingerprint(card.fingerprint_sha256) });
  assert.equal(ok.signing_key_authenticated, true);

  // ...but another client's card never does, and a different client id is reported.
  const other = await V2B.checkKeyCard(load('valid_other_client'));
  const refused = await V2B.verify(proof, { trustedKeyFingerprint: V2B.formatFingerprint(other.fingerprint_sha256) });
  assert.equal(refused.signing_key_authenticated, false);
  const wrongClient = await V2B.verify(proof, { trustedKeyFingerprint: card.fingerprint_sha256, trustedClientId: other.client_id });
  assert.ok(plain(wrongClient.failed).length > 0, 'a card of another client is refused');
  const sameClient = await V2B.verify(proof, { trustedKeyFingerprint: card.fingerprint_sha256, trustedClientId: card.client_id });
  assert.equal(sameClient.signing_key_authenticated, true);
  assert.deepEqual(plain(sameClient.failed), plain(ok.failed));

  // Display format: groups of 8 hexadecimal characters.
  assert.equal(V2B.formatFingerprint('AB'.repeat(32)), 'abababab abababab abababab abababab abababab abababab abababab abababab');

  console.log('keycard: ' + Object.keys(expected).length + ' fiches identiques à la référence Python ; empreinte injectée sans affaiblir la vérification');
})().catch(error => { console.error(error); process.exitCode = 1; });
