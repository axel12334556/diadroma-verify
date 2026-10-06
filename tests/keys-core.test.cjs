// Key creation (lot 1): formats identical to the ChainDBoM command-line tools, verified against independent tools
// (the age program, Node's crypto, the repository's own key-card verifier). Synthetic data only, no network.
// The age checks need the age CLI: with REQUIRE_AGE=1 (CI) its absence is a failure, never a silent skip.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync, spawnSync } = require('node:child_process');
const nodeCrypto = require('node:crypto');
const { OPTIONS, ctx } = require('./tools/gen_keys_vectors.js');
const K = ctx.ChainDBoMKeys;
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
const plain = v => JSON.parse(JSON.stringify(v));
const hasAge = spawnSync('age-keygen', ['--version']).status === 0;
if (!hasAge && process.env.REQUIRE_AGE === '1') { console.error('age CLI required (REQUIRE_AGE=1)'); process.exit(1); }

(async () => {
  // 1. Fresh random keys: structure, formats, and the card is accepted by the repository's own verifier.
  const fresh = await K.generateClientKeys({ signingKeyId: 'sign-2026-10', recipientKeyId: 'age-2026-10' });
  assert.deepEqual(Object.keys(fresh.files), ['client.json', 'signing.pem', 'age-identity.txt']);
  const client = JSON.parse(fresh.files['client.json']);
  assert.match(client.client_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(client.age_recipient, /^age1[0-9a-z]{58}$/);
  assert.equal(fresh.files['client.json'], JSON.stringify(Object.fromEntries(Object.entries(client).sort()), null, 2) + '\n');
  assert.match(fresh.files['signing.pem'], /^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,64}\n)+-----END PRIVATE KEY-----\n$/);
  assert.match(fresh.files['age-identity.txt'], /^# created: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\n# public key: age1[0-9a-z]{58}\nAGE-SECRET-KEY-1[0-9A-Z]{58}\n$/);
  const cardFacts = await V2B.checkKeyCard(fresh.card);
  assert.equal(cardFacts.client_id, client.client_id);
  assert.equal(cardFacts.fingerprint_sha256, fresh.publicFacts.signing_key_fingerprint_sha256);
  assert.equal(cardFacts.self_signature, 'verified');
  const tampered = plain(fresh.card); tampered.age_recipient = tampered.age_recipient.slice(0, -1) + (tampered.age_recipient.endsWith('q') ? 'p' : 'q');
  await assert.rejects(V2B.checkKeyCard(tampered));  // the verifier really checks the self-signature
  // The PEM is a real Ed25519 key whose public half is the one in client.json and in the card (Node's crypto, not ours).
  const priv = nodeCrypto.createPrivateKey(fresh.files['signing.pem']);
  assert.equal(priv.asymmetricKeyType, 'ed25519');
  const spki = nodeCrypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  assert.equal(spki.subarray(-32).toString('hex'), client.signing_public_key_hex);

  // 2. Two creations never share a key or a client id.
  const other = await K.generateClientKeys({ signingKeyId: 'sign-2026-10', recipientKeyId: 'age-2026-10' });
  assert.notEqual(other.publicFacts.client_id, fresh.publicFacts.client_id);
  assert.notEqual(other.files['signing.pem'], fresh.files['signing.pem']);
  assert.notEqual(other.publicFacts.age_recipient, fresh.publicFacts.age_recipient);

  // 3. Deterministic vectors: byte-exact with the committed files (guards any silent format drift).
  const fixed = await K.generateClientKeys(OPTIONS);
  for (const [name, content] of Object.entries(fixed.files)) assert.equal(content, fs.readFileSync('tests/vectors/keys/' + name, 'utf8'), name);
  assert.equal(fixed.cardText, fs.readFileSync('tests/vectors/keys/key-card.json', 'utf8'));

  // 4. Refusals: nothing is created from bad input.
  const base = { signingKeyId: 'sign-1', recipientKeyId: 'age-1' };
  for (const bad of [{ signingKeyId: '' }, { signingKeyId: 'a b' }, { recipientKeyId: 'x'.repeat(129) }, { recipientKeyId: undefined },
    { clientId: 'NOT-A-UUID' }, { clientId: '10111213-1415-4617-9819-1A1B1C1D1E1F' }, { now: new Date('x') },
    { seeds: { signing: new Uint8Array(31) } }, { seeds: { age: new Uint8Array(33) } }]) {
    await assert.rejects(K.generateClientKeys({ ...base, ...bad }), K.KeysError);
  }
  await assert.rejects(K.generateClientKeys(), K.KeysError);  // no default identifiers: no « demo » keys by accident

  // 5. No network and no dependency in the module.
  const source = fs.readFileSync('keys/keys-core.js', 'utf8');
  assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon|importScripts|require\s*\(|import\s*\()/.test(source.replace(/\/\*[\s\S]*?\*\//g, '')));

  // 6. The age program itself accepts what we wrote (recipient derivation, and a real encrypt/decrypt round trip).
  if (hasAge) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-core-'));
    try {
      for (const sample of [fixed, fresh, other, ...await Promise.all(Array.from({ length: 12 }, () => K.generateClientKeys(base)))]) {
        const identity = path.join(dir, 'age-identity.txt');
        fs.writeFileSync(identity, sample.files['age-identity.txt'], { mode: 0o600 });
        const recipient = JSON.parse(sample.files['client.json']).age_recipient;
        assert.equal(execFileSync('age-keygen', ['-y', identity]).toString().trim(), recipient);  // Bech32 + derivation
        const probe = nodeCrypto.randomBytes(48);
        const sealed = execFileSync('age', ['-r', recipient], { input: probe });
        assert.deepEqual(execFileSync('age', ['-d', '-i', identity], { input: sealed }), probe);  // identity really decrypts
        fs.rmSync(identity);
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  } else console.log('age CLI absent : contrôles croisés avec age ignorés (REQUIRE_AGE=1 les rend obligatoires)');

  console.log('création des clés : formats, vecteurs, refus et contrôles croisés vérifiés' + (hasAge ? ' (age compris)' : ''));
})().catch(e => { console.error(e); process.exit(1); });
