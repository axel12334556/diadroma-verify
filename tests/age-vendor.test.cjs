// The vendored age library: it is the expected file, it has no network code, and it interoperates with the age program.
// Passphrase-mode interoperability needs a terminal and is tested with the backup module (lot 2); here the recipient mode
// is checked against the age CLI. With REQUIRE_AGE=1 (CI) a missing age CLI is a failure, never a silent skip.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createHash, randomBytes } = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');

const bundlePath = 'keys/vendor/age-encryption.bundle.js';
const bundle = fs.readFileSync(bundlePath);
const manifest = JSON.parse(fs.readFileSync('keys/vendor/MANIFEST.json', 'utf8'));
const hasAge = spawnSync('age-keygen', ['--version']).status === 0;
if (!hasAge && process.env.REQUIRE_AGE === '1') { console.error('age CLI required (REQUIRE_AGE=1)'); process.exit(1); }

(async () => {
  // 1. It is the file the manifest describes, with the pinned version and licences.
  assert.equal(createHash('sha256').update(bundle).digest('hex'), manifest.bundle_sha256);
  assert.equal(bundle.length, manifest.bundle_bytes);
  assert.equal(manifest.package, 'age-encryption'); assert.equal(manifest.version, '0.3.1');
  assert.equal(JSON.parse(fs.readFileSync('keys/vendor/build/package.json', 'utf8')).dependencies['age-encryption'], '0.3.1');  // exact, no range
  assert.ok(manifest.bundled_dependencies.every(p => /^(MIT|BSD-3-Clause)$/.test(p.license)), 'only permissive licences');
  assert.equal(createHash('sha256').update(fs.readFileSync('keys/vendor/build/package-lock.json')).digest('hex'), manifest.lockfile_sha256);

  // 2. No network code or dynamic loading in what we ship (comments removed first).
  const code = bundle.toString('utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon|importScripts|EventSource)\b/.test(code), 'network API found');
  assert.ok(!/\bimport\s*\(|\brequire\s*\(/.test(code), 'dynamic loading found');

  // 3. It exposes exactly what the key tool needs, and works (in a fresh context, as a browser would run it).
  const ctx = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt, Promise,
    setTimeout, clearTimeout, queueMicrotask, ReadableStream, WritableStream, TransformStream, Blob, Response, structuredClone });
  vm.runInContext(bundle.toString('utf8'), ctx);
  const A = ctx.AgeEncryption;
  assert.deepEqual(Object.keys(A).sort(), ['Decrypter', 'Encrypter', 'generateIdentity', 'identityToRecipient']);
  const text = 'synthetic cleartext';
  const passphrase = 'synthetic passphrase for tests only';
  const encrypter = new A.Encrypter(); encrypter.setPassphrase(passphrase);
  const sealed = await encrypter.encrypt(new TextEncoder().encode(text));
  assert.ok(Buffer.from(sealed).subarray(0, 40).toString().startsWith('age-encryption.org/v1\n-> scrypt '));
  const good = new A.Decrypter(); good.addPassphrase(passphrase);
  assert.equal(await good.decrypt(sealed, 'text'), text);
  const bad = new A.Decrypter(); bad.addPassphrase('wrong passphrase');
  await assert.rejects(bad.decrypt(sealed, 'text'));
  const tampered = Uint8Array.from(sealed); tampered[tampered.length - 5] ^= 1;
  const again = new A.Decrypter(); again.addPassphrase(passphrase);
  await assert.rejects(again.decrypt(tampered, 'text'));

  // 4. Recipient mode interoperates with the age program, in both directions (no terminal needed).
  if (hasAge) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'age-vendor-'));
    try {
      const identity = path.join(dir, 'id.txt');
      execFileSync('age-keygen', ['-o', identity], { stdio: 'ignore' });
      const recipient = execFileSync('age-keygen', ['-y', identity]).toString().trim();
      const probe = randomBytes(64);
      const toCli = new A.Encrypter(); toCli.addRecipient(recipient);
      assert.deepEqual(execFileSync('age', ['-d', '-i', identity], { input: Buffer.from(await toCli.encrypt(probe)) }), probe);
      const secret = fs.readFileSync(identity, 'utf8').split('\n').find(line => line.startsWith('AGE-SECRET-KEY-'));
      const fromCli = new A.Decrypter(); fromCli.addIdentity(secret);
      assert.deepEqual(Buffer.from(await fromCli.decrypt(execFileSync('age', ['-r', recipient], { input: probe }))), probe);
      assert.equal(await A.identityToRecipient(secret), recipient);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  } else console.log('age CLI absent : interopérabilité ignorée (REQUIRE_AGE=1 la rend obligatoire)');

  console.log('bibliothèque age vendorée : empreinte, absence de code réseau, chiffrement par phrase secrète et interopérabilité vérifiés');
})().catch(e => { console.error(e); process.exit(1); });
