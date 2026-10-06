// V5 (security review 2026-10-06): a tiny .ots file must not be able to exhaust memory or time.
// The hexlify operation (0xf3) doubles the running message at each step; the parser now caps it. Synthetic data only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const bomb = steps => Buffer.concat([MAGIC, Buffer.from([0x01, 0x08]), Buffer.alloc(32, 0xab), Buffer.alloc(steps, 0xf3),
  Buffer.from([0x00]), Buffer.from('0588960d73d71901', 'hex'), Buffer.from([0x01, 0x01])]);
(async () => {
  for (const steps of [22, 40, 200]) {
    const started = Date.now();
    await assert.rejects(V2B.parseOts(new Uint8Array(bomb(steps))), /trop grand/, steps + ' hexlify steps must be refused');
    assert.ok(Date.now() - started < 1000, 'refused quickly');
  }
  // A few doublings stay legal (32 -> 64 -> 128 bytes), so ordinary proofs are untouched.
  const small = await V2B.parseOts(new Uint8Array(bomb(2)));
  assert.equal(small.attestations.length, 1);
  assert.equal(small.attestations[0].digest.length, 128);
  console.log('v2b limits: bombe hexlify (22, 40, 200 étapes) refusée en moins d\'une seconde ; 2 étapes légitimes acceptées');
})().catch(e => { console.error(e); process.exitCode = 1; });
