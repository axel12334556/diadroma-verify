const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, AbortController, setTimeout, clearTimeout, Date, Number, Set });
vm.runInContext(fs.readFileSync('ots.js', 'utf8'), ctx);
vm.runInContext(fs.readFileSync('verify.js', 'utf8'), ctx);
const valid = JSON.parse(fs.readFileSync('tests/valid_single.json', 'utf8'));
const verify = (proof, network) => vm.runInContext('verifyProof', ctx)(proof, network);
(async () => {
  let calls = 0;
  const network = async () => { calls++; throw new Error('Network must not be called'); };
  for (const chain of ['ethereum', '', null, 42]) {
    const result = await verify({ ...valid, anchor_chain: chain }, network);
    assert.equal(result.status, 'error');
    assert.equal(calls, 0);
  }
  console.log('JS: chaîne non Bitcoin rejetée avant appel réseau OK');
})().catch(e => { console.error(e); process.exitCode = 1; });
