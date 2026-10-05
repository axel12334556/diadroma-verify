// Real Bitcoin-anchored proofs (synthetic data): must reach BLOC_CONFIRME offline against the known block root.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b;
// Bitcoin block 970014 (2026-10-05 UTC), merkle root as shown by an explorer.
const BLOCK_ROOT = '9a434ade6091a562799a9cc4afd6427fa3333f2fec9058586ed6f0885dff2e05';
const load = n => JSON.parse(fs.readFileSync('tests/vectors/real/proof-' + n + '.json', 'utf8'));
const statuses = r => Object.fromEntries(r.checks.map(c => [c.id, c.status]));
(async () => {
  for (const n of [1, 2]) {
    const doc = load(n);
    assert.equal(doc.anchor.anchor_block_height, 970014);
    const result = await V2B.verify(doc, { blockMerkleRoot: BLOCK_ROOT });
    assert.equal(result.level, 'BLOC_CONFIRME', 'proof ' + n);
    assert.equal(result.failed.length, 0);
    assert.equal(statuses(result).bitcoin_block, 'pass');
    // Without the block root the level stops at the attestation; with another root it fails.
    assert.equal((await V2B.verify(doc)).level, 'ATTESTATION_BITCOIN');
    assert.deepEqual(Array.from((await V2B.verify(doc, { blockMerkleRoot: '00'.repeat(32) })).failed), ['bitcoin_block']);
    // One altered character anywhere in the proof chain is refused.
    const bad = load(n); bad.proof_only.link.record_hash = bad.proof_only.link.record_hash.replace(/^./, c => c === 'a' ? 'b' : 'a');
    assert.equal((await V2B.verify(bad, { blockMerkleRoot: BLOCK_ROOT })).level, 'INVALIDE');
  }
  // Both proofs come from the same client and batch, in sequence 1 then 2.
  const [one, two] = [load(1), load(2)];
  assert.equal(one.anchor.anchor_digest, two.anchor.anchor_digest);
  assert.equal(two.proof_only.link.previous_link_hash, one.proof_only.link.link_hash);
  console.log('preuves réelles : 2 preuves BLOC_CONFIRME (bloc 970014), altérations refusées');
})().catch(e => { console.error(e); process.exitCode = 1; });
