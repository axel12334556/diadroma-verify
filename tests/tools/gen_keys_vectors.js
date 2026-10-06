// Regenerates the deterministic, 100 % synthetic key vectors (fixed seeds, fixed date). The seeds below are public
// test values and protect nothing. Usage: node tests/tools/gen_keys_vectors.js
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, TextEncoder, Uint8Array, atob, btoa, Date });
vm.runInContext(fs.readFileSync('keys/keys-core.js', 'utf8'), ctx);
const SEEDS = { signing: Uint8Array.from({ length: 32 }, (_, i) => i + 1), age: Uint8Array.from({ length: 32 }, (_, i) => 0xA0 + i), client: Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i) };
const OPTIONS = { signingKeyId: 'sign-synthetic-1', recipientKeyId: 'age-synthetic-1', now: new Date('2026-10-06T08:00:00Z'), seeds: SEEDS };
module.exports = { SEEDS, OPTIONS, ctx };
if (require.main === module) {
  ctx.ChainDBoMKeys.generateClientKeys(OPTIONS).then(r => {
    for (const [name, content] of Object.entries(r.files)) fs.writeFileSync('tests/vectors/keys/' + name, content);
    fs.writeFileSync('tests/vectors/keys/key-card.json', r.cardText);
    console.log('vecteurs de clés régénérés :', r.publicFacts);
  });
}
