// Every check id and every level the verifier can produce has a French text; nothing is left to a default.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync('v2b.js', 'utf8'), ctx);
vm.runInContext(fs.readFileSync('v2b-text.js', 'utf8'), ctx);
const { LEVEL_TEXT, CHECK_LABELS, STATUS_TEXT, STATUS_MARK } = ctx.ChainDBoMV2bText;
const expected = JSON.parse(fs.readFileSync('tests/vectors/v2b/expected.json', 'utf8'));
const ids = new Set(), levels = new Set();
for (const { expected: e } of Object.values(expected)) { Object.keys(e.statuses).forEach(i => ids.add(i)); levels.add(e.level); }
for (const id of ids) assert.ok(CHECK_LABELS[id], 'missing label for ' + id);
for (const level of ctx.ChainDBoMV2b.LEVELS) assert.ok(LEVEL_TEXT[level] && LEVEL_TEXT[level].text && LEVEL_TEXT[level].cls, 'missing text for ' + level);
for (const status of ['pass', 'fail', 'skipped']) assert.ok(STATUS_TEXT[status] && STATUS_MARK[status]);
assert.ok(ids.size >= 10 && levels.size >= 4);
console.log('textes v2b complets : ' + ids.size + ' contrôles, ' + ctx.ChainDBoMV2b.LEVELS.length + ' niveaux');
