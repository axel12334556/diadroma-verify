// Security review 2026-10-06, N4: the key revocation date. A proof is cleared only if its Bitcoin block is dated at
// least two hours BEFORE the compromise declared by the client; every other case is doubtful. Synthetic data only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const ctx = vm.createContext({ crypto: webcrypto, Uint8Array, atob, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout });
for (const f of ['v2b.js', 'v2b-text.js']) vm.runInContext(fs.readFileSync(f, 'utf8'), ctx);
const V2B = ctx.ChainDBoMV2b, T = ctx.ChainDBoMV2bText;
const dir = path.join('tests', 'vectors', 'v2b');
const plain = value => JSON.parse(JSON.stringify(value));
const load = name => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
const expected = load('expected.json');
const statuses = result => Object.fromEntries(result.checks.map(c => [c.id, c.status]));
const detail = result => result.checks.find(c => c.id === 'key_revocation').detail;
const iso = seconds => new Date(seconds * 1000).toISOString();

(async () => {
  const valid = load('valid_5_leaves.json');
  const blockMerkleRoot = expected.valid_5_leaves.options.block_merkle_root, trustedPublicKey = expected.valid_5_leaves.options.trusted_public_key;
  const BLOCK_TIME = 1790000000, HOUR = 3600;
  const base = { blockMerkleRoot, blockTime: BLOCK_TIME, trustedPublicKey };
  assert.ok(T.CHECK_LABELS.key_revocation);

  // Without a date nothing changes: no extra check, same level.
  const none = plain(await V2B.verify(valid, base));
  assert.equal(none.level, 'BLOC_CONFIRME');
  assert.ok(!('key_revocation' in statuses(none)));
  assert.deepEqual(statuses(none), expected.valid_5_leaves.expected.statuses);

  // Anchored well before the compromise: cleared, level unchanged.
  for (const since of [iso(BLOCK_TIME + 3 * HOUR), iso(BLOCK_TIME + 2 * HOUR), iso(BLOCK_TIME + 30 * 86400)]) {
    const ok = plain(await V2B.verify(valid, { ...base, compromisedSince: since }));
    assert.equal(statuses(ok).key_revocation, 'pass', since);
    assert.equal(ok.level, 'BLOC_CONFIRME'); assert.deepEqual(ok.failed, []);
  }

  // Inside the two-hour margin, at the time, or after the block: doubtful, never green.
  for (const [since, wording] of [[iso(BLOCK_TIME + 2 * HOUR - 1), /moins de 2 h avant/], [iso(BLOCK_TIME + HOUR), /moins de 2 h avant/],
    [iso(BLOCK_TIME), /à partir de/], [iso(BLOCK_TIME - 86400), /à partir de/]]) {
    const doubtful = plain(await V2B.verify(valid, { ...base, compromisedSince: since }));
    assert.equal(statuses(doubtful).key_revocation, 'fail', since);
    assert.deepEqual(doubtful.failed, ['key_revocation']);
    assert.equal(doubtful.level, 'INVALIDE');
    assert.match(detail(doubtful), wording); assert.match(detail(doubtful), /douteuse/);
  }

  // A bare date is read as the START of that day (UTC), the earliest and therefore the prudent reading.
  const day = iso(BLOCK_TIME + 3 * 86400).slice(0, 10);
  assert.equal(statuses(plain(await V2B.verify(valid, { ...base, compromisedSince: day }))).key_revocation, 'pass');
  const sameDay = iso(BLOCK_TIME).slice(0, 10);
  assert.equal(statuses(plain(await V2B.verify(valid, { ...base, compromisedSince: sameDay }))).key_revocation, 'fail');
  // The block time may also be given as an instant.
  assert.equal(statuses(plain(await V2B.verify(valid, { blockMerkleRoot, blockTime: iso(BLOCK_TIME), compromisedSince: iso(BLOCK_TIME + 3 * HOUR) }))).key_revocation, 'pass');

  // An unreadable date is refused, not ignored.
  for (const bad of ['yesterday', '2026-13-45', '05/10/2026', '2026-10-05 12:00', 'NaN']) {
    const refused = plain(await V2B.verify(valid, { ...base, compromisedSince: bad }));
    assert.equal(statuses(refused).key_revocation, 'fail', bad);
    assert.match(detail(refused), /illisible/);
  }
  for (const empty of [undefined, null, '']) assert.ok(!('key_revocation' in statuses(plain(await V2B.verify(valid, { ...base, compromisedSince: empty })))));

  // Without the block time (offline, root only) or without a confirmed block, the proof cannot be placed before the
  // compromise: doubtful.
  const noTime = plain(await V2B.verify(valid, { blockMerkleRoot, compromisedSince: iso(BLOCK_TIME + 30 * 86400) }));
  assert.equal(statuses(noTime).key_revocation, 'fail'); assert.match(detail(noTime), /heure du bloc/);
  const noBlock = plain(await V2B.verify(valid, { compromisedSince: iso(BLOCK_TIME + 30 * 86400) }));
  assert.equal(noBlock.level, 'INVALIDE'); assert.match(detail(noBlock), /pas confirmé par un bloc/);
  const wrongBlock = plain(await V2B.verify(valid, { blockMerkleRoot: '00'.repeat(32), blockTime: BLOCK_TIME, compromisedSince: iso(BLOCK_TIME + 30 * 86400) }));
  assert.deepEqual(wrongBlock.failed, ['bitcoin_block', 'key_revocation']);

  // Through the explorer: the block time comes from the block itself (injected client, no real network).
  const HASH = 'ab'.repeat(32), height = valid.anchor.anchor_block_height;
  const mock = block => async url => {
    if (url.endsWith('/block-height/' + height)) return { ok: true, text: async () => HASH + '\n' };
    if (url.endsWith('/block/' + HASH)) return { ok: true, text: async () => JSON.stringify({ id: HASH, height, merkle_root: blockMerkleRoot, ...block }) };
    return { ok: false, text: async () => '' };
  };
  const since = iso(BLOCK_TIME + 3 * HOUR);
  const viaExplorer = plain(await V2B.verify(valid, { fetchBlock: true, fetchImpl: mock({ timestamp: BLOCK_TIME }), compromisedSince: since }));
  assert.equal(statuses(viaExplorer).key_revocation, 'pass'); assert.equal(viaExplorer.level, 'BLOC_CONFIRME');
  for (const timestamp of [undefined, 0, -5, 1.5, '1790000000']) {
    const unknown = plain(await V2B.verify(valid, { fetchBlock: true, fetchImpl: mock({ timestamp }), compromisedSince: since }));
    assert.equal(statuses(unknown).key_revocation, 'fail', String(timestamp)); assert.match(detail(unknown), /heure du bloc/);
  }
  const lateBlock = plain(await V2B.verify(valid, { fetchBlock: true, fetchImpl: mock({ timestamp: BLOCK_TIME + 10 * 86400 }), compromisedSince: since }));
  assert.equal(statuses(lateBlock).key_revocation, 'fail');
  // The timestamp read from the explorer never replaces an explicit block time given by the person.
  const explicit = plain(await V2B.verify(valid, { fetchBlock: true, fetchImpl: mock({ timestamp: BLOCK_TIME + 10 * 86400 }), blockTime: BLOCK_TIME, compromisedSince: since }));
  assert.equal(statuses(explicit).key_revocation, 'pass');

  console.log('v2b revocation : preuve ancrée au moins 2 h avant la compromission validée, tous les autres cas douteux');
})().catch(e => { console.error(e); process.exitCode = 1; });
