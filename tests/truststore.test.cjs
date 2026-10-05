// Mémoire locale des empreintes de confiance : stockage factice, aucune dépendance réseau.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync('trust-store.js', 'utf8'), ctx);
const { createTrustStore, KEY, MAX_ENTRIES } = ctx.ChainDBoMTrustStore;
const memory = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), raw: m }; };
const A = '68bb2bda-a431-4a02-89cd-b066efe320c7', B = '89bcd91c-720b-4213-8b93-60ceb3dba157';
const F1 = 'dc992588e8aacc084a02b969dfb67d9d48d038f1aad3b6a6ea8a7dcb5a02f0ab', F2 = 'ab'.repeat(32);

const s = memory(), store = createTrustStore(s);
assert.equal(store.get(A), null);
assert.equal(store.set(A, F1, '2026-10-05'), true);
assert.deepEqual({ ...store.get(A) }, { fingerprint: F1, saved_on: '2026-10-05' });
assert.equal(store.get(B), null, 'une empreinte ne vaut que pour son client');
store.set(A, F2, '2026-10-06');
assert.equal(store.get(A).fingerprint, F2);
assert.equal(store.count(), 1);
assert.equal(store.forget(A), true);
assert.equal(store.get(A), null);

// Entrées invalides refusées, jamais écrites.
for (const args of [['x', F1, '2026-10-05'], [A, 'zz', '2026-10-05'], [A, F1.toUpperCase(), '2026-10-05'], [A, F1, 'hier']]) {
  assert.equal(store.set(...args), false);
}
assert.equal(store.count(), 0);

// Contenu corrompu ou piraté : ignoré sans exception, entrées valides conservées.
s.raw.set(KEY, 'pas du json'); assert.equal(store.get(A), null);
s.raw.set(KEY, JSON.stringify([1, 2])); assert.equal(store.count(), 0);
s.raw.set(KEY, JSON.stringify({ [A]: { fingerprint: F1, saved_on: '2026-10-05' }, [B]: { fingerprint: 'nope', saved_on: '2026-10-05' }, evil: {} }));
assert.equal(store.count(), 1);
assert.equal(store.get(B), null);

// Stockage indisponible : la page doit continuer, sans mémoire.
const broken = createTrustStore({ getItem() { throw new Error('bloqué'); }, setItem() { throw new Error('plein'); } });
assert.equal(broken.get(A), null);
assert.equal(broken.set(A, F1, '2026-10-05'), false);
assert.equal(broken.forget(A), true);
assert.equal(createTrustStore({ getItem: () => null, setItem() { throw new Error('plein'); } }).set(A, F1, '2026-10-05'), false);

// Plafond du nombre de clients mémorisés.
const full = memory(), big = createTrustStore(full);
for (let i = 0; i < MAX_ENTRIES; i++) assert.equal(big.set(`00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, F1, '2026-10-05'), true);
assert.equal(big.set(A, F1, '2026-10-05'), false, 'plafond atteint');
assert.equal(big.set('00000000-0000-4000-8000-000000000000', F2, '2026-10-05'), true, 'mise à jour d’un client existant toujours possible');

console.log('trust-store : mémorisation par client, entrées invalides ignorées, stockage bloqué toléré');
