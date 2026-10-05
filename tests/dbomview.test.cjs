// Affichage lisible du DBoM : données synthétiques, aucune interprétation (pas de total, null n'est jamais zéro).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync('dbom-view.js', 'utf8'), ctx);
const { describe, MAX_ROWS } = ctx.ChainDBoMView;
const plain = v => JSON.parse(JSON.stringify(v));
const component = extra => ({ bom_component_ref: 'CELL-001', bom_component_quantity: '12', unit_of_measure: 'pcs',
  carbon_claim: { status: 'absent', value_kg_co2e: null, basis: null, method_ref: null }, recycled_content_pct: null, ...extra });
const dbom = {
  schema_version: 2, nonce: '00'.repeat(16), inputs: ['ab'.repeat(32)], dbom_id: '11111111-2222-4333-8444-555555555555',
  product_ref: { gtin_or_sku: 'SKU-SYNTH-1', batch_id: 'LOT-42', product_category: 'battery', product_name: 'Pack synthétique' },
  manufacturing_context: { facility_id: 'SITE-A', country: 'FR', production_order_id: 'OF-1', timestamp_utc: null },
  material_provenance: [component({ bom_component_name: 'Cellule', provenance_country: 'DE', supplier_batch_id: 'B7' }),
    component({ bom_component_ref: 'BMS-9', recycled_content_pct: '0', carbon_claim: { status: 'base_inconnue', value_kg_co2e: '3.5', basis: null, method_ref: null } })],
  actors: [], quality_check: { status: 'pass', checked_by: '', method: 'visuel' }, transformations: [],
};

const view = plain(describe(dbom));
assert.equal(view.recognized, true);
assert.deepEqual(view.sections.map(s => s.title), ['Produit', 'Fabrication', 'Contrôle qualité', 'Composants (2)', 'Identifiants']);
const byLabel = (title, label) => view.sections.find(s => s.title === title).rows.find(r => r.label === label).value;
assert.equal(byLabel('Produit', 'Nom'), 'Pack synthétique');
assert.equal(byLabel('Fabrication', 'Date'), 'non déclaré', 'une date absente reste absente');
assert.equal(byLabel('Contrôle qualité', 'Résultat'), 'conforme');
assert.equal(byLabel('Contrôle qualité', 'Contrôlé par'), 'non déclaré');
assert.equal(byLabel('Identifiants', 'Maillons amont référencés'), '1');
const lines = view.sections[3].table.lines;
assert.deepEqual(lines[0], ['Cellule (CELL-001)', '12 pcs', 'DE', 'B7', 'non déclaré', 'non déclaré']);
assert.equal(lines[1][4], '0 %', 'zéro déclaré est affiché comme zéro, distinct de « non déclaré »');
assert.match(lines[1][5], /^3\.5 kg CO2e \(déclaration non qualifiée/);
assert.ok(!JSON.stringify(view).toLowerCase().includes('total'), 'aucun total inféré');

// Champ inconnu : montré tel quel, jamais masqué.
const extra = plain(describe({ ...dbom, product_ref: { ...dbom.product_ref, zzz_inconnu: 'x' } }));
assert.ok(extra.sections[0].rows.some(r => r.label === 'zzz_inconnu' && r.value === 'x'));

// Document qui n'est pas un DBoM v2 : vue générique, sans exception.
for (const other of [{ name: 'valid_5_leaves', quantity: 3 }, { schema_version: true, product_ref: {}, manufacturing_context: {} }, [], 'texte', null, 42]) {
  const g = plain(describe(other));
  assert.equal(g.recognized, false);
  assert.equal(g.sections.length, 1);
}
assert.equal(plain(describe({ a: { b: 1 } })).sections[0].rows[0].value, '{"b":1}');

// Entrées hostiles : valeurs rendues en texte, tableau plafonné.
const hostile = plain(describe({ ...dbom, product_ref: { ...dbom.product_ref, product_name: '<img src=x onerror=1>' },
  material_provenance: Array.from({ length: MAX_ROWS + 5 }, () => component({})) }));
assert.equal(hostile.sections[0].rows[0].value, '<img src=x onerror=1>', 'texte brut : l’interface doit utiliser textContent');
assert.equal(hostile.sections[3].table.lines.length, MAX_ROWS);
assert.equal(hostile.truncated, true);
assert.equal(plain(describe({ ...dbom, material_provenance: [] })).sections[3].empty, 'Aucun composant déclaré.');

console.log('dbom-view : affichage lisible sans interprétation, vue générique, entrées hostiles en texte');
