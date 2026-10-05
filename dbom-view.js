// Mise en forme lisible d'un DBoM en clair, sans rien interpréter : aucun total, aucune valeur déduite,
// « non déclaré » n'est jamais présenté comme zéro. Ne produit que des données (titres, lignes, tableaux) ;
// l'interface les affiche en texte brut. Rien n'est envoyé.
(function (root) {
  'use strict';
  const MAX_ROWS = 500;
  const ABSENT = 'non déclaré';
  const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const text = v => (v === null || v === undefined || v === '' ? ABSENT : typeof v === 'object' ? JSON.stringify(v) : String(v));
  const QUALITY = { pass: 'conforme', fail: 'non conforme', pending: 'en attente' };

  function rows(object, labels) {
    const out = [];
    for (const [key, label] of labels) if (key in object) out.push({ label, value: text(object[key]) });
    for (const key of Object.keys(object).sort()) {
      if (!labels.some(([known]) => known === key)) out.push({ label: key, value: text(object[key]) });
    }
    return out;
  }
  function carbon(claim) {
    if (!isObject(claim)) return ABSENT;
    if (claim.status === 'absent') return ABSENT;
    if (claim.status === 'base_inconnue') return text(claim.value_kg_co2e) + ' kg CO2e (déclaration non qualifiée, base inconnue)';
    return text(claim.value_kg_co2e) + ' (' + text(claim.status) + ')';
  }

  // Vue générique : pour un document qui n'est pas un DBoM v2, on montre les champs tels quels.
  function generic(doc) {
    const entries = isObject(doc) ? Object.keys(doc).sort().map(key => ({ label: key, value: text(doc[key]) })) : [{ label: 'contenu', value: text(doc) }];
    return { recognized: false, sections: [{ title: 'Contenu du fichier', rows: entries.slice(0, MAX_ROWS) }], truncated: entries.length > MAX_ROWS };
  }

  function describe(doc) {
    if (!isObject(doc) || doc.schema_version !== 2 || !isObject(doc.product_ref) || !isObject(doc.manufacturing_context)) return generic(doc);
    const sections = [];
    sections.push({ title: 'Produit', rows: rows(doc.product_ref, [['product_name', 'Nom'], ['product_reference', 'Référence'], ['product_category', 'Catégorie'],
      ['gtin', 'GTIN'], ['gtin_or_sku', 'GTIN ou référence interne'], ['batch_id', 'Lot']]) });
    sections.push({ title: 'Fabrication', rows: rows(doc.manufacturing_context, [['facility_id', 'Site'], ['country', 'Pays'], ['production_order_id', 'Ordre de fabrication'],
      ['timestamp_utc', 'Date'], ['source_manufacturing_date', 'Date de fabrication (source)']]) });
    if (isObject(doc.quality_check)) {
      const q = doc.quality_check;
      sections.push({ title: 'Contrôle qualité', rows: [{ label: 'Résultat', value: QUALITY[q.status] || text(q.status) },
        { label: 'Contrôlé par', value: text(q.checked_by) }, { label: 'Méthode', value: text(q.method) }] });
    }
    const components = Array.isArray(doc.material_provenance) ? doc.material_provenance : [];
    const table = { headers: ['Composant', 'Quantité', 'Provenance', 'Lot fournisseur', 'Contenu recyclé', 'Carbone déclaré'], lines: [] };
    for (const c of components.slice(0, MAX_ROWS)) {
      if (!isObject(c)) { table.lines.push([text(c), '', '', '', '', '']); continue; }
      const name = c.bom_component_name ? c.bom_component_name + ' (' + text(c.bom_component_ref) + ')' : text(c.bom_component_ref);
      const origin = [c.provenance_country, c.provenance_site].filter(Boolean).join(', ');
      table.lines.push([name, text(c.bom_component_quantity) + ' ' + (c.unit_of_measure || ''), text(origin), text(c.supplier_batch_id),
        c.recycled_content_pct === null || c.recycled_content_pct === undefined ? ABSENT : c.recycled_content_pct + ' %', carbon(c.carbon_claim)]);
    }
    sections.push({ title: 'Composants (' + components.length + ')', table, empty: components.length ? null : 'Aucun composant déclaré.' });
    const inputs = Array.isArray(doc.inputs) ? doc.inputs : [];
    sections.push({ title: 'Identifiants', rows: [{ label: 'Identifiant du DBoM', value: text(doc.dbom_id) },
      { label: 'Maillons amont référencés', value: inputs.length ? String(inputs.length) : 'aucun' }] });
    return { recognized: true, sections, truncated: components.length > MAX_ROWS };
  }
  root.ChainDBoMView = { describe, MAX_ROWS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
