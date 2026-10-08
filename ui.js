const FINGERPRINT_SOURCE_TEXT = { key_card: 'fiche de clé déposée', device_memory: 'mémoire de cet appareil', typed: 'saisie à la main' };
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_CARD_BYTES = 64 * 1024;
const dropzone = document.getElementById('dropzone');
const input = document.getElementById('fileInput');
const output = document.getElementById('result');
const v2bPanel = document.getElementById('v2bOptions');
const v2bReport = document.getElementById('v2bReport');
const optKey = document.getElementById('optFingerprint');
const optCard = document.getElementById('optKeyCard');
const cardStatus = document.getElementById('cardStatus');
const optFetch = document.getElementById('optFetchBlock');
const optRoot = document.getElementById('optBlockRoot');
const optRevoked = document.getElementById('optRevoked');
const optDbom = document.getElementById('optDbom');
const rerun = document.getElementById('rerun');
const dbomView = document.getElementById('dbomView');
const disclosureReport = document.getElementById('disclosureReport');
const receiptReport = document.getElementById('receiptReport');
const optServiceFp = document.getElementById('optServiceFp');
const reportMeta = document.getElementById('reportMeta');
const reportActions = document.getElementById('reportActions');
const reportDownload = document.getElementById('reportDownload');
const reportPrint = document.getElementById('reportPrint');
const memoryBox = document.getElementById('memoryBox');
const memoryText = document.getElementById('memoryText');
const memoryBtn = document.getElementById('memoryBtn');
const trustStore = ChainDBoMTrustStore.createTrustStore((() => { try { return window.localStorage; } catch { return { getItem() { throw new Error('indisponible'); }, setItem() { throw new Error('indisponible'); } }; } })());
let dropSeq = 0; // numbers the dropped files: a file read that finishes after a newer drop is abandoned
let generation = 0; // incremented by every drop or verification: a result is shown only if no newer one was started (V2)
let currentLegacy = null; // old-format proof (timestamp only, no signature) dropped by the user
let currentV2b = null;
let currentV2bText = null; // raw text of that proof: verify() checks it itself (V8)
let currentV2bResult = null; // verdict for currentV2b: a disclosure is bound to a proof only if this one is sound (V6)
let currentProofSha256 = null; // SHA-256 of the exact bytes of the dropped proof file (null if it could not be computed)
let currentReport = null; // the exportable verification report for the last v2b run
let memorizedFor = null; // client dont l'empreinte vient de la mémoire de cet appareil (null sinon)
let currentDisclosure = null; // disclosure package dropped by the recipient (never decrypted by this page)
let currentReceipts = null; // signed receipts dropped by the client (checked against the service key fingerprint typed by the user)
let cardData = null; // the validated key card object, needed to check the supplier's signature
let cardClientId = null; // client of the key card that filled the fingerprint (null when typed by hand)

function show(status, msg) {
  output.textContent = msg;
  output.className = status;
  output.hidden = false;
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function renderV2b(result) {
  const T = ChainDBoMV2bText;
  const level = T.levelText(result.level, result.signing_key_authenticated);
  v2bReport.replaceChildren();
  const banner = el('div', 'banner ' + level.cls);
  banner.append(el('strong', '', level.title), el('p', '', level.text));
  v2bReport.append(banner);
  if (!result.signing_key_authenticated) {
    v2bReport.append(el('p', 'notice', "La clé de signature de ce fichier n'est pas authentifiée : sans empreinte de confiance obtenue auprès du client par une autre voie (sa fiche de clé), le fichier prouve seulement qu'il est cohérent avec la clé qu'il contient."));
  }
  const list = el('ul', 'checks');
  for (const check of result.checks) {
    const item = el('li', 'check ' + check.status);
    item.append(el('span', 'mark', T.STATUS_MARK[check.status]), el('span', 'label', T.CHECK_LABELS[check.id] || check.id),
      el('span', 'state', T.STATUS_TEXT[check.status]), el('span', 'detail', check.detail));
    list.append(item);
  }
  v2bReport.append(list);
  const limits = el('div', 'limits');
  limits.append(el('h2', '', 'Ce que cette vérification établit, et ce qu\'elle n\'établit pas'),
    el('p', '', "Elle établit qu'une empreinte a été signée par la clé indiquée, rattachée à un lot et, au niveau le plus haut, qu'elle existait au plus tard au moment d'un bloc Bitcoin. Elle ne dit rien de l'exactitude des données industrielles, ni de l'identité du titulaire de la clé sans empreinte de confiance, ni de leur contenu sans le DBoM en clair fourni par le client."),
    el('p', '', "Seul le client détient ses données en clair et ses clés. ChainDBoM ne détient aucune clé de récupération : si le client perd ses clés, ses enveloppes chiffrées sont illisibles, alors que les preuves d'intégrité restent vérifiables."));
  v2bReport.append(limits);
  v2bReport.hidden = false;
}
// Shows the cleartext DBoM only once it has been proven to match the anchored record_hash.
function renderDbom(result, bytes) {
  dbomView.replaceChildren(); dbomView.hidden = true;
  if (!result.dbom_checked || !bytes) return;
  let view;
  try { view = ChainDBoMView.describe(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); } catch { return; }
  dbomView.append(el('h2', '', 'Contenu du DBoM'),
    el('p', 'dbom-note', "Ce contenu correspond à l'empreinte de la preuve : il n'a pas changé depuis son scellement. La preuve ne dit rien de son exactitude. Il est lu dans votre navigateur et n'est envoyé nulle part."));
  if (!view.recognized) dbomView.append(el('p', 'dbom-note', "Ce fichier n'a pas la structure d'un DBoM v2 : ses champs sont affichés tels quels."));
  for (const section of view.sections) {
    dbomView.append(el('h3', '', section.title));
    if (section.rows) {
      const list = el('dl', 'dbom-rows');
      for (const row of section.rows) { const item = el('div'); item.append(el('dt', '', row.label), el('dd', '', row.value)); list.append(item); }
      dbomView.append(list);
    }
    if (section.empty) dbomView.append(el('p', 'dbom-note', section.empty));
    else if (section.table) {
      const wrap = el('div', 'dbom-scroll'), table = el('table'), head = el('tr');
      for (const h of section.table.headers) { const th = el('th', '', h); th.scope = 'col'; head.append(th); }
      const thead = el('thead'); thead.append(head);
      const tbody = el('tbody');
      for (const line of section.table.lines) { const tr = el('tr'); for (const cell of line) tr.append(el('td', '', cell)); tbody.append(tr); }
      table.append(thead, tbody); wrap.append(table); dbomView.append(wrap);
    }
  }
  if (view.truncated) dbomView.append(el('p', 'dbom-note', 'Affichage limité aux ' + ChainDBoMView.MAX_ROWS + ' premières lignes ; le fichier complet a bien été vérifié.'));
  dbomView.hidden = false;
}
const PURPOSE_TEXT = { audit_independant: 'Audit indépendant', controle_reglementaire: 'Contrôle réglementaire',
  relation_commerciale: 'Relation commerciale', reparation_recyclage: 'Réparation ou recyclage', autre: 'Autre' };
const DISCLOSURE_LABELS = { structure: 'Structure du paquet', signing_key_trust: 'Clé du fournisseur authentifiée',
  authorisation_signature: "Signature de l'autorisation", ciphertext_hash: 'Contenu chiffré intact', proof_binding: 'Rattachement à la preuve', expiry: 'Échéance' };
const DISCLOSURE_STATUS = { pass: 'Réussi', fail: 'Échec', skipped: 'Non vérifié', warn: 'À noter' };
const DISCLOSURE_MARK = { pass: '✔', fail: '✘', skipped: '–', warn: '!' };
function proofFacts() {
  // V6: bound only to a proof that passed the integrity level AND whose signing key is authenticated; otherwise "not verified".
  if (!currentV2bResult || currentV2bResult.level_rank < 1 || !currentV2bResult.signing_key_authenticated) return null;
  const m = currentV2b && currentV2b.proof_only && currentV2b.proof_only.submission && currentV2b.proof_only.submission.signed_manifest;
  return m && typeof m.record_hash === 'string' ? { recordHash: m.record_hash, clientId: m.client_id } : null;
}
// Checks the supplier's authorisation. The page never decrypts: it shows who authorised what, and for how long (contractually).
async function runDisclosure() {
  disclosureReport.replaceChildren(); disclosureReport.hidden = true;
  if (!currentDisclosure) return;
  const proof = proofFacts();
  const gen = generation;
  let result;
  try {
    result = await ChainDBoMV2b.checkDisclosure(currentDisclosure, { keyCard: cardData || undefined, trustedFingerprint: optKey.value.trim() || undefined,
      proofRecordHash: proof ? proof.recordHash : undefined, proofClientId: proof ? proof.clientId : undefined });
  } catch { result = { ok: false, checks: [{ id: 'structure', status: 'fail', detail: 'La vérification a échoué de façon inattendue.' }], facts: null }; }
  if (gen !== generation) return; // a newer file or run replaced this one while it was being checked
  disclosureReport.append(el('h2', '', "Autorisation de divulgation"));
  const banner = el('div', 'banner ' + (result.ok ? 'success' : 'error'));
  banner.append(el('strong', '', result.ok ? "Autorisation du fournisseur vérifiée" : "Autorisation non vérifiée"),
    el('p', '', result.ok ? "Le fournisseur a signé cette autorisation avec la clé dont vous avez l'empreinte. Cette page ne déchiffre pas le contenu."
      : "Ne vous appuyez pas sur ce paquet : l'un des contrôles ci-dessous n'est pas réussi."));
  disclosureReport.append(banner);
  if (!cardData) disclosureReport.append(el('p', 'notice', "Déposez la fiche de clé du fournisseur (et son empreinte, publiée par lui) pour vérifier la signature."));
  if (result.facts) {
    const rows = el('dl', 'dbom-rows');
    const add = (label, value) => { const item = el('div'); item.append(el('dt', '', label), el('dd', '', value)); rows.append(item); };
    add('Finalité', PURPOSE_TEXT[result.facts.purpose] || result.facts.purpose);
    add('Destinataire (pseudonyme)', result.facts.recipient_label || 'non indiqué');
    add('Autorisation du', result.facts.created_at);
    add('Échéance', result.facts.expires_at ? result.facts.expires_at + (result.facts.expired ? ' — dépassée (contractuelle, aucun accès retiré techniquement)' : ' (contractuelle)') : 'non indiquée');
    disclosureReport.append(rows);
  }
  const list = el('ul', 'checks');
  for (const check of result.checks) {
    const item = el('li', 'check ' + (check.status === 'warn' ? 'skipped' : check.status));
    item.append(el('span', 'mark', DISCLOSURE_MARK[check.status]), el('span', 'label', DISCLOSURE_LABELS[check.id] || check.id),
      el('span', 'state', DISCLOSURE_STATUS[check.status]), el('span', 'detail', check.detail));
    list.append(item);
  }
  disclosureReport.append(list);
  if (result.ok) disclosureReport.append(el('p', 'dbom-note', "Pour lire le contenu : déchiffrez le paquet avec votre identité age grâce à l'outil de ChainDBoM (dbom_v2_disclosure open), puis déposez le DBoM en clair dans « DBoM en clair » ci-dessus."));
  disclosureReport.hidden = false;
}
const RECEIPT_LABELS = { structure: 'Structure des reçus', service_key_trust: 'Clé du service authentifiée', signature: 'Signatures des reçus',
  sequence: 'Numéros de séquence', proof_binding: 'Rattachement à la preuve' };
function receiptProof() {
  // Bound only to a sound proof with an authenticated key (like V6 for disclosures).
  if (!currentV2b || !currentV2bResult || currentV2bResult.level_rank < 1 || !currentV2bResult.signing_key_authenticated) return undefined;
  const l = currentV2b.proof_only && currentV2b.proof_only.link, m = currentV2b.proof_only && currentV2b.proof_only.submission && currentV2b.proof_only.submission.signed_manifest;
  return l && m ? { clientId: l.client_id, submissionId: l.submission_id, clientSequence: l.client_sequence, linkHash: l.link_hash } : undefined;
}
// Checks signed receipts: that the service signed them with the key whose fingerprint the user got elsewhere. Nothing else is claimed.
async function runReceipts() {
  receiptReport.replaceChildren(); receiptReport.hidden = true;
  if (!currentReceipts) return;
  const gen = generation;
  let result;
  try { result = await ChainDBoMV2b.checkReceipts(currentReceipts, { trustedFingerprint: optServiceFp.value.trim() || undefined, proof: receiptProof() }); }
  catch { result = { ok: false, checks: [{ id: 'structure', status: 'fail', detail: 'La vérification a échoué de façon inattendue.' }], facts: null }; }
  if (gen !== generation) return;
  receiptReport.append(el('h2', '', 'Reçus signés du service'));
  const banner = el('div', 'banner ' + (result.ok ? 'success' : 'error'));
  banner.append(el('strong', '', result.ok ? 'Reçus authentiques' : 'Reçus non vérifiés'),
    el('p', '', result.ok ? "Le service a signé ces reçus avec la clé dont vous avez l'empreinte : il a bien reçu ces envois à ces dates. Un reçu ne prouve ni l'antériorité Bitcoin ni le contenu."
      : "Ne vous appuyez pas sur ces reçus : l'un des contrôles ci-dessous n'est pas réussi."));
  receiptReport.append(banner);
  if (!optServiceFp.value.trim()) receiptReport.append(el('p', 'notice', "Saisissez l'empreinte de la clé de reçus du service, obtenue par un canal extérieur au serveur : un reçu ne peut pas se valider lui-même."));
  if (result.facts) {
    const rows = el('dl', 'dbom-rows');
    const add = (label, value) => { const item = el('div'); item.append(el('dt', '', label), el('dd', '', value)); rows.append(item); };
    add('Reçus', String(result.facts.count)); add('Clients', String(result.facts.clients));
    add('Premier reçu', result.facts.first_received_at); add('Dernier reçu', result.facts.last_received_at);
    receiptReport.append(rows);
  }
  const list = el('ul', 'checks');
  for (const check of result.checks) {
    const item = el('li', 'check ' + (check.status === 'warn' ? 'skipped' : check.status));
    item.append(el('span', 'mark', DISCLOSURE_MARK[check.status]), el('span', 'label', RECEIPT_LABELS[check.id] || check.id),
      el('span', 'state', DISCLOSURE_STATUS[check.status]), el('span', 'detail', check.detail));
    list.append(item);
  }
  receiptReport.append(list);
  receiptReport.hidden = false;
}
function isReceiptFile(data) {
  const one = x => x && typeof x === 'object' && !Array.isArray(x) && 'body' in x && 'signature_b64' in x;
  return Array.isArray(data) ? data.length > 0 && data.every(one) : one(data);
}
function clearReport() { currentReport = null; reportMeta.replaceChildren(); reportActions.hidden = true; }
// Builds the exportable report. It never receives the DBoM bytes: only whether one was provided.
function refreshReport(result, options, doc, proofSha256) {
  clearReport();
  if (!proofSha256) return;
  try {
    currentReport = ChainDBoMReport.buildReport({ result, proofDoc: doc, proofSha256, generatedAt: new Date(),
      inputs: { trustedFingerprintProvided: !!optKey.value.trim(), trustedFingerprint: options.reportFingerprint, trustedFingerprintSource: options.reportFingerprintSource, keyCardProvided: !!cardClientId, blockRootProvided: !!optRoot.value.trim(), compromisedSince: optRevoked.value.trim() || null,
        blockReadFromBlockstream: !!options.fetchBlock, dbomProvided: !!options.dbomBytes } });
  } catch { return; }
  const r = currentReport, rows = el('dl', 'dbom-rows');
  const add = (label, value) => { const item = el('div'); item.append(el('dt', '', label), el('dd', '', value)); rows.append(item); };
  reportMeta.append(el('h2', '', 'Rapport de vérification'), el('p', 'dbom-note', r.statement), rows);
  add('Empreinte SHA-256 du fichier de preuve', r.proof.file_sha256);
  add('Client', r.proof.client_id || 'non lisible'); add('Soumission', r.proof.submission_id || 'non lisible');
  add('Empreinte de l\'enregistrement', r.proof.record_hash || 'non lisible');
  add('Établi le', r.generated_at);
  add('Niveau atteint', r.verdict.level + ' — ' + r.verdict.level_title);
  add('Clé de signature authentifiée', r.verdict.signing_key_authenticated ? 'oui' : 'non');
  add('Empreinte de confiance utilisée', r.inputs.trusted_fingerprint ? r.inputs.trusted_fingerprint + ' (' + FINGERPRINT_SOURCE_TEXT[r.inputs.trusted_fingerprint_source] + ')' : 'aucune');
  add('Éléments fournis par le vérifiant', [r.inputs.trusted_fingerprint_provided && 'empreinte de confiance', r.inputs.key_card_provided && 'fiche de clé',
    r.inputs.block_root_provided && 'racine de bloc', r.inputs.block_read_from_blockstream && 'bloc lu auprès de Blockstream', r.inputs.dbom_provided && 'DBoM en clair (non repris)'].filter(Boolean).join(', ') || 'aucun');
  reportActions.hidden = false;
}
async function runV2b() {
  if (!currentV2b) return;
  const gen = ++generation, doc = currentV2bText || currentV2b, proofSha256 = currentProofSha256; // frozen for this run
  const options = { trustedKeyFingerprint: optKey.value.trim() || undefined, trustedClientId: cardClientId || undefined,
    blockMerkleRoot: optRoot.value.trim() || undefined, compromisedSince: optRevoked.value.trim() || undefined,
    fetchBlock: optFetch.checked && !optRoot.value.trim() };
  const fingerprint = currentFingerprint(); // V9: the report states which fingerprint was used and where it came from
  options.reportFingerprint = fingerprint;
  options.reportFingerprintSource = !fingerprint ? null : cardClientId ? 'key_card' : memorizedFor ? 'device_memory' : 'typed';
  if (optDbom.files.length) {
    const file = optDbom.files[0];
    if (file.size > MAX_FILE_BYTES) { show('error', 'DBoM trop volumineux (maximum 1 Mo).'); return; }
    options.dbomBytes = new Uint8Array(await file.arrayBuffer());
    if (gen !== generation) return;
  }
  show('pending', 'Vérification en cours…');
  try {
    const result = await ChainDBoMV2b.verify(doc, options);
    if (gen !== generation) return; // another file or run started meanwhile: this result is not shown
    currentV2bResult = result;
    output.hidden = true;
    renderV2b(result);
    refreshReport(result, options, doc, proofSha256);
    refreshMemory(result);
    renderDbom(result, options.dbomBytes);
    await runDisclosure();
    await runReceipts();
  } catch { if (gen === generation) show('error', 'La vérification a échoué de façon inattendue.'); }
}
function proofClientId(doc) {
  const m = doc && doc.proof_only && doc.proof_only.submission && doc.proof_only.submission.signed_manifest;
  return m && typeof m.client_id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(m.client_id) ? m.client_id : null;
}
function today() { return new Date().toISOString().slice(0, 10); }
function currentFingerprint() { try { return ChainDBoMV2b.normalizeFingerprint(optKey.value); } catch { return null; } }
// Mémoire locale : jamais automatique, et proposée seulement après une authentification réussie de la clé.
function refreshMemory(result) {
  memoryBox.hidden = true; memoryBtn.hidden = false;
  const clientId = proofClientId(currentV2b);
  if (!clientId) return;
  const saved = trustStore.get(clientId);
  const typed = currentFingerprint();
  if (memorizedFor === clientId && saved && typed === saved.fingerprint) {
    memoryText.textContent = "Empreinte mémorisée sur cet appareil pour ce client (enregistrée le " + saved.saved_on + "). En cas de doute, comparez-la à celle que le client publie.";
    memoryBtn.textContent = "Oublier l'empreinte de ce client";
    memoryBtn.dataset.action = 'forget';
    memoryBox.hidden = false;
  } else if (result && result.signing_key_authenticated && typed && (!saved || saved.fingerprint !== typed)) {
    memoryText.textContent = saved
      ? "Une autre empreinte est déjà mémorisée pour ce client sur cet appareil. La remplacer seulement si le client a changé de clé et l'a publié lui-même."
      : "Mémoriser cette empreinte pour ce client, sur cet appareil seulement ? Elle ne quitte pas votre navigateur ; vous pourrez l'oublier à tout moment.";
    memoryBtn.textContent = saved ? "Remplacer l'empreinte mémorisée" : "Mémoriser pour ce client";
    memoryBtn.dataset.action = 'remember';
    memoryBox.hidden = false;
  }
}
function clearCard(message) {
  cardClientId = null; memorizedFor = null; cardData = null;
  optKey.value = '';
  cardStatus.textContent = message || '';
  cardStatus.hidden = !message;
}
// Takes a parsed key card, checks it (format, fingerprint, self-signature) and puts its fingerprint in the field.
async function applyKeyCard(data) {
  let facts;
  try { facts = await ChainDBoMV2b.checkKeyCard(data); } catch (error) {
    clearCard('Fiche de clé refusée : ' + ((error && error.message) || 'fichier inutilisable') + ". L'empreinte n'a pas été remplie.");
    return false;
  }
  cardClientId = facts.client_id;
  cardData = data;
  memorizedFor = null;
  optKey.value = ChainDBoMV2b.formatFingerprint(facts.fingerprint_sha256);
  const signed = facts.self_signature === 'verified' ? 'auto-signature vérifiée' : "auto-signature non vérifiée (ce navigateur ne gère pas Ed25519)";
  cardStatus.textContent = 'Fiche valide (' + signed + ') : client ' + facts.client_id + ', clé ' + facts.signing_key_id + ', créée le ' + facts.created_at
    + ". Cette fiche ne vaut confiance que si vous l'avez obtenue sur le canal du client lui-même, pas auprès de ChainDBoM ni de la personne qui vous a remis la preuve.";
  cardStatus.hidden = false;
  return true;
}
async function readJson(file, maxBytes) {
  if (!file || file.size > maxBytes) return undefined;
  try { return JSON.parse(await file.text()); } catch { return undefined; }
}
async function handleFile(file) {
  const drop = ++dropSeq;
  const data = await readJson(file, MAX_FILE_BYTES);
  if (drop !== dropSeq) return;
  if (data && data.format === ChainDBoMV2b.KEYCARD_FORMAT) { // a key card dropped on the main area: keep the proof, if any
    if (!(await applyKeyCard(data))) { show('error', cardStatus.textContent); return; }
    if (currentV2b) { await runV2b(); return; }
    if (currentDisclosure) { await runDisclosure(); return; }
    show('success', "Fiche de clé chargée : l'empreinte est prête. Déposez maintenant le fichier de preuve.");
    return;
  }
  if (isReceiptFile(data)) { // signed receipts: checked next to the proof (kept), never replacing it
    output.hidden = true;
    currentReceipts = data;
    v2bPanel.hidden = false;
    await runReceipts();
    return;
  }
  if (data && data.manifest && data.manifest.format === 'chaindbom-disclosure-v1') { // a disclosure package: checked, never decrypted here
    output.hidden = true;
    currentDisclosure = data;
    v2bPanel.hidden = false; // the key card and fingerprint fields live in this panel
    await runDisclosure();
    return;
  }
  generation++; // a verification still running belongs to the file being replaced: its result must not be shown
  v2bReport.hidden = true; v2bPanel.hidden = true; dbomView.hidden = true; currentV2b = null; currentV2bText = null; currentV2bResult = null; currentLegacy = null; currentProofSha256 = null; clearReport(); currentReceipts = null; receiptReport.hidden = true;
  if (!file || file.size > MAX_FILE_BYTES) { currentDisclosure = null; disclosureReport.hidden = true; show('error', 'Fichier absent ou trop volumineux (maximum 1 Mo).'); return; }
  show('pending', 'Lecture du fichier en cours…');
  if (data === undefined) { currentDisclosure = null; disclosureReport.hidden = true; show('error', 'Impossible de lire ce fichier JSON.'); return; }
  if (data && data.format === 'chaindbom-anchored-proof-v2b') {
    currentV2b = data;
    let proofBytes = null;
    try { proofBytes = new Uint8Array(await file.arrayBuffer()); currentProofSha256 = await ChainDBoMReport.sha256Hex(proofBytes); } catch { currentProofSha256 = null; }
    if (drop !== dropSeq) return;
    try {
      currentV2bText = new TextDecoder('utf-8', { fatal: true }).decode(proofBytes);
      ChainDBoMV2b.checkNumberLiterals(currentV2bText); // V8: same refusal as the Python reference (verify() repeats it)
    } catch (error) {
      currentV2b = null; currentV2bText = null; currentProofSha256 = null;
      show('error', 'Fichier de preuve refusé : ' + ((error && error.message) || 'nombre ambigu') + '.');
      return;
    }
    v2bPanel.hidden = false;
    memorizedFor = null;
    const clientId = proofClientId(data), saved = clientId && trustStore.get(clientId);
    if (saved && !optKey.value.trim()) { // nothing typed or dropped yet: use what this device remembers
      optKey.value = ChainDBoMV2b.formatFingerprint(saved.fingerprint);
      memorizedFor = clientId;
    }
    await runV2b(); // also refreshes a disclosure package already dropped, now bound to this proof
    return;
  }
  currentDisclosure = null; disclosureReport.hidden = true;
  currentLegacy = { doc: data }; // wrapped: the document may be null or a scalar, which verifyProof reports as invalid
  await runLegacy();
}
// Old format (timestamp only, no signature): the block is read from Blockstream only if the user ticked the box (V1).
async function runLegacy() {
  if (!currentLegacy) return;
  const gen = ++generation, doc = currentLegacy.doc;
  v2bPanel.hidden = false;
  try {
    const result = await verifyProof(doc, optFetch.checked ? undefined : null);
    if (gen !== generation) return;
    show(result.status, result.msg);
  } catch { if (gen === generation) show('error', 'Impossible de vérifier ce fichier.'); }
}
input.addEventListener('change', () => { if (input.files.length) handleFile(input.files[0]); });
rerun.addEventListener('click', async () => { if (currentV2b) await runV2b(); else if (currentLegacy) await runLegacy(); else if (currentDisclosure) await runDisclosure(); else await runReceipts(); });
optCard.addEventListener('change', async () => {
  if (!optCard.files.length) { clearCard(); return; }
  const data = await readJson(optCard.files[0], MAX_CARD_BYTES);
  if (data === undefined) { clearCard("Fiche de clé illisible ou trop volumineuse (maximum 64 Ko). L'empreinte n'a pas été remplie."); return; }
  if (await applyKeyCard(data)) { if (currentV2b) await runV2b(); else await runDisclosure(); }
});
optKey.addEventListener('input', () => { if (currentDisclosure && !currentV2b) runDisclosure(); memorizedFor = null; memoryBox.hidden = true; if (cardClientId) { cardClientId = null; cardStatus.hidden = true; } }); // typed by hand: no longer from a card
optServiceFp.addEventListener('input', () => { if (currentReceipts) runReceipts(); });
optRoot.addEventListener('input', () => { optFetch.disabled = optRoot.value.trim() !== ''; });
['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) handleFile(event.dataTransfer.files[0]); });
reportDownload.addEventListener('click', () => {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = ChainDBoMReport.reportFileName(currentReport);
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
reportPrint.addEventListener('click', () => { if (currentReport) window.print(); });
memoryBtn.addEventListener('click', async () => {
  const clientId = proofClientId(currentV2b);
  if (!clientId) return;
  if (memoryBtn.dataset.action === 'forget') {
    trustStore.forget(clientId); memorizedFor = null; optKey.value = '';
    await runV2b(); // the field is empty again: the key is no longer authenticated
    return;
  }
  const fingerprint = currentFingerprint();
  if (!fingerprint || !trustStore.set(clientId, fingerprint, today())) {
    memoryText.textContent = "Impossible de mémoriser sur cet appareil (stockage indisponible ou plein). La vérification n'est pas affectée.";
    memoryBtn.hidden = true; return;
  }
  memorizedFor = clientId;
  refreshMemory(null);
});
