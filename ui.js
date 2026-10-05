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
const optDbom = document.getElementById('optDbom');
const rerun = document.getElementById('rerun');
const dbomView = document.getElementById('dbomView');
const memoryBox = document.getElementById('memoryBox');
const memoryText = document.getElementById('memoryText');
const memoryBtn = document.getElementById('memoryBtn');
const trustStore = ChainDBoMTrustStore.createTrustStore((() => { try { return window.localStorage; } catch { return { getItem() { throw new Error('indisponible'); }, setItem() { throw new Error('indisponible'); } }; } })());
let currentV2b = null;
let memorizedFor = null; // client dont l'empreinte vient de la mémoire de cet appareil (null sinon)
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
  const level = T.LEVEL_TEXT[result.level];
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
async function runV2b() {
  if (!currentV2b) return;
  const options = { trustedKeyFingerprint: optKey.value.trim() || undefined, trustedClientId: cardClientId || undefined,
    blockMerkleRoot: optRoot.value.trim() || undefined,
    fetchBlock: optFetch.checked && !optRoot.value.trim() };
  if (optDbom.files.length) {
    const file = optDbom.files[0];
    if (file.size > MAX_FILE_BYTES) { show('error', 'DBoM trop volumineux (maximum 1 Mo).'); return; }
    options.dbomBytes = new Uint8Array(await file.arrayBuffer());
  }
  show('pending', 'Vérification en cours…');
  try {
    const result = await ChainDBoMV2b.verify(currentV2b, options);
    output.hidden = true;
    renderV2b(result);
    refreshMemory(result);
    renderDbom(result, options.dbomBytes);
  } catch { show('error', 'La vérification a échoué de façon inattendue.'); }
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
  cardClientId = null; memorizedFor = null;
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
  const data = await readJson(file, MAX_FILE_BYTES);
  if (data && data.format === ChainDBoMV2b.KEYCARD_FORMAT) { // a key card dropped on the main area: keep the proof, if any
    if (!(await applyKeyCard(data))) { show('error', cardStatus.textContent); return; }
    if (currentV2b) { await runV2b(); return; }
    show('success', "Fiche de clé chargée : l'empreinte est prête. Déposez maintenant le fichier de preuve.");
    return;
  }
  v2bReport.hidden = true; v2bPanel.hidden = true; dbomView.hidden = true; currentV2b = null;
  if (!file || file.size > MAX_FILE_BYTES) { show('error', 'Fichier absent ou trop volumineux (maximum 1 Mo).'); return; }
  show('pending', 'Lecture du fichier en cours…');
  if (data === undefined) { show('error', 'Impossible de lire ce fichier JSON.'); return; }
  if (data && data.format === 'chaindbom-anchored-proof-v2b') {
    currentV2b = data;
    v2bPanel.hidden = false;
    memorizedFor = null;
    const clientId = proofClientId(data), saved = clientId && trustStore.get(clientId);
    if (saved && !optKey.value.trim()) { // nothing typed or dropped yet: use what this device remembers
      optKey.value = ChainDBoMV2b.formatFingerprint(saved.fingerprint);
      memorizedFor = clientId;
    }
    await runV2b();
    return;
  }
  try {
    const result = await verifyProof(data);
    show(result.status, result.msg);
  } catch { show('error', 'Impossible de vérifier ce fichier.'); }
}
input.addEventListener('change', () => { if (input.files.length) handleFile(input.files[0]); });
rerun.addEventListener('click', runV2b);
optCard.addEventListener('change', async () => {
  if (!optCard.files.length) { clearCard(); return; }
  const data = await readJson(optCard.files[0], MAX_CARD_BYTES);
  if (data === undefined) { clearCard("Fiche de clé illisible ou trop volumineuse (maximum 64 Ko). L'empreinte n'a pas été remplie."); return; }
  if (await applyKeyCard(data) && currentV2b) await runV2b();
});
optKey.addEventListener('input', () => { memorizedFor = null; memoryBox.hidden = true; if (cardClientId) { cardClientId = null; cardStatus.hidden = true; } }); // typed by hand: no longer from a card
optRoot.addEventListener('input', () => { optFetch.disabled = optRoot.value.trim() !== ''; });
['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) handleFile(event.dataTransfer.files[0]); });
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
