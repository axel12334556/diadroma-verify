const MAX_FILE_BYTES = 1024 * 1024;
const dropzone = document.getElementById('dropzone');
const input = document.getElementById('fileInput');
const output = document.getElementById('result');
const v2bPanel = document.getElementById('v2bOptions');
const v2bReport = document.getElementById('v2bReport');
const optKey = document.getElementById('optFingerprint');
const optFetch = document.getElementById('optFetchBlock');
const optRoot = document.getElementById('optBlockRoot');
const optDbom = document.getElementById('optDbom');
const rerun = document.getElementById('rerun');
let currentV2b = null;

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
async function runV2b() {
  if (!currentV2b) return;
  const options = { trustedKeyFingerprint: optKey.value.trim() || undefined, blockMerkleRoot: optRoot.value.trim() || undefined,
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
  } catch { show('error', 'La vérification a échoué de façon inattendue.'); }
}
async function handleFile(file) {
  v2bReport.hidden = true; v2bPanel.hidden = true; currentV2b = null;
  if (!file || file.size > MAX_FILE_BYTES) { show('error', 'Fichier absent ou trop volumineux (maximum 1 Mo).'); return; }
  show('pending', 'Lecture du fichier en cours…');
  let data;
  try { data = JSON.parse(await file.text()); } catch { show('error', 'Impossible de lire ce fichier JSON.'); return; }
  if (data && data.format === 'chaindbom-anchored-proof-v2b') {
    currentV2b = data;
    v2bPanel.hidden = false;
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
optRoot.addEventListener('input', () => { optFetch.disabled = optRoot.value.trim() !== ''; });
['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) handleFile(event.dataTransfer.files[0]); });
