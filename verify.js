/* Diadroma — vérification provisoirement désactivée : aucun faux positif. */
const MAX_FILE_BYTES = 1024 * 1024;
const HEX_256 = /^[0-9a-fA-F]{64}$/;

async function verifyProof(proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) ||
      !HEX_256.test(proof.current_hash || '') ||
      !HEX_256.test(proof.merkle_root || '') ||
      !Array.isArray(proof.merkle_proof) ||
      typeof proof.ots_proof_b64 !== 'string' || !proof.ots_proof_b64 ||
      proof.merkle_proof.length > 64 ||
      proof.merkle_proof.some(step => !step || !HEX_256.test(step.sibling || '') || !['left', 'right'].includes(step.position))) {
    return { status: 'error', msg: 'Fichier de preuve invalide ou incomplet.' };
  }
  return { status: 'unsupported', msg: 'Vérification cryptographique indisponible pour le moment. Aucune preuve ne peut être confirmée par cette page.' };
}

const dropzone = document.getElementById('dropzone');
const input = document.getElementById('fileInput');
const output = document.getElementById('result');
function show(status, msg) {
  output.textContent = msg;
  output.className = status;
  output.hidden = false;
}
async function handleFile(file) {
  if (!file || file.size > MAX_FILE_BYTES) { show('error', 'Fichier absent ou trop volumineux (maximum 1 Mo).'); return; }
  show('pending', 'Lecture du fichier en cours…');
  try {
    const data = JSON.parse(await file.text());
    const verdict = await verifyProof(data);
    show(verdict.status, verdict.msg);
  } catch { show('error', 'Impossible de lire ce fichier JSON.'); }
}
if (dropzone && input && output) {
  dropzone.addEventListener('click', () => input.click());
  dropzone.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
  ['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
  dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) handleFile(event.dataTransfer.files[0]); });
  input.addEventListener('change', event => { if (event.target.files.length) handleFile(event.target.files[0]); });
}
