const MAX_FILE_BYTES = 1024 * 1024;
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
    const result = await verifyProof(data);
    show(result.status, result.msg);
  } catch { show('error', 'Impossible de lire ce fichier JSON.'); }
}
input.addEventListener('change', () => { if (input.files.length) handleFile(input.files[0]); });
['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) handleFile(event.dataTransfer.files[0]); });
