#!/usr/bin/env node
// Assemble l'outil de clés en UN SEUL fichier HTML (aucune ressource externe) et calcule son empreinte SHA-256.
// Construction déterministe : mêmes sources, même fichier, octet pour octet. Aucune dépendance, aucun réseau.
//   node keys/build-app.js          écrit keys/dist/diadroma-cles.html et keys/dist/diadroma-cles.html.sha256
//   node keys/build-app.js --check  reconstruit et exige un résultat identique aux fichiers commités
// La politique de sécurité (CSP) est écrite dans la page avec l'empreinte de chaque script et de la feuille de style :
// la page ne peut exécuter que ce code-là, ne peut se connecter à rien (connect-src 'none') et ne charge rien.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const root = path.join(__dirname, '..');
const read = rel => fs.readFileSync(path.join(root, rel), 'utf8');
const sha256 = data => createHash('sha256').update(data).digest();
const cspHash = text => "'sha256-" + sha256(text).toString('base64') + "'";

const STYLES = ['style/tokens.css', 'style/style.css', 'keys/app/app.css'];   // the verifier's own look first, then this tool's additions
const SCRIPTS = ['keys/keys-core.js', 'keys/wordlist.js', 'v2b.js', 'keys/vendor/age-encryption.bundle.js', 'keys/keys-backup.js', 'keys/app/texts.fr.js', 'keys/app/app.js'];

function build() {
  const body = text => '\n' + text + '\n';   // exactly what sits between the tags: the CSP hash covers it, whitespace included
  const style = body(STYLES.map(read).join('\n'));
  const scripts = SCRIPTS.map(rel => ({ rel, code: body(read(rel)) }));
  for (const text of [style, ...scripts.map(s => s.code)]) {
    if (/<\/(script|style)/i.test(text) || /<!--/.test(text)) throw new Error('un fichier source contient une séquence qui casserait la page intégrée');
  }
  const csp = ["default-src 'none'", `script-src ${scripts.map(s => cspHash(s.code)).join(' ')}`, `style-src ${cspHash(style)}`, "img-src 'none'", "connect-src 'none'",
    "base-uri 'none'", "form-action 'none'", "object-src 'none'", "frame-src 'none'"].join('; ');
  const html = read('keys/app/template.html')
    .replace('<!--CSP-->', () => `<meta http-equiv="Content-Security-Policy" content="${csp}">`)
    .replace('<!--STYLE-->', () => `<style>${style}</style>`)
    .replace('<!--SCRIPTS-->', () => scripts.map(s => `<script>${s.code}</script>`).join('\n'));
  return { html, digest: sha256(html).toString('hex') };
}

const outHtml = path.join(root, 'keys/dist/diadroma-cles.html');
const outSum = outHtml + '.sha256';
const { html, digest } = build();
const sumText = `${digest}  diadroma-cles.html\n`;
if (process.argv.includes('--check')) {
  const same = fs.existsSync(outHtml) && fs.readFileSync(outHtml, 'utf8') === html && fs.existsSync(outSum) && fs.readFileSync(outSum, 'utf8') === sumText;
  if (!same) { console.error('keys/dist/diadroma-cles.html n’est pas ce que produisent les sources : relancez node keys/build-app.js'); process.exit(1); }
  console.log('fichier unique identique aux sources, SHA-256 ' + digest);
} else {
  fs.mkdirSync(path.dirname(outHtml), { recursive: true });
  fs.writeFileSync(outHtml, html);
  fs.writeFileSync(outSum, sumText);
  console.log(`keys/dist/diadroma-cles.html : ${Buffer.byteLength(html)} octets, SHA-256 ${digest}`);
}
