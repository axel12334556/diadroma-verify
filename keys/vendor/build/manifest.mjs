// Écrit ou contrôle MANIFEST.json : version, licences et empreintes de ce qui a été construit.
// Usage : node manifest.mjs --write | --check   (depuis keys/vendor/build, après npm ci et la construction)
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const bundlePath = '../age-encryption.bundle.js';
const manifestPath = '../MANIFEST.json';
const bundle = readFileSync(bundlePath);
const lock = readFileSync('package-lock.json');

function installed() {
  const rows = [];
  const scan = base => {
    for (const name of readdirSync(base)) {
      if (name.startsWith('.')) continue;
      const dir = join(base, name);
      if (name.startsWith('@')) { scan(dir); continue; }
      if (!existsSync(join(dir, 'package.json'))) continue;
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      rows.push({ name: pkg.name, version: pkg.version, license: pkg.license || 'inconnue' });
    }
  };
  scan('node_modules');
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}
const all = installed();
const manifest = {
  package: 'age-encryption',
  version: all.find(p => p.name === 'age-encryption').version,
  license: all.find(p => p.name === 'age-encryption').license,
  built_with_esbuild: all.find(p => p.name === 'esbuild').version,
  lockfile_sha256: sha256(lock),
  bundle_sha256: sha256(bundle),
  bundle_bytes: bundle.length,
  bundled_dependencies: all.filter(p => !['esbuild'].includes(p.name) && !p.name.startsWith('@esbuild/')),
};
const text = JSON.stringify(manifest, null, 2) + '\n';
const mode = process.argv[2];
if (mode === '--write') { writeFileSync(manifestPath, text); console.log('MANIFEST.json écrit :', manifest.bundle_sha256); }
else if (mode === '--check') {
  if (!existsSync(manifestPath) || readFileSync(manifestPath, 'utf8') !== text) {
    console.error('MANIFEST.json ne correspond pas à la construction :\n' + text);
    process.exit(1);
  }
  console.log('bibliothèque age vendorée : reconstruction identique', manifest.bundle_sha256);
} else { console.error('usage : manifest.mjs --write | --check'); process.exit(2); }
