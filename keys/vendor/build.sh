#!/usr/bin/env bash
# Reconstruit keys/vendor/age-encryption.bundle.js à partir du verrou npm (versions et empreintes figées).
#   keys/vendor/build.sh --write   construit et écrit MANIFEST.json
#   keys/vendor/build.sh --check   construit et échoue si le résultat diffère de MANIFEST.json ET du fichier commité
set -euo pipefail
mode="${1:---check}"
cd "$(dirname "$0")/build"
test -f package-lock.json || { echo "package-lock.json manquant : voir ../README.md" >&2; exit 2; }
npm ci --ignore-scripts --no-audit --no-fund
if [ "$mode" = "--check" ]; then cp ../age-encryption.bundle.js /tmp/committed-age-bundle.js; fi
npx --no-install esbuild entry.js --bundle --format=iife --global-name=AgeEncryption --platform=browser \
  --target=es2022 --legal-comments=inline --log-level=warning --outfile=../age-encryption.bundle.js
if [ "$mode" = "--check" ]; then cmp ../age-encryption.bundle.js /tmp/committed-age-bundle.js; fi
node manifest.mjs "$mode"
