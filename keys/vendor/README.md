# Bibliothèque age vendorée (outil de clés hors ligne)

L'outil de clés doit fonctionner **sans réseau et sans rien charger d'extérieur** (voir le cadrage dans le dépôt ChainDBoM,
`docs/KEY_WEB_INTERFACE_V2B_CADRAGE.md`). Il embarque donc **une seule copie figée** de la bibliothèque officielle
[`age-encryption`](https://github.com/FiloSottile/typage) (licence BSD-3-Clause), nécessaire au chiffrement par phrase
secrète de la sauvegarde. Aucune ressource n'est chargée depuis un CDN ni depuis le registre npm à l'exécution.

## Ce qui est figé

| Élément | Valeur |
| --- | --- |
| Bibliothèque | `age-encryption` **0.3.1** (version exacte, dans `build/package.json`) |
| Outil de construction | `esbuild` **0.27.2** (version exacte) |
| Dépendances transitives | figées, avec leurs empreintes d'intégrité, dans `build/package-lock.json` |
| Ce qui est embarqué | `build/entry.js` : `Encrypter`, `Decrypter`, `generateIdentity`, `identityToRecipient`, rien d'autre |
| Résultat | `age-encryption.bundle.js` (lisible, non minifié, mentions de licence conservées) |
| Empreintes et licences | `MANIFEST.json` : version, licences de chaque paquet embarqué, SHA-256 du verrou et du fichier |

La bibliothèque ne contient aucun appel réseau (`fetch`, `XMLHttpRequest`, `WebSocket`) : le contrôle est refait avant chaque
mise à jour (voir plus bas).

## Comment on s'assure que le fichier est le bon

- **`keys/vendor/build.sh --check`** (exécuté par la CI, job `age-bundle`) reconstruit le fichier depuis le verrou et **échoue
  si le résultat n'est pas identique, à l'octet près,** au fichier commité et à `MANIFEST.json`.
- N'importe qui peut refaire cette reconstruction : `npm` et `bash` suffisent, et le résultat doit avoir l'empreinte inscrite
  dans `MANIFEST.json`.

## Première construction et mise à jour (volontaires, jamais automatiques)

1. Lancer le workflow **« Construire la bibliothèque age (manuel) »** sur `main` (case « Régénérer le verrou npm » pour une
   mise à jour de versions). Il publie le résultat, et son journal, sur la branche `chore/age-vendor-build`, **jamais sur
   `main`**.
2. Relire : liste des paquets et licences dans `MANIFEST.json`, nombre de paquets du verrou, absence d'appel réseau dans le
   fichier (`grep -nE "fetch|XMLHttpRequest|WebSocket|sendBeacon" keys/vendor/age-encryption.bundle.js`).
3. Ouvrir une PR depuis cette branche (sans `build.log`) ; la CI reconstruit et compare.

Toute mise à jour de version est une décision explicite (changer `build/package.json`, régénérer le verrou, relire).

## Limites assumées

- La confiance se reporte sur la bibliothèque officielle et sur les paquets `@noble/*` et `@scure/base` qu'elle utilise, tels
  qu'épinglés par le verrou ; elle ne remplace pas une relecture de sécurité (lot 4 du cadrage).
- La reconstruction identique suppose les mêmes versions de Node et npm de la CI ; une différence d'outil peut changer le fichier
  sans changer le sens du code, et la CI le signalera.
