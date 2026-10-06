# Création des clés du client — module pur (lot 1)

Premier lot de l'interface web de gestion des clés (cadrage : `docs/KEY_WEB_INTERFACE_V2B_CADRAGE.md` du dépôt ChainDBoM).
**Ce n'est pas encore une interface** : un module JavaScript sans réseau, sans dépendance et sans stockage, qui produit en
mémoire les mêmes fichiers que `dbom_v2_seal keygen` et `key_card create` :

| Fichier | Contenu |
| --- | --- |
| `client.json` | identifiants et clés **publiques** |
| `signing.pem` | clé privée de signature Ed25519 (PKCS#8) |
| `age-identity.txt` | identité age X25519 (clé privée de déchiffrement) |
| `key-card.json` | fiche de clé publique, auto-signée (`chaindbom-key-card-v1`) |

`ChainDBoMKeys.generateClientKeys({ signingKeyId, recipientKeyId, [clientId], [now] })` retourne `{ files, card, cardText,
publicFacts }`. Les identifiants de clé sont obligatoires (aucune valeur « demo » par défaut). Les graines fixes (`seeds`) ne
servent qu'aux vecteurs de test.

## Ce qui est garanti, et comment c'est vérifié

- Les clés viennent de WebCrypto (Ed25519, X25519) ; aucune cryptographie n'est réécrite. Seul l'encodage Bech32 de l'identité age
  est implémenté ici, et `tests/keys-core.test.cjs` le contrôle contre le programme `age` lui-même (dérivation du destinataire par
  `age-keygen -y`, puis chiffrement et déchiffrement réels) sur des clés tirées au hasard.
- La fiche de clé est acceptée par le vérificateur du dépôt, et les fichiers sont acceptés par les outils Python de ChainDBoM
  (`load_client_keys`, `verify_key_card`, `v2b_key_backup`) : contrôle fait à la main pour les vecteurs de `tests/vectors/keys`
  (la fiche produite par Python avec les mêmes clés est identique à l'octet près).
- Vecteurs déterministes (graines publiques de test, aucune valeur réelle) : `node tests/tools/gen_keys_vectors.js` les régénère.
- Le module ne contient ni appel réseau ni import (contrôlé par le test).

## Reste à faire (lots suivants)

Sauvegarde et test de restauration compatibles `v2b_key_backup` (lot 2, nécessite la bibliothèque age pour le chiffrement par
phrase secrète) ; interface et fichier unique hors ligne (lot 3) ; revue de sécurité (lot 4). Navigateurs : Ed25519 et X25519
dans WebCrypto sont requis ; sur un navigateur qui ne les gère pas, la création est refusée avec un message clair.
Ce dossier n'est **pas publié** sur GitHub Pages.
