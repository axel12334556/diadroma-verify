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

## Sauvegarde et test de restauration (lot 2) — `keys-backup.js`

`ChainDBoMKeysBackup` lit et écrit **exactement** le format de `python -m chaindbom.v2b_key_backup` : un seul fichier age protégé par
phrase secrète, qui contient une archive tar de `backup-manifest.json`, `client.json`, `signing.pem` et `age-identity.txt`. Il se
restaure aussi avec l'outil standard seul : `age -d fichier | tar -xf -`. Le module ne lit ni n'écrit aucun fichier, ne stocke rien et
n'envoie rien : il reçoit et rend des octets ou des chaînes. Le chiffrement vient de la bibliothèque age vendorée
(`keys/vendor/`), la signature de WebCrypto.

| Fonction | Rôle |
| --- | --- |
| `backup(files, passphrase, [{now}])` | vérifie que les clés fonctionnent, chiffre, **rouvre le fichier produit avec la même phrase**, revérifie, puis seulement rend `{bytes, facts}` |
| `restoreTest(bytes, passphrase, [{card}])` | déchiffre, vérifie les empreintes, prouve que la clé signe et que l'identité age déchiffre encore, la compare à la fiche publiée si fournie ; rend des faits publics, jamais un secret |
| `restore(bytes, passphrase, [{card}])` | comme `restoreTest`, et rend aussi les trois fichiers (l'appelant les propose en téléchargement) |
| `generatePassphrase([{words}])` | 7 mots tirés sans biais (rejet des tirages inégaux) dans `keys/wordlist.js` ; `entropyBits` est calculé sur la liste réelle (≈ 90 bits pour 7 mots) |

Phrase secrète saisie à la main : au moins 12 caractères, sans saut de ligne, caractère de contrôle ni espace au début ou à la fin. Elle
n'est **pas normalisée** (comme l'outil age) : une phrase avec accents doit être saisie de la même façon à la restauration.
La phrase et le fichier de sauvegarde se rangent séparément ; ChainDBoM ne peut rien récupérer si les deux sont perdus.

**Liste de mots** : copie de la « EFF Long Wordlist » (licence CC BY 3.0 US) telle que distribuée par KeePassXC. Elle compte 7772 mots,
et non les 7776 de la liste officielle : ce n'est **pas** la liste officielle à l'identique (provenance, commit et empreinte dans l'en-tête
de `keys/wordlist.js`, contrôlés par le test).

### Vérifications (`tests/keys-backup.test.cjs`, avec `REQUIRE_AGE=1` en CI)

- aller-retour, mauvaise phrase, fichier abîmé ou tronqué, fichier qui n'est pas un fichier age à phrase secrète, fiche d'un autre jeu de
  clés, fiche falsifiée, clés qui ne correspondent pas : tous refusés, sans jamais rendre d'octets de sauvegarde ;
- lecteur d'archive strict (membre inconnu ou en double, chemin, lien, répertoire, préfixe, somme de contrôle, données après la fin, taille,
  empreintes du manifeste) : chaque cas fabriqué est scellé avec la bonne phrase et doit quand même être refusé ;
- ouverture par l'outil `age` réel (phrase tapée à son invite, dans un pseudo-terminal) puis `tar`, comparaison octet à octet ;
  archive écrite par `tar` (format ustar) relue ici ; sauvegarde faite par `age -p` relue ici ;
- sauvegarde faite par l'outil Python de ChainDBoM (`tests/vectors/keys/backup-python.age`) rouverte ici ;
- dans l'autre sens, `tests/vectors/keys/backup-js.age` (faite ici) a été rouverte par `restore-test` et `restore` de l'outil Python
  (contrôle fait à la main : le dépôt privé n'est pas disponible dans cette CI) ;
- le module ne contient ni réseau, ni stockage, ni chargement dynamique, ni journal (`console`).

Les vecteurs utilisent des clés 100 % synthétiques et une phrase de test publique qui ne protège rien. `backup-js.age` change à chaque
régénération (sel aléatoire) : `node tests/tools/gen_keys_backup_fixture.js`.

## Reste à faire (lots suivants)

Interface et fichier unique hors ligne (lot 3) ; revue de sécurité (lot 4). Navigateurs : Ed25519 et X25519
dans WebCrypto sont requis ; sur un navigateur qui ne les gère pas, la création est refusée avec un message clair.
Ce dossier n'est **pas publié** sur GitHub Pages.
