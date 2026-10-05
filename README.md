# Diadroma Verify

Outil de vérification d'une preuve d'ancrage OpenTimestamps/Bitcoin. **Version de test : ne pas utiliser comme seule base d'une décision d'audit ou d'un litige.** Le dépôt principal Diadroma n'est pas requis pour exécuter cet outil.

## Utilisation web

Après publication et validation de GitHub Pages (pas encore effectuées), déposer un fichier `proof.json` dans l'interface. Pour un essai local : `python3 -m http.server 8000`, puis ouvrir `http://localhost:8000` et choisir `tests/valid_single.json`. Aucun logiciel propriétaire ni compte Diadroma n'est nécessaire. Le calcul Merkle et le décodage `.ots` ont lieu dans le navigateur ; seuls les identifiants des blocs demandés sont transmis à l'API publique Blockstream. Ne pas confondre l'existence du dépôt GitHub avec une URL Pages active.

## Vérifications réalisées

1. Recalcul de la racine Merkle à partir de `current_hash` et `merkle_proof` (SHA-256 simple sur octets, voisin à gauche/droite, duplication du dernier nœud côté producteur en cas de lot impair).
2. Désérialisation de la preuve OpenTimestamps détachée, vérification que sa racine correspond, puis calcul des digests sur les chemins d'attestation Bitcoin. Une opération non prise en charge entraîne un refus : aucun succès par défaut.
3. Lecture du bloc annoncé par l'attestation auprès de Blockstream : comparaison du digest attesté aux octets inversés avec le `merkle_root` du bloc ; si `anchor_block_height` figure dans le JSON, seules les attestations à cette hauteur sont acceptées.

La preuve confirme le lien cryptographique d'un **hash fourni** avec un bloc selon les informations de l'explorateur. Elle ne prouve pas l'exactitude des données métier à l'origine du hash, leur canonicalisation, leur provenance ni une qualification juridique. Une vérification fondée sur Blockstream dépend de cet explorateur : ce n'est pas une validation autonome du consensus Bitcoin par un nœud personnel. Aucun serveur Diadroma n'est interrogé.

## Format de la preuve

`proof.json` contient `current_hash` (64 caractères hexadécimaux), `merkle_root` (même format), `merkle_proof` (liste d'objets `{"sibling": "...", "position": "left" ou "right"}`), `ots_proof_b64` (preuve OpenTimestamps détachée), `anchor_chain` (`bitcoin`) et, facultativement, `anchor_block_height` (contrôle de cohérence). L'exemple `tests/valid_single.json` est une preuve réelle **mono-feuille**, donc `merkle_proof` y est vide. Il ne valide pas à lui seul un lot industriel multi-feuilles. Ne jamais ajouter de données métier ou d'identifiants de connexion à ce dépôt public.

## Preuves ChainDBoM v2b (moteur de vérification)

`v2b.js` vérifie, dans le navigateur ou sous Node 20+, une preuve ancrée au format `chaindbom-anchored-proof-v2b` : signature Ed25519 du manifeste, lien, inclusion Merkle (style RFC 6962), `anchor_digest` du lot, engagement OpenTimestamps et attestation Bitcoin, et, si la racine du bloc est fournie ou lue, concordance avec le bloc. Chaque contrôle est rapporté séparément ; le niveau atteint va de `INVALIDE` à `BLOC_CONFIRME`. Le champ `status` du document n'est jamais cru. Une clé de signature n'est authentifiée que si une clé ou une empreinte de confiance, obtenue par une autre voie (fiche de clé du client), est fournie.

C'est un portage indépendant du vérificateur Python de référence (`tests/tools/reference/`). Les deux sont comparés sur des vecteurs 100 % synthétiques et déterministes (`tests/vectors/v2b`, régénérés par `tests/tools/gen_v2b_vectors.py`) : `node tests/v2b.test.cjs`. Aucun réseau n'est utilisé par les tests. Validation réelle : deux preuves produites par ChainDBoM avec des données synthétiques, ancrées dans le bloc Bitcoin 970014 (5 octobre 2026), atteignent `BLOC_CONFIRME` dans ce vérificateur comme dans la version Python (`tests/vectors/real`). Cela valide le fonctionnement sur une vraie chaîne, pas une qualification d'audit. Limites : les entiers JSON au-delà de 2^53 sont refusés ; la signature Ed25519 repose sur WebCrypto (navigateurs récents) ; l'interface web pour ce format n'est pas encore branchée.

## Ligne de commande

La variante pour utilisateurs techniques est décrite dans `cli/README.md`. Elle utilise Python et le paquet `opentimestamps`.

## Tests et limites

Depuis la racine du dépôt : `node tests/merkle.test.cjs`, `node tests/ots.test.cjs`, `node tests/height.test.cjs`, `node tests/verify.test.cjs`, puis `python -m unittest discover -s tests -p 'test_cli_height.py' -v`. Les tests réseau du navigateur et de la CLI doivent être réalisés séparément avec le vecteur valide et des variantes altérées. Les tests utilisent notamment un bloc simulé ; ils ne certifient pas l'API publique ni un ancrage multi-feuilles de production. Le code `.ots` couvre les opérations rencontrées dans le vecteur et refuse les opérations inconnues. La CSP HTML limite les connexions navigateur, sans offrir toutes les protections d'un en-tête HTTP dédié. Avant diffusion, contrôler le dépôt et son historique à la recherche de secrets et faire relire le code par un tiers.

## Licence

Code de ce dépôt sous licence MIT (voir `LICENSE`). Cette licence ne s'applique pas au dépôt privé ni aux données métier de Diadroma.
