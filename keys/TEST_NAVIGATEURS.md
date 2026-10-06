# Test à la main de l'outil de clés dans les navigateurs

Le test automatique (`tests/keys-app.test.cjs`) ne couvre que Chromium. Safari et Firefox sont à tester à la main, **page ouverte depuis
le disque** (double-clic sur le fichier, adresse en `file://`). Données de test uniquement : n'utilisez jamais de vraies clés.

Fichier : `keys/dist/diadroma-cles.html`. Contrôle préalable : `shasum -a 256 -c keys/dist/diadroma-cles.html.sha256` (dans `keys/dist`).

Pour chaque navigateur (Safari, Firefox, Chrome), dans une fenêtre privée :

1. La page s'affiche avec trois boutons (aucun message rouge « ne sait pas créer les clés »).
2. **Créer mes clés** : coche, noms par défaut, « Créer mes clés » → passe à la phrase secrète.
3. Noter la phrase, cocher, la retaper, « Créer le fichier de sauvegarde » (quelques secondes) → « Télécharger le fichier de sauvegarde » :
   le fichier arrive dans les téléchargements.
4. « Passer à la preuve » → choisir ce fichier, retaper la phrase → la livraison s'affiche.
5. Télécharger les 4 fichiers (`client.json`, `signing.pem`, `age-identity.txt`, `key-card.json`) : ils arrivent avec ces noms exacts.
6. « Imprimer cette fiche » → l'aperçu d'impression ne montre que la fiche (aucune clé, aucune phrase).
7. « Terminer et effacer » → retour à l'accueil.
8. **Vérifier ma sauvegarde** avec le fichier de l'étape 3 et la phrase : « Sauvegarde valide ».
9. Dans un terminal, avec les fichiers téléchargés : `age -d <sauvegarde>` (taper la phrase) `| tar -xf -` doit extraire 4 fichiers.

À noter pour chaque navigateur : version, système, et tout comportement inattendu (téléchargement bloqué, message d'erreur, page blanche).
Résultat attendu à confirmer en particulier : Safari doit gérer Ed25519 et X25519 dans WebCrypto (version récente requise).

## Résultats

| Date | Navigateur | Version | Système | Résultat |
| --- | --- | --- | --- | --- |
| 2026-10-06 | Safari | 26.2 | macOS 15.7.9 | parcours complet validé à la main |
| 2026-10-06 | Firefox | 134.0.1 | macOS 15.7.9 | parcours complet validé à la main |

Les versions des navigateurs ont été relevées après coup, telles que communiquées par la personne qui a fait le test. Le comportement
de Safari sur Ed25519 et X25519 dépend de sa version, donc la version précise compte pour la documentation destinée aux clients.
Un test automatique tourne en CI sur Chromium seulement ; refaire ce parcours à la main à chaque changement de l'interface ou de la
bibliothèque age.
