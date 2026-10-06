# Créer vos clés avec Diadroma — mode d'emploi

Le fichier `diadroma-cles.html` crée vos deux clés (signature et chiffrement) **sur votre ordinateur**. Rien n'est envoyé à Diadroma : vos clés privées, votre phrase secrète et votre sauvegarde ne quittent jamais votre poste. Diadroma n'a aucun moyen de les récupérer si vous les perdez.

## 1. Contrôler le fichier avant de l'ouvrir

Le fichier doit être celui que Diadroma a publié. Comparez son empreinte avec celle affichée sur **deux** endroits : la version publiée du fichier et la page de téléchargement de `www.diadroma.fr` (ou celle que votre contact Diadroma vous a remise directement).

- macOS ou Linux : `shasum -a 256 diadroma-cles.html`
- Windows (PowerShell) : `Get-FileHash diadroma-cles.html -Algorithm SHA256`

Si l'empreinte est différente, **n'ouvrez pas le fichier** et prévenez Diadroma.

## 2. L'ouvrir depuis votre disque

Enregistrez le fichier sur votre ordinateur, puis ouvrez-le par un double-clic (l'adresse commence par `file://`). Ne l'utilisez pas depuis un lien web ni depuis un fichier reçu par une autre voie. Vous pouvez couper la connexion Internet pendant l'opération.

## 3. Suivre les écrans

Créer, noter les 7 mots sur papier, télécharger la sauvegarde, puis **prouver que vous savez la rouvrir** (en retapant les mots depuis votre papier). Vos clés ne vous sont remises qu'après cette preuve.

## 4. Après

- Rangez le **papier** et le **fichier de sauvegarde** à deux endroits séparés, hors ligne. Faites deux copies du fichier, sur deux supports.
- Publiez l'empreinte de votre fiche de clé sur votre propre canal (site, passeport produit, courrier), comme l'indique votre contact Diadroma.
- Ne partagez jamais `signing.pem`, `age-identity.txt` ni la sauvegarde.

## Ce qui n'est pas encore défini

Le changement de clé (rotation) et la révocation d'une clé ne sont pas encore décrits. Contactez Diadroma avant de remplacer ou d'abandonner une clé.

Navigateurs testés : Chrome, Firefox et Safari récents (versions exactes dans `TEST_NAVIGATEURS.md`). Un navigateur qui ne gère pas les algorithmes nécessaires le dit et ne crée rien.
