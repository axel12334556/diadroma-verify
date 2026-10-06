# Clés de test — NE JAMAIS ENREGISTRER

Tout ce dossier (`signing.pem`, `age-identity.txt`, `client.json`, `key-card.json`, archives de sauvegarde) est **public** :
les clés privées sont dans le dépôt, uniquement pour les tests automatisés.

- Ne jamais utiliser ces clés pour un vrai client, ni les enregistrer sur un serveur (`v2b_admin onboard` refuse leurs empreintes).
- Ne jamais y placer de clé réelle, même temporairement.
- Toute preuve signée avec elles est sans valeur.
