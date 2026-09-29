# Vérification avancée en CLI

Depuis la racine du dépôt :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python cli/verify_anchor.py --input tests/valid_single.json
echo $?
```

Le code de sortie est 0 seulement si une attestation Bitcoin correspond à la preuve et au bloc consulté ; 1 sinon. La CLI ne contacte aucun serveur Diadroma, mais utilise l'API publique Blockstream pour les données du bloc. Pour automatiser la vérification sans dépendre de cet explorateur, il faudrait remplacer cette source par un nœud Bitcoin contrôlé par le vérificateur. Ce dépôt ne réalise pas cette étape. Ne placez aucune donnée métier ou secret dans `proof.json`.
