Copie du vérificateur Python autonome `verify_v2b_anchored_proof.py` du dépôt ChainDBoM (commit 50fd8f6, puis modifications V3/V5 de la revue du 6 octobre 2026 : commit 6659f2a de ChainDBoM, puis V7/V8 : branche `fix/verifier-reference-v7-v8`),
utilisée uniquement comme référence pour générer et contrôler les vecteurs de test. Ne pas la modifier ici :
mettre à jour la copie depuis ChainDBoM puis régénérer les vecteurs.

`v2b_receipt.py` : copie octet pour octet du module de reçus signés (D5) du dépôt ChainDBoM (`src/chaindbom/v2b_receipt.py`), utilisée par
`tests/tools/gen_receipt_vectors.py` pour générer les vecteurs de `tests/vectors/receipt/`. Même règle : ne pas la modifier ici.
