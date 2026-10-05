# Vraies preuves ancrées (données 100 % synthétiques)

`proof-1.json` et `proof-2.json` sont les deux preuves du lot n° 80 produites le 5 octobre 2026 par la
validation réelle de ChainDBoM (`scripts/real_ots_validation.py`) : deux soumissions synthétiques chaînées,
un lot, un vrai engagement OpenTimestamps, une vraie attestation Bitcoin.

- Bloc Bitcoin : hauteur 970014, empreinte `00000000000000000001c5746c459525f60ccc63eb57491ab9b714bcd78d8b4e`,
  racine de Merkle `9a434ade6091a562799a9cc4afd6427fa3333f2fec9058586ed6f0885dff2e05`, daté du 2026-10-05 (UTC)
  (valeurs relevées sur l'API publique de Blockstream, et retrouvées à l'identique par calcul depuis la preuve).
- Les fichiers ne contiennent que des identifiants, des empreintes, une signature et une clé publique synthétiques :
  jamais de donnée métier.
- Ils servent de vecteurs de non-régression hors ligne : `node tests/v2b-real.test.cjs` et
  `python tests/tools/verify_real_vectors.py`. Ne pas les modifier.
