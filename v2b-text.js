/* French texts shown by the interface for the v2b verifier. Kept apart from the logic so that they can be reviewed
 * (and tested for completeness) without touching the cryptography. */
(function (root) {
  'use strict';
  const LEVEL_TEXT = {
    INVALIDE: { title: 'Preuve non valide ou incomplète', cls: 'error',
      text: "Au moins un contrôle essentiel a échoué, ou n'a pas pu être fait. Ne vous fiez pas à ce fichier." },
    INTEGRITE: { title: 'Intégrité vérifiée', cls: 'pending',
      text: "La signature, le lien et l'appartenance au lot sont cohérents. L'antériorité n'est pas encore prouvée : l'ancrage dans une blockchain n'est pas contrôlé." },
    ENGAGEMENT_OTS: { title: 'Engagement déposé, pas encore ancré', cls: 'pending',
      text: "Le lot a été soumis à OpenTimestamps, mais la preuve ne contient pas encore d'attestation Bitcoin. Revenez plus tard avec une preuve mise à jour." },
    ATTESTATION_BITCOIN: { title: 'Attestation Bitcoin présente, bloc non contrôlé', cls: 'unsupported',
      text: "La preuve contient une attestation Bitcoin cohérente, mais le bloc n'a pas été comparé à une source indépendante. Fournissez la racine du bloc ou autorisez la lecture auprès de Blockstream." },
    BLOC_CONFIRME: { title: 'Preuve confirmée par un bloc Bitcoin', cls: 'success',
      text: "Cette empreinte existait au plus tard au moment du bloc Bitcoin indiqué, d'après la racine de bloc fournie ou lue." },
  };
  const CHECK_LABELS = {
    format: 'Structure du fichier',
    manifest_signature: 'Signature Ed25519 du manifeste',
    signing_key_trust: 'Clé de signature authentifiée',
    manifest_link_binding: 'Cohérence manifeste / lien',
    link_hash: 'Recalcul du lien (chaînage client)',
    merkle_inclusion: "Appartenance au lot (preuve d'inclusion)",
    anchor_digest: 'Empreinte du lot (chaînage des lots)',
    ots_commitment: "Engagement OpenTimestamps sur l'empreinte du lot",
    ots_bitcoin_attestation: 'Attestation Bitcoin dans la preuve',
    bitcoin_block: 'Concordance avec le bloc Bitcoin',
    record_hash_vs_dbom: 'Correspondance avec le DBoM en clair',
  };
  const STATUS_TEXT = { pass: 'Réussi', fail: 'Échec', skipped: 'Non vérifié' };
  const STATUS_MARK = { pass: '✔', fail: '✖', skipped: '–' };
  root.ChainDBoMV2bText = { LEVEL_TEXT, CHECK_LABELS, STATUS_TEXT, STATUS_MARK };
})(typeof globalThis !== 'undefined' ? globalThis : this);
