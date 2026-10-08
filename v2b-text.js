/* French texts shown by the interface for the v2b verifier. Kept apart from the logic so that they can be reviewed
 * (and tested for completeness) without touching the cryptography. */
(function (root) {
  'use strict';
  const LEVEL_TEXT = {
    INVALIDE: { title: 'Preuve non valide ou incomplète', cls: 'error',
      text: "Au moins un contrôle essentiel a échoué, ou n'a pas pu être fait. Ne vous fiez pas à ce fichier." },
    INTEGRITE: { title: 'Intégrité vérifiée', cls: 'pending',
      text: "La signature, le lien et l'appartenance au lot sont cohérents. L'antériorité n'est pas encore prouvée : l'ancrage dans une blockchain n'est pas contrôlé." },
    ENGAGEMENT_OTS: { title: 'Engagement OpenTimestamps déclaré, non vérifié', cls: 'pending',
      text: "Le fichier contient une preuve OpenTimestamps qui porte sur l'empreinte du lot, sans attestation Bitcoin. Rien ne montre qu'elle a été soumise à un calendrier : un fichier fabriqué hors ligne obtient le même résultat. Ce niveau n'établit aucune antériorité." },
    ATTESTATION_BITCOIN: { title: 'Attestation Bitcoin déclarée, bloc non contrôlé', cls: 'unsupported',
      text: "Le fichier déclare une attestation Bitcoin, mais elle n'est pas confrontée au bloc : une attestation inventée obtient le même résultat. Aucune antériorité n'est établie. Fournissez la racine du bloc ou autorisez la lecture auprès de Blockstream." },
    BLOC_CONFIRME: { title: 'Preuve confirmée par un bloc Bitcoin', cls: 'success',
      text: "Cette empreinte existait au plus tard au moment du bloc Bitcoin indiqué, d'après la racine de bloc fournie ou lue." },
  };
  // V4: the green level needs an authenticated signing key. A confirmed block with an unknown author only proves that
  // SOMEONE's file existed by then (anyone can sign a manifest carrying a real client_id and timestamp it themselves).
  const UNAUTHENTICATED_BLOC = { title: 'Antériorité confirmée, auteur non authentifié', cls: 'unsupported',
    text: "Cette empreinte existait au plus tard au moment du bloc Bitcoin indiqué, mais rien n'établit qui l'a signée : sans l'empreinte de confiance obtenue auprès du client (sa fiche de clé), un tiers a pu fabriquer ce fichier avec sa propre clé. Ne l'attribuez pas au client." };
  // R4: when the ONLY failed check is the key-revocation one, the proof is not forged: it is doubtful (the key may already have
  // been compromised when it was anchored, or the block time is unknown). The level stays INVALIDE, the wording says so.
  const DOUBTFUL = { title: 'Preuve douteuse', cls: 'unsupported',
    text: "Le fichier est cohérent par ailleurs, mais avec la date de compromission saisie, rien n'établit que la clé n'était pas déjà compromise quand la preuve a été ancrée (ou l'heure du bloc Bitcoin est inconnue). Ce n'est pas la preuve d'une falsification : la preuve n'est simplement pas retenue. Voir le détail du contrôle « Ancrage antérieur à la compromission de la clé »." };
  function levelText(level, keyAuthenticated, failed) {
    if (level === 'INVALIDE' && Array.isArray(failed) && failed.length > 0 && failed.every(id => id === 'key_revocation')) return DOUBTFUL;
    return level === 'BLOC_CONFIRME' && !keyAuthenticated ? UNAUTHENTICATED_BLOC : LEVEL_TEXT[level];
  }
  const CHECK_LABELS = {
    format: 'Structure du fichier',
    manifest_signature: 'Signature Ed25519 du manifeste',
    signing_key_trust: 'Clé de signature authentifiée',
    manifest_link_binding: 'Cohérence manifeste / lien',
    link_hash: 'Recalcul du lien (chaînage client)',
    merkle_inclusion: "Appartenance au lot (preuve d'inclusion)",
    anchor_digest: 'Empreinte du lot (chaînage des lots)',
    ots_commitment: "Engagement OpenTimestamps sur l'empreinte du lot",
    ots_bitcoin_attestation: 'Attestation Bitcoin déclarée dans la preuve',
    bitcoin_block: 'Concordance avec le bloc Bitcoin',
    key_revocation: 'Ancrage antérieur à la compromission de la clé',
    record_hash_vs_dbom: 'Correspondance avec le DBoM en clair',
  };
  const STATUS_TEXT = { pass: 'Réussi', fail: 'Échec', skipped: 'Non vérifié' };
  const STATUS_MARK = { pass: '✔', fail: '✖', skipped: '–' };
  root.ChainDBoMV2bText = { LEVEL_TEXT, levelText, CHECK_LABELS, STATUS_TEXT, STATUS_MARK };
})(typeof globalThis !== 'undefined' ? globalThis : this);
