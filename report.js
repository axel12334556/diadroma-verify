/* Rapport de vérification exportable (format "diadroma-verification-report-v1").
 *
 * Le rapport est un compte rendu NON SIGNÉ de ce que ce navigateur a contrôlé. Il n'est pas une preuve et ne la remplace
 * pas : seule la preuve d'origine fait foi, et son empreinte SHA-256 figure dans le rapport pour la retrouver.
 * Il ne contient jamais le contenu du DBoM en clair, ni jeton, ni clé : seulement des identifiants, des empreintes,
 * des dates, les résultats des contrôles et les textes que la page affiche déjà. Logique pure, sans accès au DOM. */
(function (root) {
  'use strict';
  const REPORT_FORMAT = 'diadroma-verification-report-v1';
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const HEX64 = /^[0-9a-f]{64}$/;
  const FINGERPRINT_SOURCES = ['typed', 'key_card', 'device_memory'];
  const STATEMENT = "Rapport non signé, établi par la page de vérification Diadroma à partir du fichier de preuve dont l'empreinte SHA-256 figure ci-dessous. Il n'est pas un certificat : seule la preuve d'origine fait foi, et la vérification peut être rejouée à tout moment à partir d'elle.";
  const LIMITS = [
    "Cette vérification établit qu'une empreinte a été signée par la clé indiquée, rattachée à un lot et, au niveau le plus haut, qu'elle existait au plus tard au moment d'un bloc Bitcoin.",
    "Elle ne dit rien de l'exactitude des données industrielles, ni de l'identité du titulaire de la clé sans empreinte de confiance obtenue auprès du client, ni de la conformité réglementaire.",
    "Le contenu du DBoM n'est pas repris dans ce rapport.",
  ];

  function pick(value, re) { return typeof value === 'string' && re.test(value) ? value : null; }
  function manifestOf(doc) {
    const m = doc && doc.proof_only && doc.proof_only.submission && doc.proof_only.submission.signed_manifest;
    return m && typeof m === 'object' ? m : {};
  }
  async function sha256Hex(bytes) {
    const digest = new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes));
    return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
  }
  function buildReport({ result, proofDoc, proofSha256, inputs, generatedAt }) {
    const T = root.ChainDBoMV2bText;
    if (!result || !Array.isArray(result.checks) || !T || !T.LEVEL_TEXT[result.level]) throw new Error('résultat de vérification inutilisable');
    if (!pick(proofSha256, HEX64)) throw new Error('empreinte du fichier de preuve invalide');
    if (Object.prototype.toString.call(generatedAt) !== '[object Date]' || Number.isNaN(generatedAt.getTime())) throw new Error('date invalide');
    const manifest = manifestOf(proofDoc), anchor = (proofDoc && proofDoc.anchor) || {};
    const given = inputs || {};
    const level = T.levelText(result.level, result.signing_key_authenticated === true, result.failed);
    return {
      format: REPORT_FORMAT,
      format_version: 1,
      generated_at: generatedAt.toISOString(),
      statement: STATEMENT,
      proof: {
        format: 'chaindbom-anchored-proof-v2b',
        file_sha256: proofSha256,
        client_id: pick(manifest.client_id, UUID_RE),
        submission_id: pick(manifest.submission_id, UUID_RE),
        record_hash: pick(manifest.record_hash, HEX64),
        batch_number: Number.isSafeInteger(anchor.batch_number) ? anchor.batch_number : null,
      },
      verdict: {
        level: result.level,
        level_title: level.title,
        level_text: level.text,
        signing_key_authenticated: result.signing_key_authenticated === true,
        dbom_checked: result.dbom_checked === true,
      },
      inputs: {
        trusted_fingerprint_provided: given.trustedFingerprintProvided === true,
        trusted_fingerprint: pick(given.trustedFingerprint, HEX64),
        trusted_fingerprint_source: HEX64.test(given.trustedFingerprint || '') && FINGERPRINT_SOURCES.includes(given.trustedFingerprintSource) ? given.trustedFingerprintSource : null,
        key_card_provided: given.keyCardProvided === true,
        block_root_provided: given.blockRootProvided === true,
        block_read_from_blockstream: given.blockReadFromBlockstream === true,
        dbom_provided: given.dbomProvided === true,
        compromised_since: typeof given.compromisedSince === 'string' && given.compromisedSince.length <= 40 ? given.compromisedSince : null,
      },
      checks: result.checks.map(c => ({
        id: String(c.id), label: T.CHECK_LABELS[c.id] || String(c.id),
        status: c.status, status_text: T.STATUS_TEXT[c.status] || String(c.status), detail: String(c.detail),
      })),
      limits: LIMITS.slice(),
    };
  }
  function reportFileName(report) { return 'rapport-verification-' + report.proof.file_sha256.slice(0, 8) + '.json'; }
  root.ChainDBoMReport = { REPORT_FORMAT, STATEMENT, LIMITS, buildReport, sha256Hex, reportFileName };
})(typeof globalThis !== 'undefined' ? globalThis : this);
