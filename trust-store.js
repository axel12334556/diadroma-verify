// Empreintes de confiance mémorisées sur cet appareil, une par client. Rien ne quitte le navigateur.
// Le stockage peut être absent, plein ou bloqué : chaque accès est protégé et la page fonctionne sans.
(function (root) {
  'use strict';
  const KEY = 'diadroma.trusted-fingerprints.v1';
  const MAX_ENTRIES = 200;
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const HEX64 = /^[0-9a-f]{64}$/;
  const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

  function createTrustStore(storage) {
    function load() {
      try {
        const parsed = JSON.parse(storage.getItem(KEY));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
        const clean = {};
        for (const [clientId, entry] of Object.entries(parsed)) {
          if (UUID_RE.test(clientId) && entry && HEX64.test(entry.fingerprint) && DATE_RE.test(entry.saved_on)) {
            clean[clientId] = { fingerprint: entry.fingerprint, saved_on: entry.saved_on };
          }
        }
        return clean;
      } catch { return {}; }
    }
    function save(map) {
      try { storage.setItem(KEY, JSON.stringify(map)); return true; } catch { return false; }
    }
    return {
      get(clientId) { const entry = load()[clientId]; return entry ? { ...entry } : null; },
      set(clientId, fingerprint, savedOn) {
        if (!UUID_RE.test(clientId) || !HEX64.test(fingerprint) || !DATE_RE.test(savedOn)) return false;
        const map = load();
        if (!map[clientId] && Object.keys(map).length >= MAX_ENTRIES) return false;
        map[clientId] = { fingerprint, saved_on: savedOn };
        return save(map);
      },
      forget(clientId) {
        const map = load();
        if (!map[clientId]) return true;
        delete map[clientId];
        return save(map);
      },
      count() { return Object.keys(load()).length; },
    };
  }
  root.ChainDBoMTrustStore = { createTrustStore, KEY, MAX_ENTRIES };
})(typeof globalThis !== 'undefined' ? globalThis : this);
