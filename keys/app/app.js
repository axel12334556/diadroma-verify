/* Outil de clés — interface (lot 3). Aucun réseau, aucun stockage navigateur, aucun innerHTML : tout ce qui est affiché est du texte
 * brut. Les clés et la phrase secrète ne vivent que dans des variables de cette page ; « Terminer » recharge la page.
 * Les textes sont dans texts.fr.js ; la cryptographie est dans keys-core.js, keys-backup.js et la bibliothèque age vendorée. */
(function (root) {
  'use strict';
  const T = root.ChainDBoMKeysTexts, K = root.ChainDBoMKeys, B = root.ChainDBoMKeysBackup;
  const doc = root.document;
  const KEY_ID = /^[A-Za-z0-9._-]{1,128}$/;
  const MAX_BACKUP = 256 * 1024, MAX_CARD = 64 * 1024;
  const main = doc.getElementById('app');
  let state = null;   // { keys, ids, passphrase, backup, downloaded }

  // ---- tiny DOM helpers: text only ----
  function h(tag, props, ...kids) {
    const el = doc.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') el.className = value;
      else if (key === 'text') el.textContent = value;
      else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (key === 'value' || key === 'checked' || key === 'disabled' || key === 'hidden') el[key] = value;
      else el.setAttribute(key, value === true ? '' : String(value));
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid.nodeType ? kid : String(kid));
    return el;
  }
  const p = (text, cls) => h('p', { class: cls, text });
  const panel = form => h('section', { class: 'options' }, form);   // the verifier's grey rounded card for forms
  // Messages look like the verifier's: a coloured station before the text (success = mint, error = red, pending = amber ring).
  const BANNER = { ok: 'success', err: 'error', warn: 'pending' };
  const notice = (kind, title, text) => h('div', { class: 'banner ' + BANNER[kind], role: kind === 'err' ? 'alert' : 'status' }, title ? h('strong', { text: title }) : null, text ? h('p', { text }) : null);
  const tick = () => new Promise(resolve => root.setTimeout(resolve, 30));   // let the browser paint before heavy work

  function show(title, ...content) {
    main.replaceChildren(h('h1', { id: 'title', tabindex: '-1', text: title }), ...content);
    const heading = doc.getElementById('title');
    if (heading) heading.focus();
  }
  function download(name, data, type) {
    const url = root.URL.createObjectURL(new root.Blob([data], { type }));
    const link = h('a', { href: url, download: name });
    doc.body.append(link); link.click(); link.remove();
    root.setTimeout(() => root.URL.revokeObjectURL(url), 2000);
  }
  const downloadText = (name, text) => download(name, text, 'text/plain;charset=utf-8');

  function frenchError(error) {
    const E = T.errors, m = String((error && error.message) || '');
    if (error instanceof K.KeysError) return m;
    if (!(error instanceof B.BackupError)) return E.generic;
    if (/not a passphrase-protected age file/.test(m)) return E.wrongFile;
    if (/wrong passphrase/.test(m)) return E.wrongPhrase;
    if (/do not match the published key card/.test(m)) return E.cardMismatch;
    if (/key card/.test(m)) return E.cardInvalid;
    if (/phrase secrète/.test(m)) return m;
    return E.keysBroken;
  }

  // ---- reading what the person chose ----
  async function readFile(input, max) {
    const file = input.files && input.files[0];
    if (!file) throw new Error(T.errors.noFile);
    if (file.size > max) throw new Error(T.errors.fileTooBig);
    return new Uint8Array(await file.arrayBuffer());
  }
  async function readCard(input) {
    if (!input || !input.files || !input.files[0]) return undefined;
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readFile(input, MAX_CARD))); }
    catch (error) { throw new Error(error.message === T.errors.fileTooBig ? error.message : T.errors.cardUnreadable); }
  }

  // ---- reusable pieces ----
  function field(id, label, input, help) { return [h('label', { for: id, text: label }), input, help ? h('p', { class: 'help', text: help }) : null]; }
  function passwordField(id, label, showLabel) {
    const input = h('input', { id, type: 'password', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
    const toggle = h('input', { type: 'checkbox', id: id + '-show', onchange: () => { input.type = toggle.checked ? 'text' : 'password'; } });
    return { input, nodes: [h('label', { for: id, text: label }), input, h('label', { class: 'inline', for: id + '-show' }, toggle, showLabel)] };
  }
  function steps(current) {
    return h('ol', { class: 'steps', 'aria-label': T.create.title },
      T.create.steps.map((text, i) => h('li', { class: i < current ? 'done' : i === current ? 'current' : '', 'aria-current': i === current ? 'step' : null, text })));
  }
  function facts(rows) { return h('dl', { class: 'facts' }, rows.map(([k, v]) => h('div', {}, h('dt', { text: k }), h('dd', { text: v })))); }
  function errorBox() { return h('div', { id: 'problem', 'aria-live': 'assertive' }); }
  function setProblem(text) { const box = doc.getElementById('problem'); box.replaceChildren(text ? notice('err', null, text) : ''); }
  async function busy(button, message, work) {
    const status = doc.getElementById('busy');
    button.disabled = true; status.textContent = message; setProblem('');
    await tick();
    try { return await work(); } finally { button.disabled = false; status.textContent = ''; }
  }
  const busyBox = () => h('p', { id: 'busy', class: 'muted', role: 'status', 'aria-live': 'polite' });
  const dateStamp = d => d.toISOString().slice(0, 10);

  // ---- home ----
  function home() {
    state = null;
    show(T.home.title, p(T.home.intro), notice('warn', null, T.home.warning),
      h('div', { class: 'choices' },
        [['create', createForm], ['verify', () => checkScreen('verify')], ['restore', () => checkScreen('restore')]].map(([key, go]) =>
          h('button', { class: 'choice', type: 'button', 'data-action': key, onclick: go }, h('b', { text: T.home[key] }), h('span', { text: T.home[key + 'Hint'] })))));
  }

  // ---- create: 1. form ----
  function createForm() {
    const now = new Date(), month = now.toISOString().slice(0, 7);
    const responsible = h('input', { type: 'checkbox', id: 'responsible' });
    const signing = h('input', { type: 'text', id: 'signing-id', value: 'sign-' + month, autocomplete: 'off', spellcheck: 'false' });
    const recipient = h('input', { type: 'text', id: 'recipient-id', value: 'age-' + month, autocomplete: 'off', spellcheck: 'false' });
    const submit = h('button', { class: 'primary', type: 'submit', text: T.create.submit });
    const form = h('form', { novalidate: true, onsubmit: async event => {
      event.preventDefault();
      if (!responsible.checked) return setProblem(T.create.responsible);
      if (!KEY_ID.test(signing.value) || !KEY_ID.test(recipient.value)) return setProblem(T.create.idInvalid);
      await busy(submit, T.create.working, async () => {
        try {
          const keys = await K.generateClientKeys({ signingKeyId: signing.value, recipientKeyId: recipient.value, now: new Date() });
          state = { keys, ids: { signing: signing.value, recipient: recipient.value }, passphrase: null, backup: null, downloaded: false };
          root.onbeforeunload = e => { e.preventDefault(); e.returnValue = ''; };   // the keys exist only in this page until delivered
          createPassphrase();
        } catch (error) { setProblem(T.create.failed + frenchError(error)); }
      });
    } },
    h('label', { class: 'inline' }, responsible, T.create.responsible), p(T.create.responsibleHelp, 'help'),
    field('signing-id', T.create.signingId, signing), field('recipient-id', T.create.recipientId, recipient), p(T.create.idHelp, 'help'),
    errorBox(), h('div', { class: 'row' }, submit), busyBox());
    show(T.create.title, steps(0), panel(form));
  }

  // ---- create: 2. passphrase and backup file ----
  function createPassphrase() {
    let own = false;
    const phraseBox = h('div', { class: 'phrase', id: 'phrase', 'aria-live': 'off' });
    const strength = p('', 'help');
    const ownInput = h('input', { type: 'text', id: 'own-phrase', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
    const ownBlock = h('div', { hidden: true }, field('own-phrase', T.passphrase.ownLabel, ownInput, T.passphrase.ownHelp));
    const another = h('button', { class: 'link', type: 'button', text: T.passphrase.another });
    const toggle = h('button', { class: 'link', type: 'button', text: T.passphrase.own });
    const written = h('input', { type: 'checkbox', id: 'written' });
    const confirm = h('input', { type: 'text', id: 'confirm', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
    const submit = h('button', { class: 'primary', type: 'submit', text: T.passphrase.submit });
    const result = h('div', { id: 'backup-result' });
    function draw() {
      const g = B.generatePassphrase();
      state.passphrase = g.passphrase; phraseBox.textContent = g.passphrase; strength.textContent = T.passphrase.strength(g.entropyBits);
    }
    function mode(ownMode) {
      own = ownMode; ownBlock.hidden = !own; phraseBox.hidden = own; another.hidden = own;
      toggle.textContent = own ? T.passphrase.generated : T.passphrase.own;
      if (own) { state.passphrase = null; strength.textContent = ''; ownInput.focus(); } else draw();
      confirm.value = '';
    }
    another.addEventListener('click', draw);
    toggle.addEventListener('click', () => mode(!own));
    const current = () => (own ? ownInput.value : state.passphrase);
    const form = h('form', { novalidate: true, onsubmit: async event => {
      event.preventDefault();
      const phrase = current();
      if (!written.checked || !confirm.value) return setProblem(T.passphrase.confirmNeeded);
      if (confirm.value !== phrase) return setProblem(T.passphrase.mismatch);
      await busy(submit, T.passphrase.working, async () => {
        try {
          const made = await B.backup(state.keys.files, phrase, { now: new Date() });
          state.backup = made; state.passphrase = phrase;
          const name = 'diadroma-sauvegarde-cles-' + state.keys.publicFacts.client_id.slice(0, 8) + '-' + dateStamp(new Date()) + '.age';
          submit.hidden = true;
          for (const el of [written, confirm, ownInput, another, toggle]) el.disabled = true;
          const next = h('button', { class: 'primary', type: 'button', disabled: true, text: T.passphrase.next, onclick: createProof });
          result.replaceChildren(notice('ok', null, T.passphrase.done), h('div', { class: 'row' },
            h('button', { class: 'primary', type: 'button', id: 'download-backup', text: T.passphrase.download, onclick: () => { download(name, made.bytes, 'application/octet-stream'); state.downloaded = true; next.disabled = false; } }), next));
        } catch (error) { setProblem(T.passphrase.failed + frenchError(error)); }
      });
    } },
    p(T.create.createdText), p(T.passphrase.intro), notice('warn', null, T.passphrase.write), phraseBox, strength,
    h('div', { class: 'row' }, another, toggle), ownBlock,
    h('label', { class: 'inline' }, written, T.passphrase.written), field('confirm', T.passphrase.confirmLabel, confirm),
    errorBox(), h('div', { class: 'row' }, submit), busyBox(), result);
    show(T.passphrase.title, steps(1), panel(form));
    draw();
  }

  // ---- create: 3. proof that the backup works ----
  function createProof() {
    state.passphrase = null;   // the person must retype it from the paper: that is part of the proof
    const file = h('input', { type: 'file', id: 'proof-file' });
    const pass = passwordField('proof-phrase', T.proof.phrase, T.proof.show);
    const submit = h('button', { class: 'primary', type: 'submit', text: T.proof.submit });
    const form = h('form', { novalidate: true, onsubmit: async event => {
      event.preventDefault();
      await busy(submit, T.proof.working, async () => {
        try {
          const bytes = await readFile(file, MAX_BACKUP);
          if (!pass.input.value) throw new Error(T.errors.noPhrase);
          await B.restoreTest(bytes, pass.input.value, { card: state.keys.card });
          pass.input.value = '';
          delivery();
        } catch (error) { setProblem((error instanceof B.BackupError || error instanceof K.KeysError ? frenchError(error) + T.errors.hint : error.message)); }
      });
    } }, p(T.proof.intro), field('proof-file', T.proof.file, file), pass.nodes, errorBox(), h('div', { class: 'row' }, submit), busyBox());
    show(T.proof.title, steps(2), panel(form));
  }

  // ---- create: 4. delivery ----
  function delivery() {
    const f = state.keys.publicFacts, ids = state.ids, created = state.keys.card.created_at;
    const backupName = 'diadroma-sauvegarde-cles-' + f.client_id.slice(0, 8) + '-' + dateStamp(new Date()) + '.age';
    const button = (label, name, text) => h('button', { class: 'primary', type: 'button', 'data-file': name, text: T.delivery.download + label, onclick: () => downloadText(name, text) });
    const sheetRows = [[T.delivery.sheetRows.client, f.client_id], [T.delivery.sheetRows.signing, ids.signing], [T.delivery.sheetRows.recipient, ids.recipient],
      [T.delivery.sheetRows.fingerprint, f.signing_key_fingerprint_sha256], [T.delivery.sheetRows.created, created], [T.delivery.sheetRows.backup, backupName]];
    show(T.delivery.title, steps(3), notice('ok', null, T.proof.ok), p(T.delivery.intro),
      h('h2', { text: T.delivery.secretTitle }), notice('warn', null, T.delivery.secretText),
      h('ul', {}, T.delivery.secretFiles.map(([name, what]) => h('li', {}, h('b', { text: name }), ' — ' + what))),
      h('div', { class: 'row' }, T.delivery.secretFiles.map(([name]) => button(name, name, state.keys.files[name]))),
      h('h2', { text: T.delivery.publicTitle }), p(T.delivery.publicText),
      h('div', { class: 'row' }, button(T.delivery.cardFile, T.delivery.cardFile, state.keys.cardText)),
      h('div', { class: 'sheet', id: 'fiche' }, h('h2', { text: T.delivery.sheetTitle + ' — ' + T.brand }), p(T.delivery.sheetText, 'muted'), facts(sheetRows),
        h('ul', { class: 'checklist' }, T.delivery.checklist.map(item => h('li', { text: '☐ ' + item })))),
      h('div', { class: 'row' }, h('button', { class: 'primary', type: 'button', id: 'print', text: T.delivery.print, onclick: () => root.print() })),
      h('div', { class: 'row' }, h('button', { class: 'primary', type: 'button', id: 'finish', text: T.delivery.finish, onclick: finish })), p(T.delivery.finishHelp, 'help'));
  }
  function finish() { state = null; root.onbeforeunload = null; root.location.reload(); }

  // ---- verify / restore ----
  function checkScreen(mode) {
    state = null;
    const restoring = mode === 'restore';
    const file = h('input', { type: 'file', id: 'check-file' });
    const pass = passwordField('check-phrase', T.check.phrase, T.check.show);
    const card = h('input', { type: 'file', id: 'check-card', accept: '.json,application/json' });
    const submit = h('button', { class: 'primary', type: 'submit', text: restoring ? T.check.restoreSubmit : T.check.verifySubmit });
    const out = h('div', { id: 'out' });
    const form = h('form', { novalidate: true, onsubmit: async event => {
      event.preventDefault();
      out.replaceChildren();
      await busy(submit, T.check.working, async () => {
        try {
          const bytes = await readFile(file, MAX_BACKUP);
          if (!pass.input.value) throw new Error(T.errors.noPhrase);
          const options = { card: await readCard(card) };
          const result = restoring ? await B.restore(bytes, pass.input.value, options) : { facts: await B.restoreTest(bytes, pass.input.value, options) };
          pass.input.value = '';
          const x = result.facts;
          out.replaceChildren(...[notice('ok', T.check.okTitle, restoring ? T.check.restoredText : T.check.okText),
            facts([[T.check.facts.client, x.client_id], [T.check.facts.fingerprint, x.signing_key_fingerprint_sha256], [T.check.facts.recipient, x.recipient],
              [T.check.facts.created, x.backup_created_at], [T.check.facts.card, x.key_card_matched ? T.check.cardYes : T.check.cardNo]]),
            restoring ? h('div', { class: 'row' }, T.delivery.secretFiles.map(([name]) => h('button', { class: 'primary', type: 'button', 'data-file': name, text: T.delivery.download + name, onclick: () => downloadText(name, result.files[name]) }))) : null].filter(Boolean));
        } catch (error) { setProblem(error instanceof B.BackupError || error instanceof K.KeysError ? frenchError(error) + T.errors.hint : error.message); }
      });
    } }, p(T.check.intro), field('check-file', T.check.file, file), pass.nodes, field('check-card', T.check.card, card, T.check.cardHelp),
    errorBox(), h('div', { class: 'row' }, submit), busyBox(), out,
    h('div', { class: 'row' }, h('button', { class: 'link', type: 'button', text: T.check.back, onclick: home })));
    show(restoring ? T.check.restoreTitle : T.check.verifyTitle, panel(form));
  }

  // ---- start: can this browser do it at all? ----
  async function supported() {
    try {
      const s = root.crypto.subtle;
      await s.generateKey({ name: 'Ed25519' }, false, ['sign']);
      await s.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      return !!root.AgeEncryption;
    } catch { return false; }
  }
  let started = false;
  async function start() {
    if (started) return;
    started = true;
    doc.title = T.title;
    doc.getElementById('brand').textContent = T.brand;
    doc.getElementById('tagline').textContent = T.tagline + ' — ' + T.version;
    if (root.location.protocol !== 'file:') main.before(h('div', { class: 'container notes' }, notice('warn', null, T.hostedWarning)));
    doc.getElementById('footer').replaceChildren(p(T.footer), p(T.privateTip));
    if (!await supported()) { show(T.home.title, notice('err', null, T.unsupported)); return; }
    home();
  }
  root.addEventListener('DOMContentLoaded', start);
  if (doc.readyState !== 'loading') start();
})(typeof globalThis !== 'undefined' ? globalThis : this);
