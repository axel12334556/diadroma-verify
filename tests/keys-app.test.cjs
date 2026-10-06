// The key tool as a person uses it: the single built file, opened from disk (file://) in a real browser, driven like a user.
// Every file it hands out is then checked by independent code (the modules in Node, the age program). Synthetic data only.
// Needs a Chromium and playwright(-core): with REQUIRE_BROWSER=1 (CI) their absence is a failure, never a silent skip.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const required = process.env.REQUIRE_BROWSER === '1';
let playwright = null;
for (const name of [process.env.PLAYWRIGHT_MODULE, 'playwright', 'playwright-core', '/opt/node22/lib/node_modules/playwright'].filter(Boolean)) {
  try { playwright = require(name); break; } catch { /* next */ }
}
if (!playwright) { if (required) { console.error('playwright required (REQUIRE_BROWSER=1)'); process.exit(1); } console.log('playwright absent : test du navigateur ignoré (REQUIRE_BROWSER=1 le rend obligatoire)'); process.exit(0); }
const hasAge = spawnSync('age-keygen', ['--version']).status === 0;
if (!hasAge && required) { console.error('age CLI required (REQUIRE_BROWSER=1)'); process.exit(1); }

// ---- independent checkers (the modules, in Node) ----
const ctx = vm.createContext({ crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt, Promise, Date, atob, btoa,
  setTimeout, clearTimeout, queueMicrotask, ReadableStream, WritableStream, TransformStream, Blob, Response, structuredClone });
for (const file of ['keys/keys-core.js', 'keys/wordlist.js', 'v2b.js', 'keys/vendor/age-encryption.bundle.js', 'keys/keys-backup.js']) vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
const B = ctx.ChainDBoMKeysBackup, V2B = ctx.ChainDBoMV2b;

const built = path.resolve('keys/dist/diadroma-cles.html');
const url = 'file://' + built;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-app-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));
const vector = name => path.resolve('tests/vectors/keys', name);
const PYTHON_PASSPHRASE = 'synthetic test passphrase 7F3A-91C2';

(async () => {
  // 0. The built file is exactly what the sources produce, and its published fingerprint is its real SHA-256.
  assert.equal(spawnSync('node', ['keys/build-app.js', '--check'], { encoding: 'utf8' }).status, 0, 'keys/dist is stale: run node keys/build-app.js');
  const html = fs.readFileSync(built);
  assert.equal(fs.readFileSync(built + '.sha256', 'utf8'), createHash('sha256').update(html).digest('hex') + '  diadroma-cles.html\n');
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html.toString('utf8'))[1];
  for (const directive of ["default-src 'none'", "connect-src 'none'", "img-src 'none'", "base-uri 'none'", "form-action 'none'", "object-src 'none'", "frame-src 'none'"]) assert.ok(csp.includes(directive), directive);
  assert.ok(!/unsafe-inline|unsafe-eval|https?:/.test(csp), 'CSP must not weaken or name an origin');
  const markup = html.toString('utf8').replace(/<script>[\s\S]*?<\/script>/g, '<script></script>').replace(/<style>[\s\S]*?<\/style>/g, '<style></style>').replace(/ xmlns="http:\/\/www\.w3\.org\/2000\/svg"/g, '');   // an XML namespace name is not a resource
  assert.ok(!/<script[^>]+src=|<link|<img|<iframe|<object|<embed|<form|@import|https?:/i.test(markup), 'no external resource in the page markup');
  assert.ok(!/@import|url\(\s*['"]?(https?:|\/\/)/i.test(fs.readFileSync('keys/app/app.css', 'utf8')), 'no external resource in the style sheet');

  // 0b. The interface code never builds HTML from strings, never stores, never logs.
  const appCode = fs.readFileSync('keys/app/app.js', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\b|new Function|localStorage|sessionStorage|indexedDB|document\.cookie|console\.|fetch\(|XMLHttpRequest|sendBeacon|WebSocket/.test(appCode), 'forbidden construct in app.js');

  const launch = { headless: true };
  if (process.env.CHROME_PATH) launch.executablePath = process.env.CHROME_PATH;
  const browser = await playwright.chromium.launch(launch);
  try {
    const open = async (extra) => {
      const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: 'block', locale: 'fr-FR' });
      const requests = [];
      await context.route('**/*', route => { requests.push(route.request().url()); return /^(file|blob|data):/.test(route.request().url()) || (extra && extra.allow && extra.allow(route.request().url())) ? route.continue() : route.abort(); });
      const page = await context.newPage();
      const problems = [];
      page.on('pageerror', e => problems.push('pageerror: ' + e.message));
      page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
      page.setDefaultTimeout(180000);
      return { context, page, requests, problems };
    };
    const saveDownload = async (page, clickSelector, name) => {
      const [download] = await Promise.all([page.waitForEvent('download'), page.click(clickSelector)]);
      const file = path.join(tmp, name); await download.saveAs(file); return { file, suggested: download.suggestedFilename() };
    };
    const problemText = async page => (await page.locator('#problem').innerText()).trim();
    // The look is the verifier's: messages are "banners" with a coloured station, no dashed frame, no orange side stripe.
    const checkLook = async (page, where) => {
      const bad = await page.evaluate(() => [...document.querySelectorAll('body *')].filter(el => {
        const c = getComputedStyle(el);
        return ['Top', 'Right', 'Bottom', 'Left'].some(side => c['border' + side + 'Style'] === 'dashed' || (c['border' + side + 'Style'] === 'solid' && parseFloat(c['border' + side + 'Width']) >= 4));
      }).map(el => el.tagName + '.' + el.className));
      assert.deepEqual(bad, [], where + ': dashed or thick-stripe border');
      assert.equal(await page.locator('.notice').count(), 0, where + ': old notice style');
      assert.equal(await page.locator('.fond .chemin').count(), 2, where + ': background routes');
      assert.equal(await page.locator('header.top .logo').count(), 1, where + ': header logo');
    };
    // Messages of the asynchronous steps appear after a short busy state: wait for them instead of racing.
    const expectProblem = async (page, regex) => {
      await page.waitForFunction(([source, flags]) => new RegExp(source, flags).test(document.querySelector('#problem').innerText), [regex.source, regex.flags]);
      assert.match(await problemText(page), regex);
    };

    // 1. Full creation flow.
    {
      const { context, page, requests, problems } = await open();
      await page.goto(url);
      await page.waitForSelector('[data-action=create]');
      assert.equal(await page.title(), 'Diadroma — Mes clés');
      await checkLook(page, 'home');
      await page.click('[data-action=create]');
      // validation first
      await page.click('button[type=submit]');
      assert.match(await problemText(page), /personne responsable/);
      await page.check('#responsible'); await page.fill('#signing-id', 'bad id!'); await page.click('button[type=submit]');
      assert.match(await problemText(page), /n.est pas valide/);
      assert.match(await page.inputValue('#recipient-id'), /^age-\d{4}-\d{2}$/);
      await page.fill('#signing-id', 'sign-2026-10'); await page.fill('#recipient-id', 'age-2026-10'); await page.click('button[type=submit]');
      await page.waitForSelector('#phrase');
      await checkLook(page, 'passphrase');
      // keys exist but nothing secret is offered yet
      assert.equal(await page.locator('[data-file]').count(), 0);
      const phrase = (await page.locator('#phrase').innerText()).trim();
      assert.equal(phrase.split('-').length, 7);
      assert.ok(phrase.split('-').every(w => ctx.ChainDBoMWordlist.includes(w)));
      await page.click('text=Tirer une autre phrase');
      const fresh = (await page.locator('#phrase').innerText()).trim(); assert.notEqual(fresh, phrase);
      await page.click('button[type=submit]');
      assert.match(await problemText(page), /Cochez la case/);
      await page.check('#written'); await page.fill('#confirm', fresh + 'x'); await page.click('button[type=submit]');
      assert.match(await problemText(page), /ne correspond pas/);
      await page.fill('#confirm', fresh); await page.click('button[type=submit]');
      await page.waitForSelector('#download-backup');
      assert.equal(await page.locator('[data-file]').count(), 0);
      assert.ok(await page.locator('text=Passer à la preuve').isDisabled(), 'cannot skip the download');
      const backup = await saveDownload(page, '#download-backup', 'backup-1.age');
      assert.match(backup.suggested, /^diadroma-sauvegarde-cles-[0-9a-f]{8}-\d{4}-\d{2}-\d{2}\.age$/);
      await page.click('text=Passer à la preuve');
      await page.waitForSelector('#proof-file');
      assert.equal(await page.locator('#phrase').count(), 0, 'the phrase is no longer displayed: it must be retyped from paper');
      // the proof refuses everything that is not the real backup with the real phrase
      await page.click('button[type=submit]');
      await expectProblem(page, /Choisissez d.abord un fichier/);
      await page.setInputFiles('#proof-file', backup.file);
      await page.click('button[type=submit]');
      await expectProblem(page, /Tapez votre phrase/);
      await page.fill('#proof-phrase', fresh + 'x'); await page.click('button[type=submit]');
      await expectProblem(page, /phrase secrète incorrecte/);
      assert.equal(await page.locator('[data-file]').count(), 0, 'still no keys after a failed proof');
      fs.writeFileSync(path.join(tmp, 'not-a-backup.age'), 'hello, I am not a backup');
      await page.setInputFiles('#proof-file', path.join(tmp, 'not-a-backup.age')); await page.fill('#proof-phrase', fresh); await page.click('button[type=submit]');
      await expectProblem(page, /pas une sauvegarde/);
      await page.setInputFiles('#proof-file', backup.file); await page.click('#proof-phrase-show'); assert.equal(await page.getAttribute('#proof-phrase', 'type'), 'text');
      await page.click('button[type=submit]');
      await page.waitForSelector('#finish');
      await checkLook(page, 'delivery');
      // delivery: every file, then independent checks
      const got = {};
      for (const name of ['client.json', 'signing.pem', 'age-identity.txt', 'key-card.json']) got[name] = fs.readFileSync((await saveDownload(page, `[data-file="${name}"]`, 'got-' + name)).file, 'utf8');
      const client = JSON.parse(got['client.json']), card = JSON.parse(got['key-card.json']);
      assert.equal(client.signing_key_id, 'sign-2026-10'); assert.equal(client.recipient_key_id, 'age-2026-10');
      const facts = await V2B.checkKeyCard(card);
      assert.equal(facts.client_id, client.client_id); assert.equal(facts.self_signature, 'verified');
      const backupBytes = new Uint8Array(fs.readFileSync(backup.file));
      const verdict = await B.restoreTest(backupBytes, fresh, { card: JSON.parse(JSON.stringify(card)) });
      assert.equal(verdict.key_card_matched, true);
      const restored = await B.restore(backupBytes, fresh);
      for (const name of ['client.json', 'signing.pem', 'age-identity.txt']) assert.equal(restored.files[name], got[name], name + ' in the backup is the delivered file');
      if (hasAge) {
        const identityFile = path.join(tmp, 'identity.txt'); fs.writeFileSync(identityFile, got['age-identity.txt'], { mode: 0o600 });
        assert.equal(execFileSync('age-keygen', ['-y', identityFile]).toString().trim(), client.age_recipient);
      }
      // what the page shows never contains a secret, and the printed sheet holds public facts only
      const pageText = await page.locator('body').innerText();
      for (const secret of ['AGE-SECRET-KEY', 'PRIVATE KEY', fresh, got['age-identity.txt'].split('\n').find(l => l.startsWith('AGE-SECRET-KEY'))]) assert.ok(!pageText.includes(secret), 'secret displayed');
      const sheet = await page.locator('#fiche').innerText();
      assert.ok(sheet.includes(client.client_id) && sheet.includes(facts.fingerprint_sha256) && sheet.includes('sign-2026-10'));
      await page.emulateMedia({ media: 'print' });
      assert.equal(await page.evaluate(() => getComputedStyle(document.getElementById('title')).visibility), 'hidden');
      assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('#fiche dd')).visibility), 'visible');
      await page.emulateMedia({ media: 'screen' });
      // nothing kept in the browser, nothing sent anywhere
      const stored = await page.evaluate(async () => ({ local: localStorage.length, session: sessionStorage.length, cookie: document.cookie, dbs: (await indexedDB.databases()).length }));
      assert.deepEqual(stored, { local: 0, session: 0, cookie: '', dbs: 0 });
      assert.ok(requests.every(u => /^(file|blob|data):/.test(u)), 'unexpected request: ' + requests.filter(u => !/^(file|blob|data):/.test(u)));
      // the CSP really blocks a connection and injected code
      const blocked = await page.evaluate(async () => {
        const out = {};
        try { await fetch('https://example.com/'); out.fetch = 'allowed'; } catch { out.fetch = 'blocked'; }
        window.__injected = false; const s = document.createElement('script'); s.textContent = 'window.__injected = true'; document.head.append(s); out.script = window.__injected ? 'ran' : 'blocked';
        return out;
      });
      assert.deepEqual(blocked, { fetch: 'blocked', script: 'blocked' });
      // finishing reloads the page: back to the start, no state
      await Promise.all([page.waitForNavigation(), page.click('#finish')]);
      await page.waitForSelector('[data-action=create]');
      assert.equal(await page.locator('[data-file]').count(), 0);
      assert.deepEqual(problems.filter(p => !/Refused to (execute inline script|connect|apply)|Content Security Policy|Failed to load resource|example\.com/.test(p)), []);
      await context.close();
    }

    // 2. Verify and restore a backup made by the ChainDBoM Python tool.
    {
      const { context, page, problems } = await open();
      await page.goto(url); await page.click('[data-action=verify]');
      await page.setInputFiles('#check-file', vector('backup-python.age')); await page.fill('#check-phrase', PYTHON_PASSPHRASE);
      await page.setInputFiles('#check-card', vector('key-card.json')); await page.click('button[type=submit]');
      await page.waitForSelector('#out .banner.success');
      const text = await page.locator('#out').innerText();
      assert.ok(!/\bnull\b|undefined/.test(text), 'stray null in the result');
      await checkLook(page, 'verify');
      assert.ok(text.includes('10111213-1415-4617-9819-1a1b1c1d1e1f') && text.includes('65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8') && text.includes('correspond'));
      assert.equal(await page.locator('[data-file]').count(), 0, 'verifying never hands out keys');
      // wrong phrase, wrong card, unreadable card
      await page.fill('#check-phrase', PYTHON_PASSPHRASE + '!'); await page.click('button[type=submit]');
      await expectProblem(page, /phrase secrète incorrecte/);
      assert.equal(await page.locator('#out .banner.success').count(), 0);
      await page.fill('#check-phrase', PYTHON_PASSPHRASE);
      const otherCard = JSON.parse(fs.readFileSync(vector('key-card.json'), 'utf8')); otherCard.client_id = otherCard.client_id.replace(/^1/, '2');
      fs.writeFileSync(path.join(tmp, 'other-card.json'), JSON.stringify(otherCard));
      await page.setInputFiles('#check-card', path.join(tmp, 'other-card.json')); await page.click('button[type=submit]');
      await expectProblem(page, /fiche de clé/);
      fs.writeFileSync(path.join(tmp, 'broken-card.json'), '{ nope');
      await page.setInputFiles('#check-card', path.join(tmp, 'broken-card.json')); await page.click('button[type=submit]');
      await expectProblem(page, /ne peut pas être lue/);
      await context.close();
      const second = await open();
      await second.page.goto(url); await second.page.click('[data-action=restore]');
      await second.page.setInputFiles('#check-file', vector('backup-python.age')); await second.page.fill('#check-phrase', PYTHON_PASSPHRASE); await second.page.click('button[type=submit]');
      await second.page.waitForSelector('[data-file]');
      for (const name of ['client.json', 'signing.pem', 'age-identity.txt']) {
        const saved = await saveDownload(second.page, `[data-file="${name}"]`, 'restored-' + name);
        assert.equal(fs.readFileSync(saved.file, 'utf8'), fs.readFileSync(vector(name), 'utf8'), name);
        assert.equal(saved.suggested, name);
      }
      await second.context.close();
      assert.deepEqual(problems, []);
    }

    // 3. Served by a website: the page says so (the file from disk is the recommended way).
    {
      const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const origin = `http://127.0.0.1:${server.address().port}`;
      const { context, page } = await open({ allow: u => u.startsWith(origin) });
      await page.goto(origin + '/'); await page.waitForSelector('[data-action=create]');
      assert.match(await page.locator('body').innerText(), /affichée depuis un site web/);
      await context.close(); server.close();
    }

    // 4. A browser that cannot do Ed25519 / X25519: a clear refusal and nothing to click.
    {
      const { context, page } = await open();
      await page.addInitScript(() => { const original = SubtleCrypto.prototype.generateKey; SubtleCrypto.prototype.generateKey = function (algorithm, ...rest) { if (algorithm && algorithm.name === 'X25519') return Promise.reject(new Error('unsupported')); return original.call(this, algorithm, ...rest); }; });
      await page.goto(url); await page.waitForSelector('.banner.error');
      assert.match(await page.locator('main').innerText(), /ne sait pas créer les clés/);
      assert.equal(await page.locator('[data-action]').count(), 0);
      await context.close();
    }

    // 5. A narrow phone screen: no horizontal scroll.
    {
      const { context, page } = await open();
      await page.setViewportSize({ width: 360, height: 700 }); await page.goto(url); await page.waitForSelector('[data-action=create]');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'horizontal overflow');
      await page.click('[data-action=create]');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'horizontal overflow');
      await context.close();
    }
  } finally { await browser.close(); }
  console.log('outil de clés dans un vrai navigateur (file://) : création, sauvegarde, preuve, livraison, vérification, restauration, CSP et absence de réseau vérifiés');
})().catch(e => { console.error(e); process.exit(1); });
