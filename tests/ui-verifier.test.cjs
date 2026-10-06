// The verification page as a person uses it (Chromium, file://, Blockstream simulated, synthetic files only):
//  V1: an old-format proof is never shown as confirmed (no signature) and makes no request unless the box is ticked;
//  V2: when two files are dropped one after the other, only the last one's verdict and SHA-256 are ever shown.
// Needs playwright(-core) and a Chromium: with REQUIRE_BROWSER=1 (CI) their absence is a failure, never a silent skip.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');

const required = process.env.REQUIRE_BROWSER === '1';
let playwright = null;
for (const name of [process.env.PLAYWRIGHT_MODULE, 'playwright', 'playwright-core', '/opt/node22/lib/node_modules/playwright'].filter(Boolean)) {
  try { playwright = require(name); break; } catch { /* next */ }
}
if (!playwright) { if (required) { console.error('playwright required (REQUIRE_BROWSER=1)'); process.exit(1); } console.log('playwright absent : test de la page ignoré (REQUIRE_BROWSER=1 le rend obligatoire)'); process.exit(0); }

const page_url = 'file://' + path.resolve('index.html');
const sha = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const REAL = path.resolve('tests/vectors/real/proof-1.json');
const OTHER = path.resolve('tests/vectors/v2b/valid_5_leaves.json');
const LEGACY = path.resolve('tests/valid_single.json');
const REAL_BLOCK = { hash: '00000000000000000001c5746c459525f60ccc63eb57491ab9b714bcd78d8b4e', height: 970014,
  merkle_root: '9a434ade6091a562799a9cc4afd6427fa3333f2fec9058586ed6f0885dff2e05' };
const OLD_BLOCK = { hash: 'ab'.repeat(32), height: 969034, merkle_root: 'b7489a9c2992ab3d84a74bc0841c6b0aa183c262edf92bd6d9c23299a4883b67' };

(async () => {
  const launch = { headless: true };
  if (process.env.CHROME_PATH) launch.executablePath = process.env.CHROME_PATH;
  const browser = await playwright.chromium.launch(launch);
  try {
    const open = async delayMs => {
      const context = await browser.newContext({ serviceWorkers: 'block', locale: 'fr-FR' });
      const blockstream = [], problems = [];
      await context.route('**/*', async route => {
        const url = route.request().url();
        if (/^(file|blob|data):/.test(url)) return route.continue();
        if (!url.startsWith('https://blockstream.info/api/')) return route.abort();
        blockstream.push(url);
        const known = [REAL_BLOCK, OLD_BLOCK].find(b => url.endsWith('/block-height/' + b.height) || url.endsWith('/block/' + b.hash));
        if (!known) return route.fulfill({ status: 404, body: '' });
        if (delayMs) await new Promise(resolve => setTimeout(resolve, delayMs));
        if (url.endsWith('/block-height/' + known.height)) return route.fulfill({ status: 200, body: known.hash });
        return route.fulfill({ status: 200, contentType: 'application/json',
          body: JSON.stringify({ id: known.hash, height: known.height, merkle_root: known.merkle_root, timestamp: 1790000000 }) });
      });
      const page = await context.newPage();
      page.on('pageerror', e => problems.push('pageerror: ' + e.message));
      page.setDefaultTimeout(30000);
      await page.goto(page_url);
      return { context, page, blockstream, problems };
    };
    const drop = (page, file) => page.setInputFiles('#fileInput', file);

    // V1 without consent: no request, never green, honest wording.
    {
      const { context, page, blockstream, problems } = await open(0);
      await drop(page, LEGACY);
      await page.waitForFunction(() => { const r = document.getElementById('result'); return !r.hidden && !/en cours/.test(r.textContent); });
      assert.equal(await page.locator('#result').getAttribute('class'), 'unsupported');
      assert.match(await page.locator('#result').innerText(), /Ancien format, sans signature/);
      assert.equal(blockstream.length, 0, 'no request without the box');
      // V1 with consent: the block is read, and the result is "timestamp only", never "success".
      await page.check('#optFetchBlock');
      await page.click('#rerun');
      await page.waitForFunction(() => /Horodatage seul/.test(document.getElementById('result').textContent));
      assert.equal(await page.locator('#result').getAttribute('class'), 'unsigned');
      assert.match(await page.locator('#result').innerText(), /aucune signature/);
      assert.ok(blockstream.length > 0 && blockstream.every(u => u.startsWith('https://blockstream.info/api/')));
      assert.deepEqual(problems, []);
      await context.close();
    }

    // V2: a slow verification of the first file must not show its verdict under the second file.
    {
      const { context, page, problems } = await open(2500);
      await drop(page, REAL); // the options only appear once a proof is dropped
      await page.waitForSelector('#v2bReport .banner');
      await page.check('#optFetchBlock');
      await page.click('#rerun'); // would reach BLOC_CONFIRME once Blockstream answers (2.5 s per request)
      await page.waitForFunction(() => /en cours/.test(document.getElementById('result').textContent));
      await drop(page, OTHER);
      await page.waitForSelector('#v2bReport .banner');
      await page.waitForTimeout(7000); // long enough for the first run to finish and (wrongly) overwrite
      const banner = await page.locator('#v2bReport .banner strong').innerText();
      const report = await page.locator('#reportMeta').textContent();
      assert.ok(!/confirmée/.test(banner), 'the first file\'s verdict must not be shown: ' + banner);
      assert.ok(report.includes(sha(OTHER)), 'the report carries the SHA-256 of the file on screen');
      assert.ok(!report.includes(sha(REAL)), 'and never that of the abandoned one');
      assert.deepEqual(problems, []);
      await context.close();
    }
    // V4: a block-confirmed proof is green only when the signing key is authenticated by a fingerprint.
    {
      const { context, page, problems } = await open(0);
      await drop(page, REAL);
      await page.waitForSelector('#v2bReport .banner');
      await page.fill('#optBlockRoot', REAL_BLOCK.merkle_root);
      await page.click('#rerun');
      await page.waitForFunction(() => /auteur non authentifié/.test((document.querySelector('#v2bReport .banner') || {}).textContent || ''));
      assert.match(await page.locator('#v2bReport .banner').getAttribute('class'), /unsupported/);
      assert.ok(!/confirmée par un bloc/.test(await page.locator('#v2bReport .banner').innerText()));
      const keyHex = JSON.parse(fs.readFileSync(REAL, 'utf8')).proof_only.submission.signing_public_key_hex;
      await page.fill('#optFingerprint', createHash('sha256').update(Buffer.from(keyHex, 'hex')).digest('hex'));
      await page.click('#rerun');
      await page.waitForFunction(() => /confirmée par un bloc/.test((document.querySelector('#v2bReport .banner') || {}).textContent || ''));
      assert.match(await page.locator('#v2bReport .banner').getAttribute('class'), /success/);
      // V9: the report names the fingerprint and where it came from.
      assert.match(await page.locator('#reportMeta').textContent(), /Empreinte de confiance utilisée[\s\S]*saisie à la main/);
      assert.deepEqual(problems, []);
      await context.close();
    }
    // V8: an integer written as a decimal is refused by the page, like the Python reference does.
    {
      const { context, page } = await open(0);
      const forged = fs.readFileSync(REAL, 'utf8').replace('"batch_number": 80', '"batch_number": 80.0');
      assert.notEqual(forged, fs.readFileSync(REAL, 'utf8'), 'the fixture contains the field to alter');
      const file = path.join(os.tmpdir(), 'ui-v8-' + process.pid + '.json');
      fs.writeFileSync(file, forged);
      try {
        await drop(page, file);
        await page.waitForFunction(() => /refusé/.test(document.getElementById('result').textContent));
      } finally { fs.rmSync(file, { force: true }); }
      assert.equal(await page.locator('#v2bReport .banner').count(), 0);
      await context.close();
    }
    // V6: a disclosure is not "attached" to an invalid proof (or one whose key is not authenticated).
    {
      const { context, page } = await open(0);
      await drop(page, path.resolve('tests/vectors/v2b/tampered_anchor_digest.json')); // same record and client as the disclosure, but an invalid proof
      await page.waitForSelector('#v2bReport .banner');
      await page.setInputFiles('#optKeyCard', path.resolve('tests/vectors/keycard/valid.json'));
      await page.waitForFunction(() => !document.getElementById('cardStatus').hidden);
      await drop(page, path.resolve('tests/vectors/disclosure/valid.json'));
      await page.waitForSelector('#disclosureReport .check');
      const row = page.locator('#disclosureReport li.check', { hasText: 'Rattachement à la preuve' });
      assert.match(await row.locator('.state').innerText(), /Non vérifié/);
      await context.close();
    }
    // Control: the same slow file alone does reach the confirmed level (the simulation is faithful).
    {
      const { context, page } = await open(300);
      await drop(page, REAL);
      await page.waitForSelector('#v2bReport .banner');
      await page.check('#optFetchBlock');
      await page.click('#rerun');
      await page.waitForFunction(() => /Antériorité confirmée/.test((document.querySelector('#v2bReport .banner') || {}).textContent || ''));
      assert.ok((await page.locator('#reportMeta').textContent()).includes(sha(REAL)));
      await context.close();
    }
  } finally { await browser.close(); }
  console.log('page de vérification : ancien format jamais vert et sans réseau sans consentement ; deux fichiers à la suite : seul le dernier est affiché');
})().catch(e => { console.error(e); process.exitCode = 1; });
