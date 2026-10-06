// Regenerates tests/vectors/keys/backup-js.age: a backup of the synthetic lot-1 keys made by keys-backup.js, so that the
// ChainDBoM Python tool can be checked against it (python -m chaindbom.v2b_key_backup restore-test). Public test passphrase,
// 100 % synthetic keys. The file differs at every run (random salt): regenerate only when the format changes.
// Usage: node tests/tools/gen_keys_backup_fixture.js
const fs = require('node:fs');
const vm = require('node:vm');
const { OPTIONS, ctx } = require('./gen_keys_vectors.js');
for (const file of ['v2b.js', 'keys/vendor/age-encryption.bundle.js', 'keys/keys-backup.js']) vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
const PASSPHRASE = 'synthetic test passphrase 7F3A-91C2';
module.exports = { PASSPHRASE };
if (require.main === module) {
  (async () => {
    const keys = await ctx.ChainDBoMKeys.generateClientKeys(OPTIONS);
    const { bytes } = await ctx.ChainDBoMKeysBackup.backup(keys.files, PASSPHRASE, { now: OPTIONS.now });
    fs.writeFileSync('tests/vectors/keys/backup-js.age', bytes);
    console.log('backup-js.age régénérée :', bytes.length, 'octets');
  })();
}
