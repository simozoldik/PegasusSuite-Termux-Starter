#!/usr/bin/env node
/* Pegasus Suite — release keystore helper.
 *
 * Creates a release keystore OUTSIDE Git (android/keystore/, which is ignored)
 * and writes android/keystore.properties (also ignored) that Gradle reads.
 *
 *   node scripts/generate-keystore.js
 *
 * Provide values via environment variables (preferred) or you will be prompted
 * to confirm defaults:
 *   KEYSTORE_PASSWORD   (required)
 *   KEY_ALIAS           (default: pegasusrelease)
 *   KEY_PASSWORD        (default: same as KEYSTORE_PASSWORD)
 *   KEYSTORE_DNAME      (default: CN=Pegasus Suite, O=Pegasus, C=MA)
 *   KEYSTORE_VALIDITY   (default: 10000 days)
 *
 * NOTE: keytool is used, so JAVA_HOME / java must be on PATH.
 * NEVER commit android/keystore/ or android/keystore.properties.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const keystoreDir = path.join(root, 'android', 'keystore');
const keystoreFile = path.join(keystoreDir, 'release.keystore');
const propsFile = path.join(root, 'android', 'keystore.properties');

function main() {
  const storePassword = process.env.KEYSTORE_PASSWORD;
  if (!storePassword) {
    console.error('[keystore] ERROR: set KEYSTORE_PASSWORD before running.');
    console.error('  e.g.  set KEYSTORE_PASSWORD=... && node scripts/generate-keystore.js');
    process.exit(1);
  }
  const keyAlias = process.env.KEY_ALIAS || 'pegasusrelease';
  const keyPassword = process.env.KEY_PASSWORD || storePassword;
  const dname = process.env.KEYSTORE_DNAME || 'CN=Pegasus Suite, O=Pegasus, OU=Recon, L=Casablanca, C=MA';
  const validity = process.env.KEYSTORE_VALIDITY || '10000';

  fs.mkdirSync(keystoreDir, { recursive: true });
  if (fs.existsSync(keystoreFile)) {
    console.error(`[keystore] refusing to overwrite existing keystore: ${keystoreFile}`);
    process.exit(1);
  }

  const keytool = process.env.JAVA_HOME
    ? path.join(process.env.JAVA_HOME, 'bin', 'keytool.exe')
    : 'keytool';

  console.log(`[keystore] generating ${keystoreFile}`);
  execFileSync(keytool, [
    '-genkeypair',
    '-v',
    '-keystore', keystoreFile,
    '-alias', keyAlias,
    '-keyalg', 'RSA',
    '-keysize', '2048',
    '-validity', String(validity),
    '-storepass', storePassword,
    '-keypass', keyPassword,
    '-dname', dname,
  ], { stdio: 'inherit' });

  const props =
`# GENERATED — DO NOT COMMIT. Release signing material for Pegasus Suite.
# This file is git-ignored. Keep it and the keystore outside version control.
storeFile=keystore/release.keystore
storePassword=${storePassword}
keyAlias=${keyAlias}
keyPassword=${keyPassword}
`;
  fs.writeFileSync(propsFile, props, 'utf8');
  console.log(`[keystore] wrote ${propsFile} (git-ignored)`);
  console.log('[keystore] done. Build release with: npm run android:release');
}

main();
