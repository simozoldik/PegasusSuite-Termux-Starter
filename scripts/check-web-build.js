#!/usr/bin/env node
/* Pegasus Suite — web build verification (npm run test:web).
 *
 * Fails (non-zero exit) if the Capacitor webDir (www/) is missing required
 * assets, if config.js is malformed, or if any credential-like value leaked
 * into the shipped web assets.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const outDir = path.join(root, 'www');

const REQUIRED = [
  'index.html', 'styles.css', 'app.js', 'config.js',
  'manifest.webmanifest', 'sw.js',
  path.join('icons', 'icon-192.png'),
  path.join('icons', 'icon-512.png'),
];

let checks = 0;
let failed = 0;
function ok(cond, label) {
  checks++;
  if (cond) { console.log(`  ok   - ${label}`); }
  else { failed++; console.log(`  FAIL - ${label}`); }
}

function main() {
  console.log('[check-web-build] verifying www/');
  ok(fs.existsSync(outDir), 'www/ exists (run `npm run build` first)');
  if (!fs.existsSync(outDir)) { finish(); return; }

  for (const rel of REQUIRED) {
    ok(fs.existsSync(path.join(outDir, rel)), `asset present: ${rel}`);
  }

  // config.js must define __PEGASUS_CONFIG__ and must not contain secrets.
  const cfgPath = path.join(outDir, 'config.js');
  let cfg = '';
  try { cfg = fs.readFileSync(cfgPath, 'utf8'); } catch { /* handled below */ }
  ok(/__PEGASUS_CONFIG__/.test(cfg), 'config.js defines window.__PEGASUS_CONFIG__');
  ok(/apiBaseUrl/.test(cfg), 'config.js defines apiBaseUrl');

  // The API base must never be cleartext localhost/loopback in the web bundle.
  const badBase = /apiBaseUrl\s*:\s*"(http:\/\/(localhost|127\.0\.0\.1)|[^"]*localhost)/.test(cfg);
  ok(!badBase, 'apiBaseUrl is not loopback (must reach the lab PC over the LAN)');

  // No credential-like material in any shipped asset. A bare `password:` is a
  // legit field name, so only hardcoded string literals are flagged.
  const secretRe = /(client_secret|clientSecret|api_key|apiKey|private_key|BEGIN [A-Z ]*PRIVATE KEY|Set-Cookie|session_cookie|password\s*[:=]\s*['"`])/i;
  let leaked = false;
  for (const rel of REQUIRED) {
    const p = path.join(outDir, rel);
    if (!fs.existsSync(p)) continue;
    const buf = fs.readFileSync(p, 'latin1');
    if (secretRe.test(buf)) { leaked = true; console.log(`        potential secret pattern in ${rel}`); }
  }
  ok(!leaked, 'no credential-like material in shipped assets');

  finish();
}

function finish() {
  console.log(`[check-web-build] ${checks - failed}/${checks} checks passed`);
  if (failed > 0) process.exit(1);
}

main();
