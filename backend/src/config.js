'use strict';

/**
 * Pegasus Suite — central configuration.
 *
 * The backend is a LAN/Wi-Fi/cellular reconnaissance helper for AUTHORIZED
 * security testing. It exposes bounded, read-only scan endpoints and a small
 * static frontend. There is no user account, no login and no business/payment
 * workflow of any kind.
 *
 * Everything is driven by environment variables (backend/.env), with safe
 * defaults so the lab server starts with zero configuration.
 */

const fs = require('node:fs');
const path = require('node:path');

// Minimal .env loader (avoids an extra dependency; supports KEY=VALUE lines).
function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2];
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

loadDotEnv(path.resolve(__dirname, '..', '.env'));

const env = (name, dflt = '') => {
  const v = process.env[name];
  return v === undefined || v === '' ? dflt : v;
};
const num = (name, dflt) => {
  const v = Number(process.env[name]);
  return Number.isFinite(v) ? v : dflt;
};
const bool = (name, dflt = false) => {
  const v = process.env[name];
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
};
const list = (name, dflt = '') =>
  env(name, dflt)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

const config = {
  env: env('NODE_ENV', 'development'),
  isProduction: env('NODE_ENV', 'development') === 'production',

  server: {
    port: num('PORT', 8710),
    // 0.0.0.0 lets a phone on the same Wi-Fi reach the backend over the LAN.
    host: env('HOST', '0.0.0.0'),
    // Static frontend served by Express (same assets bundled into the APK).
    staticDir: path.resolve(__dirname, '..', '..', 'frontend'),
    trustProxy: bool('TRUST_PROXY', false),
    requireHttps: bool('REQUIRE_HTTPS', false),
    // Extra CORS origins for the native (Capacitor) WebView, on top of the
    // built-in Capacitor defaults (https://localhost, capacitor://localhost).
    allowedOrigins: list('CORS_ALLOWED_ORIGINS'),
  },

  // Bounded defaults for the live LAN scan endpoints. Kept conservative so a
  // single request cannot turn into an unbounded sweep.
  scan: {
    defaultCidr: env('SCAN_DEFAULT_CIDR', '192.168.1.0/24'),
    connectTimeoutMs: num('SCAN_CONNECT_TIMEOUT_MS', 800),
    httpTimeoutMs: num('SCAN_HTTP_TIMEOUT_MS', 1500),
    concurrency: num('SCAN_CONCURRENCY', 64),
  },

  rateLimit: {
    apiWindowMs: num('RATE_LIMIT_WINDOW_MS', 60 * 1000),
    apiMax: num('RATE_LIMIT_MAX', 120),
  },
};

/** Validation that prevents silently unsafe boots. */
function validateStartup() {
  const problems = [];
  if (config.isProduction && config.server.requireHttps === false) {
    problems.push('REQUIRE_HTTPS=true is required with NODE_ENV=production.');
  }
  if (config.scan.concurrency < 1 || config.scan.concurrency > 256) {
    problems.push('SCAN_CONCURRENCY must be between 1 and 256.');
  }
  return problems;
}

// This module is consumed two ways across the codebase:
//   const config = require('../config');                      (direct object)
//   const { config, validateStartup } = require('./config');  (destructured)
module.exports = config;
module.exports.config = config;
module.exports.validateStartup = validateStartup;
