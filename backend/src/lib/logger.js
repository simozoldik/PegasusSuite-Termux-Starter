'use strict';

/**
 * Application logger + masking helpers.
 * NEVER log credentials, tokens or cookies. Sensitive values are masked.
 */

const mask = (value) => {
  if (value === null || value === undefined) return value;
  const s = String(value);
  if (s.length <= 8) return s.slice(0, 2) + '…' + s.slice(-2);
  return s.slice(0, 4) + '…' + s.slice(-4);
};

const SENSITIVE_KEYS = /token|secret|password|cookie|authorization|session|credential/i;

function scrub(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(scrub);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.test(k)) { out[k] = '[MASKED]'; continue; }
    if (typeof v === 'object') { out[k] = scrub(v); continue; }
    if (typeof v === 'string' && /^[0-9a-zA-Z]{10,}$/.test(v) && /(ref|id|code)/i.test(k)) {
      out[k] = mask(v);
      continue;
    }
    out[k] = v;
  }
  return out;
}

function line(level, msg, meta) {
  const rec = { ts: new Date().toISOString(), level, msg };
  if (meta !== undefined) rec.meta = scrub(meta);
  process.stdout.write(JSON.stringify(rec) + '\n');
}

module.exports = {
  mask,
  scrub,
  info: (msg, meta) => line('info', msg, meta),
  warn: (msg, meta) => line('warn', msg, meta),
  error: (msg, meta) => line('error', msg, meta),
};
