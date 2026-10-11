'use strict';

/**
 * Wi-Fi handshake tooling helpers.
 *
 * Parses capture files / hashcat `.22000` lines and builds a crack PLAN.
 * This module NEVER brute-forces by itself: it only prepares the wordlist,
 * the hashcat command and the expected output file, so the operator (or the
 * Android app) runs it against networks they are authorized to test.
 */

const path = require('node:path');

const DEFAULT_WORDLIST = path.resolve(__dirname, '..', 'data', 'rockyou.txt');

// Small built-in candidate list used when no wordlist file is present.
const CANDIDATE_WORDS = [
  '12345678', '123456789', 'password', 'password123', 'changeme123',
  'azerty123', 'qwerty123', 'admin123', 'wifi12345', '00000000',
  '11111111', '87654321', 'summer2026', 'welcome123', 'livebox',
];

/**
 * Parse hashcat .22000 lines.
 *
 * Formats:
 *   WPA*01*PMKID*APMAC*STAMAC*SSID_HEX*...        (PMKID)
 *   WPA*02*MIC*APMAC*STAMAC*SSID_HEX*...          (EAPOL / handshake)
 *
 * Returns an array of { type, pmkid?, mic?, apMac, staMac, ssid, ssidHex, raw }.
 * Invalid lines are collected in `invalid` but never throw.
 */
function parseHandshake(text) {
  const entries = [];
  const invalid = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const f = line.split('*');
    if (f[0] !== 'WPA' || (f[1] !== '01' && f[1] !== '02')) { invalid.push(line); continue; }
    const type = f[1] === '01' ? 'pmkid' : 'eapol';
    const pmkid = type === 'pmkid' ? f[2] : null;
    const mic = type === 'eapol' ? f[2] : null;
    const apMac = (f[3] || '').toUpperCase();
    const staMac = (f[4] || '').toUpperCase();
    const ssidHex = f[5] || '';
    entries.push({
      type, pmkid, mic, apMac, staMac, ssidHex,
      ssid: hexToAscii(ssidHex),
      raw: line,
    });
  }
  return { entries, invalid, count: entries.length };
}

function hexToAscii(hex) {
  const h = String(hex || '');
  let out = '';
  for (let i = 0; i + 1 < h.length; i += 2) {
    const code = parseInt(h.substr(i, 2), 16);
    if (Number.isFinite(code)) out += String.fromCharCode(code);
  }
  return out;
}

function normalizeType(type) {
  return type === 'eapol' || type === 'handshake' ? 'eapol' : 'pmkid';
}

/**
 * Build a cracking plan (no execution).
 * @param {object} opts
 *   - target: SSID / BSSID label
 *   - type: 'pmkid' | 'eapol'
 *   - wordlist: absolute path (default data/rockyou.txt)
 *   - hashesFile: input .22000 file (default "handshake.22000")
 *   - outputFile: default "cracked.txt"
 */
function crackPlan(opts = {}) {
  const target = opts.target ? String(opts.target) : 'unknown';
  const type = normalizeType(opts.type);
  const wordlist = opts.wordlist ? String(opts.wordlist) : DEFAULT_WORDLIST;
  const hashesFile = opts.hashesFile ? String(opts.hashesFile) : 'handshake.22000';
  const outputFile = opts.outputFile ? String(opts.outputFile) : 'cracked.txt';

  const command = `hashcat -m 22000 -a 0 "${hashesFile}" "${wordlist}" -o "${outputFile}"`;

  return {
    target,
    type,
    hashMode: 22000,
    wordlist,
    hashesFile,
    outputFile,
    candidates: CANDIDATE_WORDS.length,
    candidateWords: [...CANDIDATE_WORDS],
    command,
    note: 'Cracking plan. Run it only against networks you are authorized to test.',
  };
}

module.exports = { parseHandshake, crackPlan, CANDIDATE_WORDS, DEFAULT_WORDLIST, normalizeType };
