'use strict';

/**
 * Security-Suite unit tests (node:test).
 * Run:  node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert');

const cellTriangulation = require('../src/services/cellTriangulation');
const cameraHacker = require('../src/services/cameraHacker');
const wifiCracker = require('../src/services/wifiCracker');

const TOWERS3 = [
  { cellId: 6789, mcc: 604, mnc: 1, lac: 12345, rssi: -65 },
  { cellId: 6790, mcc: 604, mnc: 1, lac: 12345, rssi: -72 },
  { cellId: 6791, mcc: 604, mnc: 1, lac: 12345, rssi: -80 },
];

test('triangulate: 3 towers -> method triangulation', () => {
  const r = cellTriangulation.triangulate(TOWERS3);
  assert.strictEqual(r.method, 'triangulation');
  assert.strictEqual(r.samples, 3);
});

test('triangulate: 3 towers -> high confidence and numeric location', () => {
  const r = cellTriangulation.triangulate(TOWERS3);
  assert.strictEqual(r.confidence, 'high');
  assert.ok(Number.isFinite(r.location.lat) && Number.isFinite(r.location.lon));
  assert.ok(r.rmsMeters >= 0);
  assert.ok(r.accuracyMeters > 0);
});

test('triangulate: 1 tower -> single_cell, accuracy 3000, low confidence', () => {
  const r = cellTriangulation.triangulate([TOWERS3[0]]);
  assert.strictEqual(r.method, 'single_cell');
  assert.strictEqual(r.accuracyMeters, 3000);
  assert.strictEqual(r.confidence, 'low');
});

test('triangulate: empty input -> unknown', () => {
  const r = cellTriangulation.triangulate([]);
  assert.strictEqual(r.method, 'unknown');
  assert.strictEqual(r.location, null);
});

test('triangulate: unknown cell -> deterministic fallback position', () => {
  const t = [{ cellId: 999999, mcc: 604, mnc: 1, lac: 99999, rssi: -70 }];
  const a = cellTriangulation.triangulate([t[0], TOWERS3[0]]);
  const b = cellTriangulation.triangulate([t[0], TOWERS3[0]]);
  const f = a.towers.find((x) => x.cellId === 999999);
  assert.strictEqual(f.positionSource, 'fallback');
  assert.deepStrictEqual(a.location, b.location);
});

test('estimateRangeM: stronger signal -> smaller range', () => {
  const near = cellTriangulation.estimateRangeM(-55);
  const far = cellTriangulation.estimateRangeM(-95);
  assert.ok(near < far);
});

test('parseCIDR: 192.168.1.0/24 -> 254 hosts', () => {
  const p = cameraHacker.parseCIDR('192.168.1.0/24');
  assert.strictEqual(p.hostCount, 254);
  assert.strictEqual(p.hosts[0], '192.168.1.1');
  assert.strictEqual(p.hosts[253], '192.168.1.254');
});

test('parseCIDR: rejects 192.168.1/24 (missing fourth octet)', () => {
  assert.throws(() => cameraHacker.parseCIDR('192.168.1/24'));
});

test('parseCIDR: rejects prefixes wider than /24', () => {
  assert.throws(() => cameraHacker.parseCIDR('192.168.0.0/16'));
});

test('rtspUrlsForHost: returns the 4 candidate paths', () => {
  const urls = cameraHacker.rtspUrlsForHost('192.168.1.10');
  assert.strictEqual(urls.length, 4);
  assert.ok(urls[0].startsWith('rtsp://192.168.1.10:554/'));
  assert.ok(urls.some((u) => u.endsWith('/Streaming/Channels/101')));
  assert.ok(urls.some((u) => u.endsWith('/onvif1')));
});

test('buildScanPlan: bounded host list + sample urls', () => {
  const plan = cameraHacker.buildScanPlan('192.168.1.0/24');
  assert.strictEqual(plan.hostCount, 254);
  assert.strictEqual(plan.sampleUrls.length, 3);
  assert.strictEqual(plan.sampleUrls[0].length, 4);
});

test('parseHandshake: PMKID line -> type pmkid + decoded ssid', () => {
  const ssid = Buffer.from('TestHome').toString('hex');
  const line = `WPA*01*${'a'.repeat(32)}*AABBCCDDEEFF*112233445566*${ssid}***`;
  const r = wifiCracker.parseHandshake(line);
  assert.strictEqual(r.count, 1);
  assert.strictEqual(r.entries[0].type, 'pmkid');
  assert.strictEqual(r.entries[0].ssid, 'TestHome');
});

test('parseHandshake: EAPOL line -> type eapol', () => {
  const ssid = Buffer.from('TestNet').toString('hex');
  const line = `WPA*02*${'b'.repeat(32)}*AABBCCDDEEFF*112233445566*${ssid}***`;
  const r = wifiCracker.parseHandshake(line);
  assert.strictEqual(r.entries[0].type, 'eapol');
  assert.strictEqual(r.entries[0].ssid, 'TestNet');
});

test('parseHandshake: invalid lines are collected, not thrown', () => {
  const r = wifiCracker.parseHandshake('garbage\n# comment\n\n');
  assert.strictEqual(r.count, 0);
  assert.strictEqual(r.invalid.length, 1);
});

test('crackPlan: hashcat mode 22000, 15 candidates, expected command', () => {
  const plan = wifiCracker.crackPlan({ target: 'TestHome', type: 'pmkid' });
  assert.strictEqual(plan.hashMode, 22000);
  assert.strictEqual(plan.candidates, 15);
  assert.strictEqual(plan.type, 'pmkid');
  assert.strictEqual(plan.outputFile, 'cracked.txt');
  assert.ok(plan.command.startsWith('hashcat -m 22000 -a 0'));
  assert.ok(plan.command.includes('cracked.txt'));
});
/* ---------------- phoneAudit (nearby-phone discovery + real-progress audit) ---------------- */

const phoneAudit = require('../src/services/phoneAudit');

test('lookupOui: known Apple OUI resolves with phone tag', () => {
  const hit = phoneAudit.lookupOui('A4-83-E7-12-34-56');
  assert.ok(hit && hit.tag === 'phone');
  assert.ok(/apple/i.test(hit.vendor));
});

test('lookupOui: normalizes separators and is case-insensitive', () => {
  const a = phoneAudit.lookupOui('a4:83:e7:00:00:01');
  const b = phoneAudit.lookupOui('A483E7');
  assert.deepStrictEqual(a, b);
});

test('lookupOui: unknown MAC -> null', () => {
  assert.strictEqual(phoneAudit.lookupOui('00:00:00:00:00:00'), null);
});

test('friendlyVendor: aliases Apple/Samsung and truncates unknowns', () => {
  assert.strictEqual(phoneAudit.friendlyVendor('Apple, Inc.'), 'Apple');
  assert.strictEqual(phoneAudit.friendlyVendor('Samsung Electronics Co.,Ltd'), 'Samsung');
  assert.strictEqual(phoneAudit.friendlyVendor('Super Vendor Industries'), 'Super');
  assert.strictEqual(phoneAudit.friendlyVendor(''), null);
});

test('isPrivateIp: RFC1918 only', () => {
  assert.ok(phoneAudit.isPrivateIp('192.168.1.34'));
  assert.ok(phoneAudit.isPrivateIp('10.0.0.7'));
  assert.ok(phoneAudit.isPrivateIp('172.20.3.9'));
  assert.ok(!phoneAudit.isPrivateIp('8.8.8.8'));
  assert.ok(!phoneAudit.isPrivateIp('172.32.0.1'));
});

const ARP_FIXTURE = [
  '',
  'Interface Internet : 192.168.1.137 --- 0xd',
  '  Adresse IP           Adresse physique     Type',
  '  192.168.1.1          3c-37-86-11-22-33    dynamique',
  '  192.168.1.34         a4-83-e7-aa-bb-cc    dynamique',
  '  192.168.1.255        ff-ff-ff-ff-ff-ff    statique',
  '  224.0.0.22           01-00-5e-00-00-16    statique',
  '  0.0.0.0              00-00-00-00-00-00    statique',
  '  169.254.10.20        aa-bb-cc-dd-ee-01    dynamique',
  '  10.27.1.155          aa-bb-cc-dd-ee-02    dynamique',
].join('\r\n');

test('parseArpText: keeps private unicast entries, drops multicast/link-local/own', () => {
  const rows = phoneAudit.parseArpText(ARP_FIXTURE);
  const ips = rows.map((r) => r.ip);
  assert.ok(ips.includes('192.168.1.1'));
  assert.ok(ips.includes('192.168.1.34'));
  assert.ok(!ips.includes('224.0.0.22'));
  assert.ok(!ips.includes('0.0.0.0'));
  assert.ok(!ips.includes('169.254.10.20'));
  assert.ok(ips.includes('10.27.1.155')); // 10/8 IS RFC1918-private
  const phone = rows.find((r) => r.ip === '192.168.1.34');
  assert.strictEqual(phone.mac, 'A4:83:E7:AA:BB:CC');
});

test('parseRouteGateway: default-route line -> gateway, else null', () => {
  const rt = [
    '===========================================================================',
    'Itinéraires actifs :',
    'Destination réseau    Masque réseau  Passerelle     Interface Métrique',
    '          0.0.0.0          0.0.0.0    192.168.1.1    192.168.1.137      35',
  ].join('\r\n');
  assert.strictEqual(phoneAudit.parseRouteGateway(rt), '192.168.1.1');
  assert.strictEqual(phoneAudit.parseRouteGateway('rien ici'), null);
});

const WLAN_FR = [
  'Il existe 1 interface sur le système :',
  '    Nom                   : Wi-Fi',
  '    SSID                  : INWI_HOME_5G',
  '    BSSID                 : 3c:37:86:11:22:33',
  '    Type de radio         : 802.11ax',
  '    Bande                 : Bande 5 GHz',
].join('\r\n');

test('parseNetshWlan: French netsh output -> ssid/band/radio (BSSID line ignored)', () => {
  const w = phoneAudit.parseNetshWlan(WLAN_FR);
  assert.strictEqual(w.ssid, 'INWI_HOME_5G');
  assert.strictEqual(w.radioType, '802.11ax');
  assert.ok(/5 GHz/.test(w.band));
});

test('parseAdbBanner: extracts model/name/device/serial from CNXN banner', () => {
  const banner = 'device::ro.product.model=SM-A536B;ro.product.name=a53x;ro.product.device=a53x;ro.serialno=RZ8T30XXXXX;features=';
  const a = phoneAudit.parseAdbBanner(banner);
  assert.strictEqual(a.model, 'SM-A536B');
  assert.strictEqual(a.name, 'a53x');
  assert.strictEqual(a.serial, 'RZ8T30XXXXX');
});

test('parseNbns: NBSTAT response -> registered names', () => {
  const name15 = 'PC-CLIENT'.padEnd(15, ' ');
  const qname = 'CK' + 'CA'.repeat(15);
  const b = [];
  const push16 = (v) => b.push((v >> 8) & 0xff, v & 0xff);
  push16(0x84a1); push16(0x8500); push16(0); push16(1); push16(0); push16(0); // header, ancount=1
  b.push(qname.length); for (const c of qname) b.push(c.charCodeAt(0)); b.push(0);
  push16(0x0021); push16(0x0001); // question NBSTAT/IN
  b.push(0xc0, 0x0c);              // RR name pointer
  push16(0x0021); push16(0x0001); push16(0); push16(0x0021); // type/class/ttl
  push16(1 + 18);                  // rdlength
  b.push(1);                       // name count
  for (const c of name15) b.push(c.charCodeAt(0));
  b.push(0x00); push16(0x0400);    // suffix, flags
  const names = phoneAudit.parseNbns(Buffer.from(b));
  assert.strictEqual(names.length, 1);
  assert.strictEqual(names[0].name, 'PC-CLIENT');
  assert.strictEqual(names[0].suffix, 0x00);
});

test('computeScore: evidence-weighted, 65 without ADB, 85 ADB open, 100 with banner', () => {
  assert.strictEqual(phoneAudit.computeScore({}), 0);
  assert.strictEqual(phoneAudit.computeScore({ reachable: true }), 10);
  const base = { reachable: true, vendor: 'Apple', openPorts: [62078], http: [{ port: 62078 }], names: { mdns: 'iPhone' } };
  assert.strictEqual(phoneAudit.computeScore(base), 65); // no ADB evidence
  assert.strictEqual(phoneAudit.computeScore({ ...base, adb: { open: true } }), 85);
  assert.strictEqual(phoneAudit.computeScore({ ...base, adb: { open: true, banner: 'SM-A536B' } }), 100);
  assert.strictEqual(phoneAudit.computeScore({ reachable: true, vendor: 'S', openPorts: [5555], adb: { open: true } }), 55);
});

test('startAudit: rejects non-private targets', () => {
  assert.throws(() => phoneAudit.startAudit('8.8.8.8'), /private/);
});

test('startAudit: dead private IP -> all 9 REAL steps finish, progress 100, no fabricated score', async () => {
  const job = phoneAudit.startAudit('10.255.255.1', {
    pingTimeoutMs: 300, tcpTimeoutMs: 300, httpTimeoutMs: 300,
    adbTimeoutMs: 300, mdnsTimeoutMs: 400, nbnsTimeoutMs: 400,
  });
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const j = phoneAudit.getAudit(job.id);
    if (j && j.status !== 'running') break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const j = phoneAudit.getAudit(job.id);
  assert.ok(j && j.status === 'done', 'job status=' + (j && j.status));
  assert.strictEqual(j.progress, 100);
  assert.strictEqual(j.steps.length, 9);
  assert.ok(j.steps.every((s) => s.status === 'done'), JSON.stringify(j.steps.map((s) => [s.id, s.status])));
  assert.ok(j.score === 0 || j.score === 10, 'dead-IP score=' + j.score);
  assert.ok(j.level && typeof j.level === 'string');
  const pub = phoneAudit.publicJob(j);
  assert.strictEqual(pub.id, job.id);
  assert.ok(pub.findings && typeof pub.findings.reachable === 'boolean');
});

test('cancelAudit: canceling a running audit stops it before 100%', async () => {
  const job = phoneAudit.startAudit('10.255.255.2', {
    pingTimeoutMs: 800, tcpTimeoutMs: 800, httpTimeoutMs: 400,
    adbTimeoutMs: 400, mdnsTimeoutMs: 600, nbnsTimeoutMs: 600,
  });
  phoneAudit.cancelAudit(job.id);
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const j = phoneAudit.getAudit(job.id);
    if (j && j.status !== 'running') break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const j = phoneAudit.getAudit(job.id);
  assert.ok(j, 'job exists');
  assert.ok(['cancelled', 'done'].includes(j.status), 'status=' + j.status);
  if (j.status === 'cancelled') assert.ok(j.progress < 100, 'cancelled before 100%: ' + j.progress);
});