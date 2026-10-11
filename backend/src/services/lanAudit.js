'use strict';

/**
 * LAN audit — real (bounded) TCP-connect host discovery + IP-camera
 * fingerprinting, run by the Pegasus backend on the same LAN as the target
 * subnet. Used only against assets the operator is authorized to test.
 *
 *   parseCidr(cidr)                -> { cidr, prefix, hosts, hostCount }
 *   scanHosts(cidr, ports, opts)   -> { cidr, scannedHosts, hosts:[{ip, openPorts}] }
 *   cameraAudit(cidr, opts)        -> { cidr, scannedHosts, count, candidates:[...] }
 *
 * All work is capped (max hosts, per-socket timeout, bounded concurrency) so a
 * single request cannot run unbounded.
 */

const net = require('node:net');
const http = require('node:http');
const cameraHacker = require('./cameraHacker');

const MAX_HOSTS = 1024;                                   // never scan more than a /22
const DEFAULT_HOST_PORTS = [80, 443, 22, 8080, 554, 8000, 445, 139];
const CAMERA_PORTS = [80, 554, 8080, 8000, 8081, 81, 88, 8554, 8899, 34567];
const HTTP_PORTS = new Set([80, 81, 88, 8000, 8001, 8080, 8081, 8899]);

const CAMERA_SIGNATURES = /camera|hikvision|dahua|netsurveillance|ipcam|ip cam|webcam|onvif|boa\/|goahead|netwave|xiongmai|device type|rtsp|\bipc\b/i;

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
function ipKey(ip) {
  const p = String(ip).split('.').map(Number);
  return (((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0);
}

function parseCidr(cidr) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(cidr || '').trim());
  if (!m) throw new Error('Invalid CIDR (expected e.g. 192.168.1.0/24).');
  const oct = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (oct.some((n) => n < 0 || n > 255)) throw new Error('Invalid CIDR octet.');
  const prefix = Number(m[5]);
  if (prefix < 16 || prefix > 32) throw new Error('CIDR prefix must be between /16 and /32.');

  const base = ipKey(oct.join('.'));
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const size = Math.pow(2, 32 - prefix);

  const hosts = [];
  const start = prefix >= 31 ? network : network + 1;
  const end = prefix >= 31 ? network + size - 1 : network + size - 2;
  for (let i = start; i <= end && hosts.length < MAX_HOSTS; i++) hosts.push(intToIp(i >>> 0));
  const total = end - start + 1;
  return { cidr: String(cidr).trim(), prefix, hosts, hostCount: hosts.length, truncated: total > MAX_HOSTS };
}

function tcpProbe(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch (_) { /* ignore */ }
      resolve(open);
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => finish(true));
    s.once('timeout', () => finish(false));
    s.once('error', () => finish(false));
    try { s.connect(port, ip); } catch (_) { finish(false); }
  });
}

function httpProbe(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: ip,
        port,
        method: 'GET',
        path: '/',
        timeout: timeoutMs,
        headers: { 'User-Agent': 'PegasusSuite/1.0', Host: ip + ':' + port },
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { if (body.length < 8192) body += d; });
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            server: res.headers['server'] || '',
            location: res.headers['location'] || '',
            body: body.slice(0, 4096),
          })
        );
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

/**
 * Bounded TCP-connect scan of a CIDR over the given ports.
 * Concurrency is applied globally over (host, port) pairs.
 */
async function scanHosts(cidr, ports, opts = {}) {
  const parsed = parseCidr(cidr);
  const portList = (Array.isArray(ports) && ports.length ? ports : DEFAULT_HOST_PORTS)
    .map(Number)
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
  if (!portList.length) throw new Error('No valid ports to scan.');

  const timeoutMs = Math.max(150, Math.min(3000, opts.timeoutMs || 600));
  const concurrency = Math.max(1, Math.min(256, opts.concurrency || 64));

  const tasks = [];
  for (const ip of parsed.hosts) for (const p of portList) tasks.push({ ip, p });

  const openByIp = new Map();
  let idx = 0;
  async function worker() {
    while (true) {
      const i = idx++;
      if (i >= tasks.length) return;
      const { ip, p } = tasks[i];
      const open = await tcpProbe(ip, p, timeoutMs);
      if (open) {
        if (!openByIp.has(ip)) openByIp.set(ip, []);
        openByIp.get(ip).push(p);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));

  const hosts = Array.from(openByIp.entries())
    .map(([ip, openPorts]) => ({ ip, openPorts: openPorts.sort((a, b) => a - b) }))
    .sort((a, b) => ipKey(a.ip) - ipKey(b.ip));

  return {
    cidr: parsed.cidr,
    prefix: parsed.prefix,
    scannedHosts: tasks.length,
    hostCount: parsed.hostCount,
    truncated: parsed.truncated,
    hosts,
    ports: portList,
  };
}

/**
 * Camera-focused audit: connect-scan camera ports, fingerprint HTTP services,
 * and attach candidate RTSP URLs for anything camera-like.
 */
async function cameraAudit(cidr, opts = {}) {
  const base = await scanHosts(cidr, CAMERA_PORTS, {
    timeoutMs: opts.timeoutMs || 600,
    concurrency: opts.concurrency || 96,
  });

  const candidates = [];
  for (const h of base.hosts) {
    for (const port of h.openPorts) {
      const isRtsp = port === 554 || port === 8554;
      const isHttp = HTTP_PORTS.has(port);
      let banner = '';
      let camera = false;
      const service = isRtsp ? 'rtsp' : isHttp ? 'http' : 'tcp';

      if (isHttp) {
        const r = await httpProbe(h.ip, port, opts.httpTimeoutMs || 1500);
        if (r) {
          banner = (r.server ? '[' + r.server + '] ' : '') + 'HTTP ' + r.status;
          if (CAMERA_SIGNATURES.test(r.server + ' ' + r.body + ' ' + r.location)) camera = true;
        }
      } else if (isRtsp) {
        banner = 'RTSP service';
        camera = true;
      }

      const candidate = { ip: h.ip, port, service, camera, banner: banner.slice(0, 180) };
      if (camera || isRtsp) {
        try {
          candidate.rtspUrls = cameraHacker.rtspUrlsForHost(h.ip, isRtsp ? port : undefined).slice(0, 5);
        } catch (_) {
          candidate.rtspUrls = [];
        }
      }
      candidates.push(candidate);
    }
  }

  return {
    cidr: base.cidr,
    scannedHosts: base.scannedHosts,
    count: candidates.length,
    candidates,
    note: 'TCP-connect probe + HTTP/RTSP fingerprint. Read-only; no authentication attempted.',
  };
}

module.exports = {
  parseCidr,
  scanHosts,
  cameraAudit,
  tcpProbe,
  DEFAULT_HOST_PORTS,
  CAMERA_PORTS,
  httpProbe,
  HTTP_PORTS,
};
