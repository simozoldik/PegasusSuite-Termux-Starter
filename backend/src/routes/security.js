'use strict';

/**
 * Security Suite API (Pegasus field-recon backend).
 *
 *   POST /api/lan/scan              -> bounded TCP-connect host discovery over a CIDR
 *   POST /api/camera/audit          -> camera-focused TCP/HTTP/RTSP fingerprint
 *   GET  /api/lan/subnets           -> private subnets the backend host is on
 *   POST /api/location/triangulate  -> cell-tower multilateration
 *   POST /api/camera/scan-plan      -> RTSP scan plan for a CIDR
 *   GET  /api/camera/rtsp-urls      -> candidate RTSP URLs for one host
 *   POST /api/wifi/parse-handshake  -> parse a .22000 capture
 *   POST /api/wifi/crack-plan       -> build a hashcat plan (no execution)
 *   POST /api/phone/scan-plan       -> plan for nearby-device enumeration
 *   POST /api/phone/discover        -> live nearby-phone discovery (ARP+ping+mDNS/NBNS)
 *   POST /api/phone/audit           -> start a 9-step phone audit job (returns 202 + jobId)
 *   GET  /api/phone/audit/:jobId    -> job status incl. REAL progress, score, level
 *   POST /api/phone/audit/:jobId/cancel -> cancel a running audit job
 *   GET  /api/security/all          -> aggregate capability report
 *
 * These endpoints are open (no account required) so the app can call them
 * directly. The active endpoints (/lan/scan, /camera/audit) only perform
 * bounded, read-only TCP-connect/HTTP fingerprinting against the requested
 * private subnet; targets are validated as RFC1918 before any probe is sent.
 */

const os = require('node:os');
const express = require('express');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const cellTriangulation = require('../services/cellTriangulation');
const cameraHacker = require('../services/cameraHacker');
const wifiCracker = require('../services/wifiCracker');
const lanAudit = require('../services/lanAudit');
const phoneAudit = require('../services/phoneAudit');

const router = express.Router();

const securityLimiter = rateLimit({
  windowMs: config.rateLimit.apiWindowMs,
  max: config.rateLimit.apiMax,
  standardHeaders: true,
  legacyHeaders: false,
});

router.use(securityLimiter);

function badRequest(res, message) {
  return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message, guidance: 'Check the parameters you sent.' } });
}

/* ---------------- LAN host discovery (live TCP-connect scan) ---------------- */

router.post('/lan/scan', async (req, res, next) => {
  try {
    const body = req.body || {};
    const cidr = body.cidr || config.scan.defaultCidr;
    const ports = Array.isArray(body.ports) && body.ports.length ? body.ports : undefined;
    const result = await lanAudit.scanHosts(cidr, ports, {
      timeoutMs: body.timeoutMs,
      concurrency: body.concurrency,
    });
    res.json(result);
  } catch (err) {
    if (/CIDR|octet|prefix/.test(err.message)) return badRequest(res, err.message);
    next(err);
  }
});

/* ---------------- camera audit (TCP + HTTP/RTSP fingerprint) ---------------- */

router.post('/camera/audit', async (req, res, next) => {
  try {
    const body = req.body || {};
    const cidr = body.cidr || config.scan.defaultCidr;
    const result = await lanAudit.cameraAudit(cidr, {
      timeoutMs: body.timeoutMs,
      httpTimeoutMs: body.httpTimeoutMs,
      concurrency: body.concurrency,
    });
    res.json(result);
  } catch (err) {
    if (/CIDR|octet|prefix/.test(err.message)) return badRequest(res, err.message);
    next(err);
  }
});

/* ---------------- backend host subnets (helps pick a target CIDR) ------------ */

router.get('/lan/subnets', (req, res) => {
  const nets = os.networkInterfaces();
  const subnets = [];
  for (const [name, addrs] of Object.entries(nets)) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      const ip = a.address;
      const priv = /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
      if (!priv) continue;
      const cidr = ip.split('.').slice(0, 3).join('.') + '.0/24';
      subnets.push({ iface: name, ip, cidr });
    }
  }
  res.json({ subnets });
});

/* ---------------- location / triangulation ---------------- */

router.post('/location/triangulate', (req, res, next) => {
  try {
    const body = req.body || {};
    const towers = body.towers;
    if (!Array.isArray(towers) || towers.length === 0) {
      return badRequest(res, 'Provide a non-empty "towers" array.');
    }
    const result = cellTriangulation.triangulate(towers);
    res.json(result);
  } catch (err) { next(err); }
});

/* ---------------- camera / RTSP ---------------- */

router.post('/camera/scan-plan', (req, res) => {
  try {
    const { cidr, port } = req.body || {};
    if (!cidr) return badRequest(res, 'Provide a "cidr" (e.g. 192.168.1.0/24).');
    const plan = cameraHacker.buildScanPlan(cidr, port ? Number(port) : undefined);
    res.json(plan);
  } catch (err) {
    return badRequest(res, err.message);
  }
});

router.get('/camera/rtsp-urls', (req, res) => {
  try {
    const host = req.query.host;
    if (!host) return badRequest(res, 'Provide "host" (e.g. 192.168.1.10).');
    const urls = cameraHacker.rtspUrlsForHost(host, req.query.port ? Number(req.query.port) : undefined);
    res.json({ host: String(host), count: urls.length, urls });
  } catch (err) {
    return badRequest(res, err.message);
  }
});

/* ---------------- wifi ---------------- */

router.post('/wifi/parse-handshake', (req, res) => {
  try {
    const body = req.body || {};
    const text = typeof body === 'string' ? body : (body.text || body.data || '');
    if (!text) return badRequest(res, 'Provide the handshake content in "text".');
    const parsed = wifiCracker.parseHandshake(text);
    res.json(parsed);
  } catch (err) { return badRequest(res, err.message); }
});

router.post('/wifi/crack-plan', (req, res, next) => {
  try {
    const plan = wifiCracker.crackPlan(req.body || {});
    res.json(plan);
  } catch (err) { next(err); }
});

/* ---------------- phone / nearby-device enumeration ---------------- */

router.post('/phone/scan-plan', (req, res) => {
  try {
    const { cidr, port } = req.body || {};
    const c = cidr || config.scan.defaultCidr;
    const plan = cameraHacker.buildScanPlan(c, port ? Number(port) : 80);
    res.json({
      cidr: plan.cidr,
      hostCount: plan.hostCount,
      hosts: plan.hosts,
      probes: ['arp', 'icmp', 'tcp:80', 'tcp:443', 'tcp:62078', 'mdns'],
      note: 'Local-network device enumeration plan. Restricted to authorized assets.' ,
    });
  } catch (err) {
    return badRequest(res, err.message);
  }
});

/* ---------------- phone discovery + audit (real progress) ---------------- */

router.post('/phone/discover', async (req, res, next) => {
  try {
    const result = await phoneAudit.discoverPhones({
      cidr: (req.body || {}).cidr,
      timeoutMs: (req.body || {}).timeoutMs,
      concurrency: (req.body || {}).concurrency,
    });
    res.json(result);
  } catch (err) {
    if (/CIDR|octet|prefix|subnet/i.test(err.message)) return badRequest(res, err.message);
    next(err);
  }
});

router.post('/phone/audit', (req, res, next) => {
  try {
    const ip = (req.body || {}).ip;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(String(ip || ''))) {
      return badRequest(res, 'Provide a target phone IP in "ip" (e.g. 192.168.1.34).');
    }
    const job = phoneAudit.startAudit(String(ip), {
      timeoutMs: (req.body || {}).timeoutMs,
      tcpTimeoutMs: (req.body || {}).tcpTimeoutMs,
    });
    res.status(202).json({ jobId: job.id, job: phoneAudit.publicJob(job) });
  } catch (err) {
    if (/private IPv4/.test(err.message)) return badRequest(res, err.message);
    next(err);
  }
});

router.get('/phone/audit/:jobId', (req, res) => {
  const job = phoneAudit.getAudit(req.params.jobId);
  if (!job) return badRequest(res, 'Unknown jobId.');
  res.json(phoneAudit.publicJob(job));
});

router.post('/phone/audit/:jobId/cancel', (req, res) => {
  const job = phoneAudit.cancelAudit(req.params.jobId);
  if (!job) return badRequest(res, 'Unknown jobId.');
  res.json(phoneAudit.publicJob(job));
});

/* ---------------- aggregate capability report ---------------- */

router.get('/security/all', (req, res) => {
  res.json({
    ok: true,
    version: '2.0.0',
    env: config.env,
    modules: {
      lanAudit: {
        endpoints: ['POST /api/lan/scan', 'POST /api/camera/audit', 'GET /api/lan/subnets'],
        defaultPorts: lanAudit.DEFAULT_HOST_PORTS,
        cameraPorts: lanAudit.CAMERA_PORTS,
      },
      cellTriangulation: {
        endpoint: 'POST /api/location/triangulate',
        methods: ['triangulation', 'single_cell', 'unknown'],
      },
      phoneAudit: {
        endpoints: ['POST /api/phone/discover', 'POST /api/phone/audit', 'GET /api/phone/audit/:jobId', 'POST /api/phone/audit/:jobId/cancel'],
        auditSteps: phoneAudit.AUDIT_STEPS.map(([id, label]) => id),
        phonePorts: phoneAudit.PHONE_PORTS,
        probes: ['arp', 'icmp', 'tcp', 'mdns', 'nbns', 'adb', 'http'],
      },
      cameraHacker: {
        endpoints: ['POST /api/camera/scan-plan', 'GET /api/camera/rtsp-urls'],
        candidatePaths: cameraHacker.CANDIDATE_PATHS,
      },
      wifiCracker: {
        endpoints: ['POST /api/wifi/parse-handshake', 'POST /api/wifi/crack-plan'],
        hashMode: 22000,
      },
    },
  });
});

module.exports = router;
