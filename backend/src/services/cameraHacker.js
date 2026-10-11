'use strict';

/**
 * Camera / RTSP reconnaissance helpers.
 *
 * Turns a CIDR range into a bounded host list and, for a given host, builds
 * the candidate RTSP/ONVIF URLs to probe. This module performs NO scanning by
 * itself — it only produces plans and URLs that the operator's tooling (or the
 * Android app) exercises, strictly against authorized assets.
 */

const CANDIDATE_PATHS = [
  '/Streaming/Channels/101', // Hikvision main stream
  '/stream1',                // Dahua / generic
  '/h264',                   // generic
  '/onvif1',                 // ONVIF media profile
];

const DEFAULT_RTSP_PORT = 554;
const MAX_HOSTS = 254; // never produce more than a /24 worth of hosts

function ipToInt(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) throw new Error('Invalid IP: 4 octets required.');
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error(`Invalid IP octet: ${p}`);
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * Parse a CIDR such as "192.168.1.0/24".
 * The network address MUST be written with all four octets (e.g. "192.168.1.0",
 * not "192.168.1"). Returns { baseIp, prefix, hosts:[...] } capped at MAX_HOSTS.
 */
function parseCIDR(cidr) {
  const m = String(cidr || '').trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) throw new Error('Invalid CIDR. Expected format: 192.168.1.0/24 (4 octets).');
  const baseInt = ipToInt(m[1]);
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 32) throw new Error('Invalid CIDR prefix (0-32).');
  if (prefix < 24) throw new Error('Prefix too broad: limit to /24 or narrower.');

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  const first = network + 1;
  const last = network + size - 2;

  const hosts = [];
  for (let ip = first; ip <= last && hosts.length < MAX_HOSTS; ip++) {
    hosts.push(intToIp(ip >>> 0));
  }
  return { baseIp: intToIp(network), prefix, size, hostCount: hosts.length, hosts };
}

/** Candidate RTSP URLs for a single host. */
function rtspUrlsForHost(host, port = DEFAULT_RTSP_PORT) {
  const h = String(host).trim();
  if (!h) throw new Error('Host is required.');
  return CANDIDATE_PATHS.map((p) => `rtsp://${h}:${port}${p}`);
}

/** Full scan plan for a CIDR: host list + candidate URLs, host-bounded. */
function buildScanPlan(cidr, port = DEFAULT_RTSP_PORT) {
  const { baseIp, prefix, hosts } = parseCIDR(cidr);
  return {
    cidr: `${baseIp}/${prefix}`,
    baseIp,
    prefix,
    port,
    hostCount: hosts.length,
    hosts,
    candidatePaths: [...CANDIDATE_PATHS],
    sampleUrls: hosts.slice(0, 3).map((h) => rtspUrlsForHost(h, port)),
    note: 'RTSP reconnaissance plan. Run only against authorized assets.',
  };
}

module.exports = { parseCIDR, rtspUrlsForHost, buildScanPlan, CANDIDATE_PATHS, MAX_HOSTS };
