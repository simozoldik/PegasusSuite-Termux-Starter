'use strict';

/**
 * Cell Tower Triangulation — weighted least-squares (Gauss–Newton)
 * multilateration of a mobile device position from surrounding cell towers.
 *
 * Input model
 * -----------
 * Each tower sample: { cellId, mcc, mnc, lac, lat?, lon?, rssi? }
 *   - When the tower carries explicit `lat`/`lon` they are used directly.
 *   - Otherwise the position is resolved from the Cell-ID database
 *     (data/cells.json + SEED_CELLS) or, failing that, from a DETERMINISTIC
 *     fallback derived from the cell key (so results are reproducible).
 *   - `rssi` (dBm) is converted to an approximate range via the log-distance
 *     path-loss model. Without rssi a neutral default range is used.
 *
 * Output model
 * ------------
 * { method, confidence, location:{lat,lon}, accuracyMeters, rmsMeters,
 *   towers:[...], samples }
 *
 * method      : 'triangulation' | 'single_cell' | 'unknown'
 * confidence  : 'high' | 'medium' | 'low' | 'none'
 *
 * NOTE: this is a positioning ESTIMATE, not a guarantee. Cell-ID based
 * positioning is inherently coarse; use it only with explicit authorization
 * on assets you own or are contracted to test.
 */

const fs = require('node:fs');
const path = require('node:path');

const CASABLANCA = { lat: 33.5731, lon: -7.5898 };
const EARTH_R = 6371000; // meters
const RSSI_REF_DBM = -40;   // reference RSSI at REF_DIST_M
const REF_DIST_M = 100;      // reference distance (m)
const PATH_LOSS_N = 3.2;     // environment exponent (urban macro-cell)

// A few seed cells (MCC 604 / MNC 01) so a demo triangulation
// produces a plausible, stable geometry. A production deployment replaces
// this with a full Cell-ID -> position database (data/cells.json overrides).
const SEED_CELLS = {
  '604:1:12345:6789': { lat: 33.5902, lon: -7.6031 },
  '604:1:12345:6790': { lat: 33.5731, lon: -7.5898 },
  '604:1:12345:6791': { lat: 33.5560, lon: -7.6205 },
  '604:1:22201:4102': { lat: 33.5990, lon: -7.5750 },
  '604:1:22201:4103': { lat: 33.5480, lon: -7.6000 },
};

let DB_CACHE = null;

function loadCellDb() {
  if (DB_CACHE) return DB_CACHE;
  DB_CACHE = { ...SEED_CELLS };
  const file = path.join(__dirname, '..', 'data', 'cells.json');
  try {
    if (fs.existsSync(file)) {
      const extra = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const [k, v] of Object.entries(extra)) {
        if (v && Number.isFinite(v.lat) && Number.isFinite(v.lon)) DB_CACHE[k] = { lat: v.lat, lon: v.lon };
      }
    }
  } catch { /* non-fatal: fall back to seeds only */ }
  return DB_CACHE;
}

function cellKey(t) {
  const mcc = t.mcc != null ? String(t.mcc) : '604';
  const mnc = t.mnc != null ? String(t.mnc) : '1';
  const lac = t.lac != null ? String(t.lac) : '0';
  const cid = t.cellId != null ? String(t.cellId) : '0';
  return `${mcc}:${mnc}:${lac}:${cid}`;
}

function hash32(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

/** Deterministic pseudo-position around Casablanca for unknown cells. */
function fallbackPosition(key) {
  const h = hash32(key);
  const northM = ((h % 20000) - 10000);        // +/-10 km
  const eastM = (((h >> 8) % 20000) - 10000);  // +/-10 km
  return offsetLatLon(CASABLANCA, northM, eastM);
}

function toRad(d) { return (d * Math.PI) / 180; }
function toDeg(r) { return (r * 180) / Math.PI; }

function offsetLatLon(base, northM, eastM) {
  const dLat = northM / EARTH_R;
  const dLon = eastM / (EARTH_R * Math.cos(toRad(base.lat)));
  return { lat: base.lat + toDeg(dLat), lon: base.lon + toDeg(dLon) };
}

function haversine(a, b) {
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const la1 = toRad(a.lat);
  const la2 = toRad(b.lat);
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_R * Math.asin(Math.min(1, Math.sqrt(x)));
}

/** RSSI (dBm) -> range (m) via log-distance path loss around a reference. */
function estimateRangeM(dbm) {
  if (!Number.isFinite(dbm)) return 1000;
  const d = REF_DIST_M * 10 ** ((RSSI_REF_DBM - dbm) / (10 * PATH_LOSS_N));
  return Math.max(50, Math.min(8000, d));
}

/** Local ENU (east, north) meters relative to a reference lat/lon. */
function toEnu(ref, p) {
  const north = toRad(p.lat - ref.lat) * EARTH_R;
  const east = toRad(p.lon - ref.lon) * EARTH_R * Math.cos(toRad(ref.lat));
  return { e: east, n: north };
}
function fromEnu(ref, e, n) {
  const lat = ref.lat + toDeg(n / EARTH_R);
  const lon = ref.lon + toDeg(e / (EARTH_R * Math.cos(toRad(ref.lat))));
  return { lat, lon };
}

function resolveTower(t) {
  const key = cellKey(t);
  if (Number.isFinite(t.lat) && Number.isFinite(t.lon)) {
    return { key, lat: t.lat, lon: t.lon, source: 'input' };
  }
  const db = loadCellDb();
  if (db[key]) return { key, ...db[key], source: 'db' };
  const fb = fallbackPosition(key);
  return { key, ...fb, source: 'fallback' };
}

function weightedCentroid(pts, weights) {
  let sw = 0, se = 0, sn = 0;
  for (let i = 0; i < pts.length; i++) {
    const w = weights[i];
    se += pts[i].e * w;
    sn += pts[i].n * w;
    sw += w;
  }
  if (sw === 0) return { e: 0, n: 0 };
  return { e: se / sw, n: sn / sw };
}

/**
 * Gauss–Newton WLS multilateration.
 * Minimizes sum_i w_i * (dist(x, p_i) - r_i)^2 in local ENU coordinates.
 */
function gaussNewton(pts, ranges, weights) {
  let x = weightedCentroid(pts, weights);
  const ITER = 25;
  for (let it = 0; it < ITER; it++) {
    let a11 = 0, a12 = 0, a22 = 0, b1 = 0, b2 = 0;
    for (let i = 0; i < pts.length; i++) {
      const dx = x.e - pts[i].e;
      const dy = x.n - pts[i].n;
      const d = Math.hypot(dx, dy) || 1e-6;
      const residual = d - ranges[i];
      const jx = dx / d;
      const jy = dy / d;
      const w = weights[i];
      a11 += w * jx * jx;
      a12 += w * jx * jy;
      a22 += w * jy * jy;
      b1 += w * jx * residual;
      b2 += w * jy * residual;
    }
    const det = a11 * a22 - a12 * a12;
    if (Math.abs(det) < 1e-9) break; // degenerate geometry
    const dE = -(a22 * b1 - a12 * b2) / det;
    const dN = -(a11 * b2 - a12 * b1) / det;
    x = { e: x.e + dE, n: x.n + dN };
    if (Math.hypot(dE, dN) < 0.1) break; // converged (<10 cm)
  }
  return x;
}

function rmsError(pts, ranges, x) {
  let s = 0;
  for (let i = 0; i < pts.length; i++) {
    const d = Math.hypot(x.e - pts[i].e, x.n - pts[i].n);
    s += (d - ranges[i]) ** 2;
  }
  return Math.sqrt(s / pts.length);
}

function triangulate(rawTowers) {
  const towers = Array.isArray(rawTowers) ? rawTowers.filter(Boolean) : [];
  const resolved = towers.map((t) => {
    const pos = resolveTower(t);
    const range = estimateRangeM(Number(t.rssi));
    return {
      cellId: t.cellId != null ? t.cellId : null,
      lac: t.lac != null ? t.lac : null,
      mcc: t.mcc != null ? t.mcc : 604,
      mnc: t.mnc != null ? t.mnc : 1,
      lat: Number(pos.lat.toFixed(6)),
      lon: Number(pos.lon.toFixed(6)),
      positionSource: pos.source,
      rangeMeters: Number(range.toFixed(1)),
      rssi: Number.isFinite(Number(t.rssi)) ? Number(t.rssi) : null,
    };
  });

  if (resolved.length === 0) {
    return {
      method: 'unknown',
      confidence: 'none',
      location: null,
      accuracyMeters: null,
      rmsMeters: null,
      towers: [],
      samples: 0,
      note: 'No usable cell tower was provided.',
    };
  }

  const ref = { lat: resolved[0].lat, lon: resolved[0].lon };

  if (resolved.length === 1) {
    return {
      method: 'single_cell',
      confidence: 'low',
      location: { lat: resolved[0].lat, lon: resolved[0].lon },
      accuracyMeters: 3000,
      rmsMeters: null,
      towers: resolved,
      samples: 1,
      note: 'Approximate position from a single cell (metro-scale accuracy).',
    };
  }

  const pts = resolved.map((r) => toEnu(ref, r));
  const ranges = resolved.map((r) => r.rangeMeters);
  // Nearer (stronger) cells are trusted more.
  const weights = resolved.map((r) => (Number.isFinite(r.rangeMeters) ? 1 / (1 + r.rangeMeters / 1000) : 0.5));

  const x = gaussNewton(pts, ranges, weights);
  const rms = rmsError(pts, ranges, x);
  const loc = fromEnu(ref, x.e, x.n);

  const n = resolved.length;
  let confidence = 'medium';
  if (n >= 3) confidence = rms <= 900 ? 'high' : 'medium';
  else confidence = 'medium';
  // Wide spread in unresolved positions downgrades confidence.
  if (resolved.some((r) => r.positionSource === 'fallback') && confidence === 'high') confidence = 'medium';

  const accuracy = Math.round(Math.max(50, rms) * 1.5);

  return {
    method: 'triangulation',
    confidence,
    location: { lat: Number(loc.lat.toFixed(6)), lon: Number(loc.lon.toFixed(6)) },
    accuracyMeters: accuracy,
    rmsMeters: Number(rms.toFixed(1)),
    towers: resolved,
    samples: n,
    note: `WLS multilateration over ${n} cells (Gauss-Newton).`,
  };
}

module.exports = { triangulate, cellKey, estimateRangeM, fallbackPosition, haversine };
