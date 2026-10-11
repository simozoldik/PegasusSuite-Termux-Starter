'use strict';

/**
 * Minimal, allow-listed CORS middleware for the native (Capacitor) WebView.
 *
 * WHY THIS IS NEEDED
 * ------------------
 * On Android the app is rendered by the system WebView from the Capacitor
 * origin `https://localhost` (capacitor.config.json -> server.androidScheme
 * "https"). Every API call the app makes there is therefore CROSS-ORIGIN,
 * unlike the browser version which calls a same-origin `/api`. Two
 * consequences:
 *
 *   1. API calls that send `Content-Type: application/json` (the scan
 *      endpoints) trigger a CORS PREFLIGHT (OPTIONS). Without CORS the
 *      preflight is answered with no CORS headers and the request never
 *      happens.
 *   2. Even a "simple" GET is sent, but the WebView refuses to expose the
 *      response unless `Access-Control-Allow-Origin` matches its origin.
 *
 * Both failure modes surface in the frontend as a rejected `fetch` (the
 * "Backend unreachable" message in frontend/app.js api()).
 *
 * SAFETY
 * ------
 * - Only EXPLICITLY allow-listed origins are reflected. Never `*`.
 * - No `Access-Control-Allow-Credentials`: the API uses no cookies.
 */

const config = require('../config');

// Origins the Capacitor WebView can present. These are NOT network secrets.
const DEFAULT_ORIGINS = [
  'https://localhost',     // Capacitor Android (androidScheme = "https")
  'capacitor://localhost', // Capacitor iOS (scheme = "capacitor")
  'http://localhost',
  'http://127.0.0.1',
];

function allowedOriginSet() {
  const configured = (config.server && config.server.allowedOrigins) || [];
  return new Set([...DEFAULT_ORIGINS, ...configured]);
}

function cors(req, res, next) {
  const origin = req.get('origin');

  if (origin && allowedOriginSet().has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }

  // Answer the preflight for API routes here so a legitimate WebView preflight
  // is answered before the router. A preflight from a non-allow-listed origin
  // gets NO CORS headers and is blocked by the WebView.
  if (req.method === 'OPTIONS' && (req.path === '/api' || req.path.startsWith('/api/'))) {
    return res.sendStatus(204);
  }

  next();
}

module.exports = cors;
