'use strict';

/**
 * Pegasus Suite — Express application assembly.
 *
 * A single, small surface:
 *   - /api/*  : read-only reconnaissance endpoints (see routes/security.js)
 *   - /       : the static Pegasus frontend (same assets bundled into the APK)
 *
 * There is NO login, NO user account and NO business/payment workflow.
 */

const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const config = require('./config');
const securityRoutes = require('./routes/security');
const cors = require('./middleware/cors');
const { notFound, errorHandler } = require('./middleware/errorHandler');

const app = express();
app.disable('x-powered-by');
if (config.server.trustProxy) app.set('trust proxy', 1);

// HTTPS enforcement behind a reverse proxy.
app.use((req, res, next) => {
  if (config.server.requireHttps && req.get('x-forwarded-proto') !== 'https') {
    return res.status(400).json({ error: { code: 'HTTPS_REQUIRED', message: 'HTTPS required.', guidance: 'Retry over HTTPS.' } });
  }
  next();
});

// CORS for the native (Capacitor) WebView — must run BEFORE the API routes so
// the preflight OPTIONS is answered without hitting the router.
app.use(cors);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
}));

app.use(express.json({ limit: '256kb' }));

/* ---------------- API (read-only reconnaissance) ---------------- */

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', env: config.env, service: 'pegasus-suite', version: '2.0.0' });
});

// alias: some builds probe the bare /health path (SPA fallback would return HTML)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', env: config.env, service: 'pegasus-suite', version: '2.0.0' });
});

app.use('/api', securityRoutes);

/* ---------------- Static frontend ---------------- */

app.use(express.static(config.server.staticDir, {
  index: 'index.html',
  maxAge: '1h',
  setHeaders(res) {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  },
}));

// SPA fallback for any other app path: serve the shell. Unknown /api/* never
// reaches here (it is handled by the API router / notFound below).
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  if (req.accepts('html')) return res.sendFile(path.join(config.server.staticDir, 'index.html'));
  next();
});

app.use(notFound);
app.use(errorHandler);

module.exports = app;
