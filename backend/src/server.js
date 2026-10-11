'use strict';

/** Pegasus Suite entry point. Boots only with a safe configuration. */

const { config, validateStartup } = require('./config');

const problems = validateStartup();
if (problems.length) {
  for (const p of problems) {
    process.stdout.write(`[startup] PROBLEM: ${p}\n`);
  }
  process.stdout.write('[startup] Refusing to start. Fix the configuration (see backend/.env).\n');
  process.exit(1);
}

const app = require('./app');

const server = app.listen(config.server.port, config.server.host, () => {
  process.stdout.write(`[startup] Pegasus Suite — http://${config.server.host}:${config.server.port}\n`);
  process.stdout.write(`[startup] env=${config.env} staticDir=${config.server.staticDir}\n`);
  process.stdout.write('[startup] Recon endpoints: POST /api/lan/scan, POST /api/camera/audit, GET /api/lan/subnets\n');
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
