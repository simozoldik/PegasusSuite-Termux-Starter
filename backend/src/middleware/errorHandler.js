'use strict';

/** Central error handler: AppError -> JSON payload; anything else -> 500. */

const { AppError, ERRORS } = require('../lib/errors');
const logger = require('../lib/logger');

function notFound(req, res, next) {
  next(ERRORS.NOT_FOUND());
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err instanceof AppError) {
    if (err.http >= 500) {
      logger.error(err.code, { detail: err.detail, path: req.path });
    }
    return res.status(err.http).json({
      error: {
        code: err.code,
        message: err.message,
        guidance: err.guidance,
        details: err.details || undefined,
      },
    });
  }

  // Body-parser JSON syntax errors -> 400, not 500.
  if (err && err.type === 'entity.parse.failed') {
    const e = ERRORS.VALIDATION_ERROR();
    return res.status(e.http).json({ error: { code: e.code, message: e.message, guidance: e.guidance } });
  }

  logger.error('unhandled', { path: req.path, message: String(err && err.message) });
  const e = ERRORS.INTERNAL();
  return res.status(e.http).json({ error: { code: e.code, message: e.message, guidance: e.guidance } });
}

module.exports = { notFound, errorHandler };
