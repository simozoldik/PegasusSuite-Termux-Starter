'use strict';

/**
 * Error catalog (English). Every user-facing message is truthful: the API
 * NEVER reports a fabricated success. Codes are stable machine identifiers;
 * `guidance` tells the operator what to do next.
 */

class AppError extends Error {
  /**
   * @param {string} code     stable machine code
   * @param {number} http     HTTP status for the API response
   * @param {string} message  human-readable message
   * @param {string} guidance what the operator should do next
   * @param {object} [details] optional structured details (logged, not shown raw)
   */
  constructor(code, http, message, guidance, details = undefined) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.http = http;
    this.guidance = guidance;
    this.details = details;
  }
}

const ERRORS = {
  RATE_LIMITED: () => new AppError('RATE_LIMITED', 429,
    'Too many requests. Please wait a moment.',
    'Retry after the rate-limit window has elapsed.'),
  VALIDATION_ERROR: () => new AppError('VALIDATION_ERROR', 400,
    'Invalid request.',
    'Check the parameters you sent.'),
  SCAN_TARGET_INVALID: () => new AppError('SCAN_TARGET_INVALID', 422,
    'Invalid scan target.',
    'Provide a private CIDR such as 192.168.1.0/24 and a bounded port list.'),
  SCAN_TARGET_NOT_PRIVATE: () => new AppError('SCAN_TARGET_NOT_PRIVATE', 403,
    'Scan target is outside the permitted private ranges.',
    'This tool only scans RFC1918 private networks. Enter a private subnet.'),
  SCAN_TIMEOUT: () => new AppError('SCAN_TIMEOUT', 504,
    'The scan did not finish in time.',
    'Reduce the CIDR size or the port list and retry.'),
  NOT_FOUND: () => new AppError('NOT_FOUND', 404,
    'Resource not found.',
    'Check the requested path.'),
  INTERNAL: () => new AppError('INTERNAL', 500,
    'Unexpected internal error.',
    'Retry. If the problem persists, check the server logs with the timestamp.'),
};

module.exports = { AppError, ERRORS };
