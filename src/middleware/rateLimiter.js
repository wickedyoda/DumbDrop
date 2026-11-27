const rateLimit = require('express-rate-limit');
const { registerCleanupTask } = require('../utils/cleanup');
const { getSecurityIdentity } = require('../utils/ipExtractor');
const { isValidBatchId } = require('../utils/fileUtils');
const logger = require('../utils/logger');

// Create rate limiters
const createLimiter = (options) => {
  const limiter = rateLimit(options);
  // Register cleanup for the rate limiter's store
  if (limiter.store && typeof limiter.store.resetAll === 'function') {
    registerCleanupTask(async () => {
      await limiter.store.resetAll();
    });
  }
  return limiter;
};

function positiveIntFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    logger.warn(`Invalid ${name} value: "${raw}". Using default ${fallback}.`);
    return fallback;
  }
  return parsed;
}

/**
 * Security identity helper: headers may not choose the bucket unless the
 * immediate proxy is whitelisted (see ipExtractor.getSecurityIdentity).
 */
const identityKey = (req) => getSecurityIdentity(req);

/**
 * Rate limiter for upload initialization.
 * Limits the number of NEW upload jobs/batches a client can start.
 *
 * This used to `skip` any request carrying an `x-batch-id` header, which meant
 * a client could opt out of the limit entirely by setting a header. The header
 * is no longer a get-out-of-jail card; see uploadInitLimiter below for how
 * legitimate multi-file batches are still allowed to proceed quickly.
 */
const initUploadLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute window
  max: positiveIntFromEnv('UPLOAD_INIT_RATE_LIMIT', 30), // 30 upload jobs per minute
  message: {
    error: 'Too many upload jobs started. Please wait before starting new uploads.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: identityKey
});

/**
 * Rate limiter for chunk uploads.
 * More permissive to allow large file uploads.
 */
const chunkUploadLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute window
  max: positiveIntFromEnv('UPLOAD_CHUNK_RATE_LIMIT', 600), // chunks per minute
  message: {
    error: 'Upload rate limit exceeded. Please wait before continuing.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: identityKey
});

/**
 * Batch registry: first time we see a client-supplied batch id from an
 * identity, that request is charged to the normal init limiter. Later
 * initialisations of the SAME batch from the SAME identity get the generous
 * batch tier, so folder uploads keep moving while a caller that simply invents
 * new batch ids still hits the per-identity cap.
 */
const BATCH_TTL_MS = 30 * 60 * 1000; // matches the batch session timeout in routes/upload.js
const MAX_KNOWN_BATCHES = 20000;
/** @type {Map<string, {identity: string, lastSeen: number}>} */
const knownBatches = new Map();

function rememberBatch(batchId, identity) {
  const now = Date.now();

  for (const [id, entry] of knownBatches.entries()) {
    if (now - entry.lastSeen >= BATCH_TTL_MS) knownBatches.delete(id);
  }
  if (knownBatches.size >= MAX_KNOWN_BATCHES) {
    // Map is insertion ordered: drop the oldest batch registrations first
    for (const id of knownBatches.keys()) {
      knownBatches.delete(id);
      break;
    }
  }

  knownBatches.set(batchId, { identity, lastSeen: now });
}

function isKnownBatchFor(batchId, identity) {
  const entry = knownBatches.get(batchId);
  if (!entry) return false;
  if (Date.now() - entry.lastSeen >= BATCH_TTL_MS) {
    knownBatches.delete(batchId);
    return false;
  }
  entry.lastSeen = Date.now();
  return entry.identity === identity;
}

const batchInitUploadLimiter = createLimiter({
  windowMs: 60 * 1000,
  max: positiveIntFromEnv('UPLOAD_BATCH_INIT_RATE_LIMIT', 600), // files per minute within a known batch
  message: {
    error: 'Too many files started in this batch. Please wait before adding more.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${identityKey(req)}|batch:${req.headers['x-batch-id']}`
});

/**
 * Upload init limiter that keeps folder/batch uploads usable without letting a
 * header disable rate limiting.
 */
function uploadInitLimiter(req, res, next) {
  const rawBatchId = req.headers['x-batch-id'];
  const batchId = typeof rawBatchId === 'string' && isValidBatchId(rawBatchId) ? rawBatchId : '';
  const identity = identityKey(req);

  if (batchId && isKnownBatchFor(batchId, identity)) {
    return batchInitUploadLimiter(req, res, next);
  }

  // Register on first sight even if this request is then throttled, so a
  // genuine batch can continue on the next init. Garbage-shaped batch ids are
  // ignored entirely (the route rejects them anyway) and stay in the per-identity
  // bucket.
  if (batchId) rememberBatch(batchId, identity);
  return initUploadLimiter(req, res, next);
}

/**
 * Rate limiter for PIN verification attempts
 * Prevents brute force attacks on actual PIN verification
 */
const pinVerifyLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 minutes
  message: {
    error: 'Too many PIN verification attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: identityKey,
  // Apply strict rate limiting only to PIN verification, not PIN status checks
  skip: (req) => {
    return req.path === '/pin-required'; // Skip rate limiting for PIN requirement checks
  }
});

/**
 * Rate limiter for PIN status checks
 * More permissive for checking if PIN is required
 */
const pinStatusLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute window
  max: 30, // 30 requests per minute
  message: {
    error: 'Too many requests. Please wait before trying again.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: identityKey
});

/**
 * Rate limiter for file downloads
 * Prevents abuse of the download system
 */
const downloadLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute window
  max: positiveIntFromEnv('DOWNLOAD_RATE_LIMIT', 60), // downloads per minute
  message: {
    error: 'Download rate limit exceeded. Please wait before downloading more files.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: identityKey
});

module.exports = {
  initUploadLimiter,
  batchInitUploadLimiter,
  uploadInitLimiter,
  chunkUploadLimiter,
  pinVerifyLimiter,
  pinStatusLimiter,
  downloadLimiter,
  // exposed for tests and cleanup tooling
  _knownBatches: knownBatches
};
