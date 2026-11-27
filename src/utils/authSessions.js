/**
 * Opaque browser sessions for PIN-protected access.
 *
 * The PIN itself is never written to a cookie: once /api/auth/verify-pin
 * confirms the PIN, this module issues a random, single-use-of-secret token and
 * the browser only ever holds that token. Tokens live in memory and expire.
 */

const crypto = require('crypto');

const SESSION_COOKIE = 'DUMBDROP_SESSION';
/** Cookie used by older releases, which stored the raw PIN in it. */
const LEGACY_PIN_COOKIE = 'DUMBDROP_PIN';

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours, matching the old cookie lifetime
const MAX_SESSIONS = 50000; // bound memory: Map is insertion-ordered, so the oldest go first

/** @type {Map<string, number>} token -> absolute expiry (ms epoch) */
const sessions = new Map();

function purgeExpired(now = Date.now()) {
  for (const [token, expiresAt] of sessions.entries()) {
    if (expiresAt <= now) sessions.delete(token);
  }
}

/**
 * Issue a new session token.
 * @returns {string} opaque token safe to hand to a browser
 */
function issueSession() {
  purgeExpired();

  if (sessions.size >= MAX_SESSIONS) {
    const excess = sessions.size - MAX_SESSIONS + 1;
    let dropped = 0;
    for (const token of sessions.keys()) {
      sessions.delete(token);
      if (++dropped >= excess) break;
    }
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

/**
 * @param {unknown} token
 * @returns {boolean} true when the token was issued here and has not expired
 */
function isValidSession(token) {
  if (typeof token !== 'string' || token.length < 32) return false;
  const expiresAt = sessions.get(token);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    sessions.delete(token);
    return false;
  }
  return true;
}

/**
 * @param {unknown} token
 */
function revokeSession(token) {
  if (typeof token === 'string') sessions.delete(token);
}

function sessionCount() {
  return sessions.size;
}

module.exports = {
  SESSION_COOKIE,
  LEGACY_PIN_COOKIE,
  SESSION_TTL_MS,
  MAX_SESSIONS,
  issueSession,
  isValidSession,
  revokeSession,
  purgeExpired,
  sessionCount,
};
