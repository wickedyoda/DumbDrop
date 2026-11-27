/**
 * Security middleware implementations for HTTP-level protection.
 * Sets security headers (CSP, HSTS) and implements PIN-based authentication.
 * Provides Express middleware for securing routes and responses.
 */

const { safeCompare } = require('../utils/security');
const { getSecurityIdentity } = require('../utils/ipExtractor');
const {
  SESSION_COOKIE,
  LEGACY_PIN_COOKIE,
  SESSION_TTL_MS,
  issueSession,
  isValidSession,
} = require('../utils/authSessions');
const logger = require('../utils/logger');
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

/**
 * Security header configuration for helmet.
 *
 * CSP is now enforced. Everything the UI loads is same-origin (styles.css,
 * /toastify/*, assets/*, manifest.json) except inline handlers/`<script>`
 * blocks in the shipped HTML, so script/style need 'unsafe-inline'; there is
 * no remote script or style source in this app. `upgrade-insecure-requests` is
 * deliberately NOT sent because the app is routinely served over plain http on
 * a LAN, where that directive would break every request.
 *
 * HSTS is enabled only when BASE_URL is https, and without includeSubDomains:
 * a wildcard parent (e.g. *.example.com) may still host http-only services.
 */
function getHelmetConfig() {
  const isSecure = BASE_URL.startsWith('https://');

  return {
    noSniff: true, // Prevent MIME type sniffing
    frameguard: { action: 'deny' }, // Prevent clickjacking
    crossOriginEmbedderPolicy: false, // Disable for local network access
    crossOriginOpenerPolicy: false, // Disable to prevent warnings on HTTP
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // Allow cross-origin for local network
    referrerPolicy: { policy: 'no-referrer-when-downgrade' }, // Set referrer policy
    ieNoOpen: true, // Prevent IE from executing downloads
    // includeSubDomains is explicitly off: a parent domain often hosts
    // http-only services, and HSTS there would break them.
    hsts: isSecure ? { maxAge: 15552000 /* 180 days */, includeSubDomains: false } : false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'", 'data:'],
        mediaSrc: ["'self'", 'blob:'],
        manifestSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'self'"],
        formAction: ["'self'"],
      },
    },
    dnsPrefetchControl: true, // Disable DNS prefetching
    permittedCrossDomainPolicies: false,
    originAgentCluster: false,
    xssFilter: false,
  };
}

function buildCookieOptions(req) {
  return {
    httpOnly: true, // Always enable HttpOnly
    secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_TTL_MS,
  };
}

/**
 * PIN protection middleware
 *
 * A browser is authenticated by an opaque session token (see
 * utils/authSessions); the PIN itself is never stored client-side. API/CLI
 * clients may still present the PIN directly through the `x-pin` header.
 *
 * @param {string} PIN - Valid PIN for comparison
 */
function requirePin(PIN) {
  return (req, res, next) => {
    // Skip PIN check if no PIN is configured
    if (!PIN) {
      return next();
    }

    // Session cookie carries an opaque token, not the PIN
    if (isValidSession(req.cookies?.[SESSION_COOKIE])) {
      return next();
    }

    // Header fallback for programmatic clients
    const headerPin = req.headers['x-pin'];
    if (headerPin && safeCompare(headerPin, PIN)) {
      res.cookie(SESSION_COOKIE, issueSession(), buildCookieOptions(req));
      // Old releases put the raw PIN in this cookie; make sure it is gone
      res.clearCookie(LEGACY_PIN_COOKIE, { path: '/' });
      return next();
    }

    logger.warn(`Unauthorized access attempt from IP: ${getSecurityIdentity(req)}`);
    res.status(401).json({ error: 'Unauthorized' });
  };
}

module.exports = {
  getHelmetConfig,
  requirePin,
  buildCookieOptions,
};
