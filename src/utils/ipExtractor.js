/**
 * Secure IP address extraction utility.
 * Prevents IP spoofing attacks by properly validating proxy trust.
 * Implements defense against X-Forwarded-For header manipulation.
 */

const { config } = require('../config');
const logger = require('./logger');

/**
 * Safely extract the real client IP address from a request.
 * 
 * Security Behavior:
 * - If proxy NOT trusted (default): Always use socket IP, ignore headers
 * - If proxy trusted WITH specific IPs: Validate proxy IP before trusting headers
 * - If proxy trusted WITHOUT specific IPs: Trust Express's req.ip (trust proxy: 1)
 * 
 * This prevents attackers from spoofing X-Forwarded-For headers to bypass
 * rate limiting and brute-force protection.
 * 
 * @param {object} req - Express request object
 * @returns {string} The real client IP address
 * 
 * @example
 * // In route handlers or middleware:
 * const ip = getClientIp(req);
 * if (isRateLimited(ip)) { ... }
 */
function getClientIp(req) {
  // If proxy trust is disabled (secure default), always use socket IP
  if (!config.trustProxy) {
    const socketIp = req.socket.remoteAddress || req.connection.remoteAddress || 'unknown';
    return normalizeIp(socketIp);
  }

  // If specific trusted proxy IPs are configured, validate the proxy
  if (config.trustedProxyIps && config.trustedProxyIps.length > 0) {
    const proxyIp = req.socket.remoteAddress || req.connection.remoteAddress;
    
    if (validateProxyChain(proxyIp, config.trustedProxyIps)) {
      // Proxy is trusted, use Express's parsed IP (respects trust proxy setting)
      return normalizeIp(req.ip || proxyIp || 'unknown');
    } else {
      // Proxy is NOT in trusted list, ignore headers and use socket IP
      logger.warn(`Untrusted proxy attempted to set X-Forwarded-For: ${proxyIp}`);
      return normalizeIp(proxyIp || 'unknown');
    }
  }

  // Proxy trust enabled without specific IPs - trust Express's req.ip
  // (Express already configured with 'trust proxy': 1)
  return normalizeIp(req.ip || req.socket.remoteAddress || 'unknown');
}

/**
 * Identity used for security decisions (rate limits, PIN lockouts).
 * `trustSettings` optionally overrides {trustProxy, trustedProxyIps}; the
 * exported config is frozen, so tests need that seam.
 *
 * Unlike getClientIp(), this NEVER lets a request header pick the identity
 * unless the immediate proxy is explicitly whitelisted in TRUSTED_PROXY_IPS.
 * With `TRUST_PROXY=true` but no whitelist, a caller could otherwise send a
 * fresh X-Forwarded-For value on every attempt and sail past both the PIN
 * lockout bucket and the upload limiters (the exact bypass this closes).
 *
 * @param {object} req - Express request object
 * @returns {string} stable client identity
 */
function getSecurityIdentity(req, trustSettings) {
  const socketIp = normalizeIp(
    req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown'
  );

  const trustProxy = trustSettings && 'trustProxy' in trustSettings
    ? trustSettings.trustProxy
    : config.trustProxy;
  const trustedProxyIps = trustSettings && 'trustedProxyIps' in trustSettings
    ? trustSettings.trustedProxyIps
    : config.trustedProxyIps;

  const hasWhitelist = Array.isArray(trustedProxyIps) && trustedProxyIps.length > 0;
  if (trustProxy && hasWhitelist && validateProxyChain(socketIp, trustedProxyIps)) {
    return normalizeIp(req.ip || socketIp);
  }

  return socketIp;
}

/**
 * Validate that the immediate proxy is in the trusted proxy list.
 * 
 * @param {string} proxyIp - IP address of the immediate proxy
 * @param {string[]} trustedIps - Array of trusted proxy IPs
 * @returns {boolean} True if proxy is trusted
 */
function validateProxyChain(proxyIp, trustedIps) {
  if (!proxyIp || !trustedIps || trustedIps.length === 0) {
    return false;
  }

  const normalizedProxyIp = normalizeIp(proxyIp);

  // Check if proxy IP is in the trusted list
  return trustedIps.some(trustedIp => {
    const normalizedTrustedIp = normalizeIp(trustedIp);
    return normalizedProxyIp === normalizedTrustedIp;
  });
}

/**
 * Normalize IP address format.
 * Handles IPv6-mapped IPv4 addresses (::ffff:192.168.1.1 -> 192.168.1.1)
 * 
 * @param {string} ip - IP address to normalize
 * @returns {string} Normalized IP address
 */
function normalizeIp(ip) {
  if (!ip) return 'unknown';
  
  // Convert IPv6-mapped IPv4 to standard IPv4
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  
  return ip;
}

module.exports = {
  getClientIp,
  getSecurityIdentity,
  validateProxyChain,
  normalizeIp
};

