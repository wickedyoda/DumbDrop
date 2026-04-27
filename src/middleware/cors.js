const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || process.env.ALLOWED_IFRAME_ORIGINS || '*';
const NODE_ENV = process.env.NODE_ENV || 'production';
let allowedOrigins = [];

function setupOrigins(baseUrl) {
    const normalizedBaseUrl = normalizeOrigin(baseUrl);
    allowedOrigins = [ normalizedBaseUrl ];

    if (NODE_ENV === 'development' || ALLOWED_ORIGINS === '*') allowedOrigins = '*';
    else if (ALLOWED_ORIGINS && typeof ALLOWED_ORIGINS === 'string') {
        try {
          const allowed = ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
          allowed.forEach(origin => {
              const normalizedOrigin = normalizeOrigin(origin);
              if (normalizedOrigin !== normalizedBaseUrl) allowedOrigins.push(normalizedOrigin);
          });
        }
        catch (error) {
            console.error(`Error setting up ALLOWED_ORIGINS: ${ALLOWED_ORIGINS}:`, error);
        }
    }
    console.log("ALLOWED ORIGINS:", allowedOrigins);
    return allowedOrigins;
}

function normalizeOrigin(origin) {
  if (origin) {
      try {
          const normalizedOrigin = new URL(origin).origin;
          return normalizedOrigin;
      } catch (error) {
          console.error("Error parsing referer URL:", error);
          throw new Error(`Error parsing origin URL: ${origin}`);
      }
  }
}

function hasMatchingHost(origin, allowlist) {
  if (!Array.isArray(allowlist)) {
    return false;
  }

  try {
    const incomingHost = new URL(origin).host;
    return allowlist.some((allowedOrigin) => {
      try {
        return new URL(allowedOrigin).host === incomingHost;
      } catch {
        return false;
      }
    });
  } catch {
    return false;
  }
}

function validateOrigin(origin) {
  if (NODE_ENV === 'development' || allowedOrigins === '*') return true;

  try {
      if (origin) origin = normalizeOrigin(origin);
      else {
          console.warn("No origin to validate.");
          return false;
      }

      console.log("Validating Origin:", origin);
      if (allowedOrigins.includes(origin)) {
        console.log("Allowed request from origin:", origin);
        return true;
      } 
      // Reverse proxies can alter scheme before Express sees the request.
      // Accept same-host origins even if protocol differs (http/https mismatch).
      if (hasMatchingHost(origin, allowedOrigins)) {
        console.log("Allowed request from matching host:", origin);
        return true;
      }
      else {
          console.warn("Blocked request from origin:", origin);
          return false;
      }
  }
  catch (error) {
      console.error(error);
  }
}

function originValidationMiddleware(req, res, next) {
  // Browser navigation and some same-origin requests do not include Origin/Referer.
  // Allow those requests and rely on authentication/rate limiting for protection.
  const rawOrigin = req.headers.origin || req.headers.referer;
  if (!rawOrigin) {
    return next();
  }

  const origin = rawOrigin;
  const isOriginValid = validateOrigin(origin);
  if (isOriginValid) {
      next();
  } else {
      res.status(403).json({ error: 'Forbidden' });
  }
}

function getCorsOptions(baseUrl) {
  const allowedOrigins = setupOrigins(baseUrl);
  const corsOptions = {
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Pin', 'X-Batch-Id'],
  };
  return corsOptions;
}

module.exports = { getCorsOptions, originValidationMiddleware, validateOrigin, allowedOrigins };