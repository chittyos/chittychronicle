import type { Request, Response, NextFunction } from 'express';

/**
 * Fail-closed service token middleware.
 *
 * Behavior (binding — do not weaken):
 *  - Missing server-side CHITTYCHRONICLE_SERVICE_TOKEN env var → 503 (service mis-configured,
 *    refuse to serve rather than silently allow). NEVER fall back to "unauthenticated default user".
 *  - Missing/malformed Authorization header → 401.
 *  - Wrong bearer token → 401 (do not leak whether the token format was correct).
 *
 * Envelope shape mirrors the canonical chittyconnect pattern: `{ error, code }`.
 *
 * Phase 1 (this PR) uses the static service token already provisioned for chittychronicle.
 * Action 7 will migrate this to JWKS federation once the Neon Auth ownership chain ships;
 * the migration replaces the comparison step but keeps the fail-closed envelope intact.
 */
export function requireServiceToken(req: Request, res: Response, next: NextFunction) {
  const expected = process.env.CHITTYCHRONICLE_SERVICE_TOKEN;
  if (!expected) {
    return res.status(503).json({
      error: 'Service auth not configured',
      code: 'SERVICE_TOKEN_NOT_CONFIGURED',
    });
  }
  const auth = req.header('authorization') || req.header('Authorization') || '';
  if (!auth.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({
      error: 'Missing bearer token',
      code: 'MISSING_BEARER_TOKEN',
    });
  }
  const token = auth.slice(7).trim();
  if (token.length === 0 || token !== expected) {
    return res.status(401).json({
      error: 'Invalid bearer token',
      code: 'INVALID_BEARER_TOKEN',
    });
  }
  return next();
}

/**
 * @deprecated Fail-open variant retained ONLY for legacy /api/v1/events* routes that pre-date
 * the fail-closed policy. Do not mount on new routes. Action 7 (JWKS federation) will remove
 * this entirely once all routes have migrated.
 */
export function requireServiceTokenIfConfigured(req: Request, res: Response, next: NextFunction) {
  const expected = process.env.CHITTYCHRONICLE_SERVICE_TOKEN;
  if (!expected) return next();
  const auth = req.header('authorization') || req.header('Authorization') || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Missing bearer token' });
  }
  const token = auth.slice('Bearer '.length).trim();
  if (token !== expected) {
    return res.status(403).json({ success: false, message: 'Invalid token' });
  }
  return next();
}
