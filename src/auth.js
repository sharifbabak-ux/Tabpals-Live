import { ApiError } from './errors.js';
import { safeEqualHex, sha256 } from './crypto.js';

const TOUCH_INTERVAL_MS = 60 * 1000;

export function bearerToken(header) {
  const m = /^Bearer ([A-Za-z0-9_-]{20,128})$/.exec(header || '');
  return m ? m[1] : null;
}

/**
 * Resolve a raw device token to {id, eventId, memberId, roles}.
 * Throws unauthorized / device-revoked.
 */
export async function authenticateToken(db, token) {
  if (!token) throw new ApiError('unauthorized');
  const hash = sha256(token);
  const rows = await db.query(
    'SELECT id, event_id, member_id, token_hash, revoked_at, last_seen_at FROM devices WHERE token_hash = $1',
    [hash],
  );
  const d = rows[0];
  if (!d || !safeEqualHex(d.token_hash, hash)) throw new ApiError('unauthorized');
  if (d.revoked_at) throw new ApiError('device-revoked');
  if (Date.now() - new Date(d.last_seen_at).getTime() > TOUCH_INTERVAL_MS) {
    await db.query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [d.id]);
  }
  const roles = (
    await db.query('SELECT role FROM member_roles WHERE event_id = $1 AND member_id = $2', [d.event_id, d.member_id])
  ).map((r) => r.role);
  return { id: d.id, eventId: d.event_id, memberId: d.member_id, roles };
}

export const authMiddleware = (db) => async (req, _res, next) => {
  try {
    req.device = await authenticateToken(db, bearerToken(req.headers.authorization));
    next();
  } catch (err) {
    next(err);
  }
};

/** For routes with :eventId — callers who are not members get 404, never 403. */
export function requireEventMember(req, _res, next) {
  if (req.device.eventId !== req.params.eventId) return next(new ApiError('event-not-found'));
  next();
}
