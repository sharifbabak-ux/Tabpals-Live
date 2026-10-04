import express from 'express';
import rateLimit from 'express-rate-limit';
import { ApiError, OP_REASONS, errorBody } from './errors.js';
import { authMiddleware, requireEventMember } from './auth.js';
import { audit } from './audit.js';
import { lockEvent } from './db.js';
import { newId, newShortCode, newToken, normalizeShortCode, sha256 } from './crypto.js';
import { ROLES, can, checkOp, hasAny } from './permissions.js';

export const MAX_OPS_PER_BATCH = 500;
export const MAX_OP_BYTES = 64 * 1024;
const MAX_MEMBERS_PER_EVENT = 200;
const MAX_PUBLIC_KEY_BYTES = 2048;
const MAX_WRAPPED_KEY_BYTES = 4096;
const MAX_ENVELOPE_META_BYTES = 1024;

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const ENTITY_ID_RE = /^[\w.:-]{1,128}$/;
const str = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
const clean = (v) => v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function need(cond, field) {
  if (!cond) throw new ApiError('invalid-field', `فیلد «${field}» نامعتبر است.`);
}

function parseMember(m, field) {
  need(isObj(m) && ID_RE.test(m.memberId ?? '') && str(m.displayName, 80), field);
  return { memberId: m.memberId, displayName: clean(m.displayName) };
}

/** Accepts an ECDH P-256 public JWK (object or JSON string); returns the normalized JSON string. Rejects private keys. */
function parsePublicKey(v, field = 'publicKey') {
  let jwk = v;
  if (typeof v === 'string') {
    need(Buffer.byteLength(v) <= MAX_PUBLIC_KEY_BYTES, field);
    try {
      jwk = JSON.parse(v);
    } catch {
      need(false, field);
    }
  }
  const coord = (c) => typeof c === 'string' && /^[A-Za-z0-9_-]{43}$/.test(c);
  need(isObj(jwk) && jwk.kty === 'EC' && jwk.crv === 'P-256' && coord(jwk.x) && coord(jwk.y) && jwk.d === undefined, field);
  return JSON.stringify({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });
}
const optionalPublicKey = (v) => (v === undefined || v === null ? null : parsePublicKey(v));

/** Non-sensitive audit details for a logSend op: only ids, channel and timestamp, each strictly validated. */
function statementSentDetails(op) {
  const pick = (...names) => {
    for (const n of names) {
      for (const v of [op.changes?.[n]?.after, op.changes?.[n], op[n]]) {
        if (typeof v === 'string' && /^[\w.:-]{1,128}$/.test(v)) return v;
      }
    }
    return null;
  };
  return {
    statementId: op.entityId,
    targetMemberId: pick('targetMemberId', 'memberId', 'personId', 'recipientId'),
    channel: pick('channel'),
    timestamp: toClientTs(op.timestamp).toISOString(),
  };
}

function toClientTs(v) {
  const ms = typeof v === 'number' ? v : typeof v === 'string' ? Date.parse(v) : NaN;
  return Number.isFinite(ms) && ms > 0 && ms < 4102444800000 ? new Date(ms) : null;
}

/** Structural validation of one client op. Returns {reason} or {op, clientTs}. */
function validateOp(op) {
  if (!isObj(op)) return { reason: 'bad-op' };
  const clientTs = toClientTs(op.timestamp);
  if (!ENTITY_ID_RE.test(op.id ?? '') || !ENTITY_ID_RE.test(op.entityId ?? '') || !clientTs) return { reason: 'bad-op' };
  if (typeof op.entity !== 'string' || typeof op.type !== 'string') return { reason: 'bad-op' };
  if (op.changes !== undefined && !isObj(op.changes) && !Array.isArray(op.changes)) return { reason: 'bad-op' };
  if (Buffer.byteLength(JSON.stringify(op)) > MAX_OP_BYTES) return { reason: 'op-too-large' };
  return { clientTs };
}

const opView = (r) => ({
  seq: Number(r.seq),
  serverTs: new Date(r.server_ts).toISOString(),
  memberId: r.member_id,
  deviceId: r.device_id,
  op: typeof r.payload === 'string' ? JSON.parse(r.payload) : r.payload,
});

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

export function buildRouter({ db, config, hub }) {
  const r = express.Router();
  const auth = authMiddleware(db);
  const member = [auth, requireEventMember];
  const small = express.json({ limit: '256kb' });
  const big = express.json({ limit: '8mb' }); // 500 ops x 64 KB would be 32 MB; clients chunk by size
  const limited = (opts) =>
    rateLimit({
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      handler: (_req, res) => res.status(429).json(errorBody('rate-limited')),
      ...opts,
    });
  const createLimiter = limited({ windowMs: 3600_000, limit: config.limits.createPerHour });
  const redeemLimiter = limited({
    windowMs: 15 * 60_000,
    limit: config.limits.redeemFailPer15Min,
    skipSuccessfulRequests: true, // carrier-grade NAT: only failed attempts count against an IP
  });
  const envelopeLimiter = limited({
    windowMs: 60_000,
    limit: config.limits.envelopesPerMin,
    keyGenerator: (req) => req.device.id,
  });
  const opsLimiter = limited({
    windowMs: 60_000,
    limit: config.limits.opsPerMin,
    keyGenerator: (req) => req.device.id,
  });

  const requireAction = (req, action) => {
    if (!can(req.device.roles, action)) throw new ApiError('forbidden');
  };

  // ---- events -------------------------------------------------------------------------------
  r.post(
    '/events',
    createLimiter,
    small,
    wrap(async (req, res) => {
      const b = req.body;
      need(isObj(b), 'body');
      need(ID_RE.test(b.eventId ?? ''), 'eventId');
      need(str(b.title, 200), 'title');
      need(str(b.deviceLabel, 40), 'deviceLabel');
      const creator = parseMember(b.creator, 'creator');
      const publicKey = optionalPublicKey(b.publicKey);
      need(b.members === undefined || (Array.isArray(b.members) && b.members.length <= MAX_MEMBERS_PER_EVENT), 'members');
      const members = new Map([[creator.memberId, creator]]);
      for (const m of b.members ?? []) {
        const p = parseMember(m, 'members');
        if (!members.has(p.memberId)) members.set(p.memberId, p);
      }
      const token = newToken();
      const deviceId = newId();
      try {
        await db.tx(async (q) => {
          if ((await q.query('SELECT id FROM events WHERE id = $1', [b.eventId])).length) throw new ApiError('event-exists');
          await q.query('INSERT INTO events (id, title, created_by_member) VALUES ($1,$2,$3)', [
            b.eventId,
            clean(b.title),
            creator.memberId,
          ]);
          for (const m of members.values()) {
            await q.query('INSERT INTO members (event_id, member_id, display_name) VALUES ($1,$2,$3)', [
              b.eventId,
              m.memberId,
              m.displayName,
            ]);
            const roles = m.memberId === creator.memberId ? ['admin', 'treasurer'] : ['member'];
            for (const role of roles) {
              await q.query('INSERT INTO member_roles (event_id, member_id, role) VALUES ($1,$2,$3)', [
                b.eventId,
                m.memberId,
                role,
              ]);
            }
          }
          await q.query('INSERT INTO devices (id, event_id, member_id, token_hash, label, public_key) VALUES ($1,$2,$3,$4,$5,$6)', [
            deviceId,
            b.eventId,
            creator.memberId,
            sha256(token),
            clean(b.deviceLabel),
            publicKey,
          ]);
          await audit(q, b.eventId, { memberId: creator.memberId, id: deviceId }, 'event.created', b.eventId, {
            memberCount: members.size,
          });
        });
      } catch (err) {
        if (err.code === '23505') throw new ApiError('event-exists');
        throw err;
      }
      res.status(201).json({ deviceToken: token, deviceId });
    }),
  );

  r.delete(
    '/events/:eventId',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'event.purge');
      const { eventId } = req.params;
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        for (const t of ['ops', 'audit_log', 'key_envelopes', 'invites', 'devices', 'member_roles', 'members']) {
          await q.query(`DELETE FROM ${t} WHERE event_id = $1`, [eventId]);
        }
        await q.query('DELETE FROM events WHERE id = $1', [eventId]);
      });
      hub.eventPurged(eventId);
      res.json({ ok: true });
    }),
  );

  r.get(
    '/me',
    auth,
    wrap(async (req, res) => {
      const d = req.device;
      const [ev] = await db.query('SELECT title FROM events WHERE id = $1', [d.eventId]);
      const [m] = await db.query('SELECT display_name FROM members WHERE event_id = $1 AND member_id = $2', [
        d.eventId,
        d.memberId,
      ]);
      res.json({
        eventId: d.eventId,
        memberId: d.memberId,
        roles: d.roles,
        deviceId: d.id,
        eventTitle: ev?.title,
        displayName: m?.display_name,
      });
    }),
  );

  // ---- ops ----------------------------------------------------------------------------------
  r.post(
    '/events/:eventId/ops',
    ...member,
    opsLimiter,
    big,
    wrap(async (req, res) => {
      const { eventId } = req.params;
      const actor = req.device;
      const ops = req.body?.ops;
      need(Array.isArray(ops) && ops.length >= 1 && ops.length <= MAX_OPS_PER_BATCH, 'ops');

      const rejected = [];
      const todo = [];
      for (const op of ops) {
        const opId = isObj(op) && typeof op.id === 'string' ? op.id.slice(0, 128) : null;
        const v = validateOp(op);
        const verdict = v.reason ? { ok: false, reason: v.reason } : checkOp(actor, op);
        if (verdict.ok) todo.push({ op, clientTs: v.clientTs });
        else rejected.push({ opId, reason: verdict.reason, message: OP_REASONS[verdict.reason] });
      }

      const accepted = [];
      const fresh = [];
      let lastSeq = 0;
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        for (const { op, clientTs } of todo) {
          // Writers are serialized by the event lock, so check-then-insert cannot race.
          const [ex] = await q.query('SELECT seq FROM ops WHERE event_id = $1 AND op_id = $2', [eventId, op.id]);
          if (ex) {
            accepted.push({ opId: op.id, seq: Number(ex.seq) });
            continue;
          }
          const [row] = await q.query(
            `INSERT INTO ops (event_id, op_id, device_id, member_id, entity, entity_id, type, payload, client_ts)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING seq, server_ts, member_id, device_id, payload`,
            [eventId, op.id, actor.id, actor.memberId, op.entity, op.entityId, op.type, JSON.stringify(op), clientTs],
          );
          fresh.push(row);
          if (op.type === 'logSend') {
            const d = statementSentDetails(op);
            await audit(q, eventId, actor, 'statement.sent', d.statementId, d);
          }
          accepted.push({ opId: op.id, seq: Number(row.seq) });
        }
        const [head] = await q.query('SELECT max(seq) AS s FROM ops WHERE event_id = $1', [eventId]);
        lastSeq = Number(head.s ?? 0);
      });
      if (fresh.length) hub.opsAccepted(eventId, fresh.map(opView), lastSeq);
      res.json({ accepted, rejected, lastSeq });
    }),
  );

  r.get(
    '/events/:eventId/ops',
    ...member,
    wrap(async (req, res) => {
      const after = req.query.after === undefined ? 0 : Number(req.query.after);
      const limit = req.query.limit === undefined ? 200 : Number(req.query.limit);
      need(Number.isInteger(after) && after >= 0, 'after');
      need(Number.isInteger(limit) && limit >= 1 && limit <= MAX_OPS_PER_BATCH, 'limit');
      // memberProfile ops are delivered only to the owner, treasurers and admins (seq gaps are expected).
      const restricted = !hasAny(req.device.roles, ['admin', 'treasurer']);
      const rows = await db.query(
        `SELECT seq, server_ts, member_id, device_id, payload FROM ops
         WHERE event_id = $1 AND seq > $2 ${restricted ? "AND (entity <> 'memberProfile' OR entity_id = $4)" : ''}
         ORDER BY seq ASC LIMIT $3`,
        restricted ? [req.params.eventId, after, limit + 1, req.device.memberId] : [req.params.eventId, after, limit + 1],
      );
      const hasMore = rows.length > limit;
      const ops = rows.slice(0, limit).map(opView);
      res.json({ ops, hasMore, lastSeq: ops.length ? ops[ops.length - 1].seq : after });
    }),
  );

  // ---- members & roles ----------------------------------------------------------------------
  r.get(
    '/events/:eventId/members',
    ...member,
    wrap(async (req, res) => {
      const { eventId } = req.params;
      const [members, roles, devices] = await Promise.all([
        db.query('SELECT member_id, display_name, created_at, removed_at FROM members WHERE event_id = $1 ORDER BY created_at, member_id', [eventId]),
        db.query('SELECT member_id, role FROM member_roles WHERE event_id = $1', [eventId]),
        db.query('SELECT member_id FROM devices WHERE event_id = $1 AND revoked_at IS NULL', [eventId]),
      ]);
      res.json({
        members: members.map((m) => ({
          memberId: m.member_id,
          displayName: m.display_name,
          createdAt: new Date(m.created_at).toISOString(),
          removedAt: m.removed_at ? new Date(m.removed_at).toISOString() : null,
          roles: ROLES.filter((role) => roles.some((x) => x.member_id === m.member_id && x.role === role)),
          activeDevices: devices.filter((d) => d.member_id === m.member_id).length,
        })),
      });
    }),
  );

  r.post(
    '/events/:eventId/members',
    ...member,
    small,
    wrap(async (req, res) => {
      requireAction(req, 'members.add');
      const { eventId } = req.params;
      const m = parseMember(req.body, 'member');
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        const [{ n }] = await q.query('SELECT count(*) AS n FROM members WHERE event_id = $1', [eventId]);
        if (Number(n) >= MAX_MEMBERS_PER_EVENT) throw new ApiError('invalid-field', 'تعداد اعضا بیش از حد مجاز است.');
        const exists = await q.query('SELECT 1 AS x FROM members WHERE event_id = $1 AND member_id = $2', [eventId, m.memberId]);
        if (exists.length) throw new ApiError('member-exists');
        await q.query('INSERT INTO members (event_id, member_id, display_name) VALUES ($1,$2,$3)', [eventId, m.memberId, m.displayName]);
        await q.query("INSERT INTO member_roles (event_id, member_id, role) VALUES ($1,$2,'member')", [eventId, m.memberId]);
        await audit(q, eventId, req.device, 'member.added', m.memberId);
      });
      res.status(201).json({ memberId: m.memberId, displayName: m.displayName, roles: ['member'] });
    }),
  );

  r.put(
    '/events/:eventId/members/:memberId/roles',
    ...member,
    small,
    wrap(async (req, res) => {
      requireAction(req, 'roles.set');
      const { eventId, memberId } = req.params;
      const roles = req.body?.roles;
      need(Array.isArray(roles) && roles.length >= 1 && roles.every((x) => ROLES.includes(x)), 'roles');
      const next = ROLES.filter((x) => roles.includes(x));
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        const cur = (await q.query('SELECT role FROM member_roles WHERE event_id = $1 AND member_id = $2', [eventId, memberId])).map((x) => x.role);
        const [known] = await q.query('SELECT removed_at FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        if (!known) throw new ApiError('member-not-found');
        if (known.removed_at) throw new ApiError('member-removed');
        if (cur.includes('admin') && !next.includes('admin')) {
          const others = await q.query("SELECT member_id FROM member_roles WHERE event_id = $1 AND role = 'admin' AND member_id <> $2", [eventId, memberId]);
          if (!others.length) throw new ApiError('last-admin');
        }
        await q.query('DELETE FROM member_roles WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        for (const role of next) {
          await q.query('INSERT INTO member_roles (event_id, member_id, role) VALUES ($1,$2,$3)', [eventId, memberId, role]);
        }
        await audit(q, eventId, req.device, 'roles.changed', memberId, { from: cur, to: next });
      });
      hub.rolesChanged(eventId, memberId, next);
      res.json({ memberId, roles: next });
    }),
  );

  // ---- invites ------------------------------------------------------------------------------
  r.post(
    '/events/:eventId/invites',
    ...member,
    small,
    wrap(async (req, res) => {
      requireAction(req, 'invites.manage');
      const { eventId } = req.params;
      const memberId = req.body?.memberId;
      need(typeof memberId === 'string' && ID_RE.test(memberId), 'memberId');
      const [m] = await db.query('SELECT removed_at FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
      if (!m) throw new ApiError('member-not-found');
      if (m.removed_at) throw new ApiError('member-removed');
      const inviteToken = newToken();
      const shortCode = newShortCode();
      const id = newId();
      const expiresAt = new Date(Date.now() + config.inviteTtlMs);
      await db.tx(async (q) => {
        await q.query(
          `INSERT INTO invites (id, event_id, member_id, token_hash, short_code_hash, expires_at, created_by_member)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [id, eventId, memberId, sha256(inviteToken), sha256(shortCode), expiresAt, req.device.memberId],
        );
        await audit(q, eventId, req.device, 'invite.created', memberId, { inviteId: id });
      });
      res.status(201).json({ inviteId: id, inviteToken, shortCode, expiresAt: expiresAt.toISOString() });
    }),
  );

  r.get(
    '/events/:eventId/invites',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'invites.manage');
      const rows = await db.query(
        `SELECT id, member_id, created_at, expires_at, used_at, revoked_at, created_by_member FROM invites
         WHERE event_id = $1 ORDER BY created_at, id`,
        [req.params.eventId],
      );
      const iso = (v) => (v ? new Date(v).toISOString() : null);
      const status = (i) =>
        i.used_at ? 'used' : i.revoked_at ? 'revoked' : new Date(i.expires_at).getTime() <= Date.now() ? 'expired' : 'pending';
      res.json({
        invites: rows.map((i) => ({
          inviteId: i.id,
          memberId: i.member_id,
          status: status(i),
          createdAt: iso(i.created_at),
          expiresAt: iso(i.expires_at),
          usedAt: iso(i.used_at),
          createdBy: i.created_by_member,
        })),
      });
    }),
  );

  r.delete(
    '/events/:eventId/invites/:inviteId',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'invites.manage');
      const { eventId, inviteId } = req.params;
      await db.tx(async (q) => {
        const [inv] = await q.query('SELECT id, member_id FROM invites WHERE id = $1 AND event_id = $2', [inviteId, eventId]);
        if (!inv) throw new ApiError('invite-not-found');
        await q.query('UPDATE invites SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL', [inviteId]);
        await audit(q, eventId, req.device, 'invite.revoked', inv.member_id, { inviteId });
      });
      res.json({ ok: true });
    }),
  );

  r.post(
    '/invites/redeem',
    redeemLimiter,
    small,
    wrap(async (req, res) => {
      const { inviteToken, shortCode, deviceLabel } = req.body ?? {};
      need(str(deviceLabel, 40), 'deviceLabel');
      const publicKey = optionalPublicKey(req.body?.publicKey);
      let hash;
      let column;
      if (typeof inviteToken === 'string' && inviteToken.length <= 128) {
        hash = sha256(inviteToken);
        column = 'token_hash';
      } else if (typeof shortCode === 'string' && shortCode.length <= 32) {
        hash = sha256(normalizeShortCode(shortCode));
        column = 'short_code_hash';
      } else {
        throw new ApiError('invalid-field', 'inviteToken یا shortCode لازم است.');
      }
      const token = newToken();
      const deviceId = newId();
      const out = await db.tx(async (q) => {
        const [inv] = await q.query(`SELECT * FROM invites WHERE ${column} = $1`, [hash]); // column is a fixed literal above
        if (!inv) throw new ApiError('invite-not-found');
        if (inv.revoked_at) throw new ApiError('invite-revoked');
        if (inv.used_at) throw new ApiError('invite-used');
        if (new Date(inv.expires_at).getTime() <= Date.now()) throw new ApiError('invite-expired');
        // Atomic single use: only one concurrent redeemer can flip used_at.
        const won = await q.query('UPDATE invites SET used_at = now(), used_by_device = $2 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL RETURNING id', [inv.id, deviceId]);
        if (!won.length) throw new ApiError('invite-used');
        const [mem] = await q.query('SELECT removed_at FROM members WHERE event_id = $1 AND member_id = $2', [inv.event_id, inv.member_id]);
        if (mem?.removed_at) throw new ApiError('member-removed');
        await q.query('INSERT INTO devices (id, event_id, member_id, token_hash, label, public_key) VALUES ($1,$2,$3,$4,$5,$6)', [deviceId, inv.event_id, inv.member_id, sha256(token), clean(deviceLabel), publicKey]);
        await audit(q, inv.event_id, { memberId: inv.member_id, id: deviceId }, 'invite.redeemed', inv.member_id, { inviteId: inv.id });
        const roles = (await q.query('SELECT role FROM member_roles WHERE event_id = $1 AND member_id = $2', [inv.event_id, inv.member_id])).map((x) => x.role);
        const [ev] = await q.query('SELECT title FROM events WHERE id = $1', [inv.event_id]);
        return { eventId: inv.event_id, memberId: inv.member_id, roles: ROLES.filter((x) => roles.includes(x)), eventTitle: ev.title };
      });
      if (publicKey) hub.keyNeeded(out.eventId, deviceId, out.memberId);
      res.json({ ...out, deviceToken: token, deviceId });
    }),
  );

  // ---- devices ------------------------------------------------------------------------------
  r.get(
    '/events/:eventId/devices',
    ...member,
    wrap(async (req, res) => {
      const all = can(req.device.roles, 'devices.listAll');
      const rows = await db.query(
        `SELECT id, member_id, label, created_at, last_seen_at, revoked_at FROM devices
         WHERE event_id = $1 ${all ? '' : 'AND member_id = $2'} ORDER BY created_at, id`,
        all ? [req.params.eventId] : [req.params.eventId, req.device.memberId],
      );
      res.json({
        devices: rows.map((d) => ({
          deviceId: d.id,
          memberId: d.member_id,
          label: d.label,
          createdAt: new Date(d.created_at).toISOString(),
          lastSeenAt: new Date(d.last_seen_at).toISOString(),
          revokedAt: d.revoked_at ? new Date(d.revoked_at).toISOString() : null,
          current: d.id === req.device.id,
        })),
      });
    }),
  );

  r.delete(
    '/events/:eventId/devices/:deviceId',
    ...member,
    wrap(async (req, res) => {
      const { eventId, deviceId } = req.params;
      const [d] = await db.query('SELECT id, member_id FROM devices WHERE id = $1 AND event_id = $2', [deviceId, eventId]);
      if (!d) throw new ApiError('device-not-found');
      if (d.id !== req.device.id) requireAction(req, 'devices.revokeAny');
      await db.tx(async (q) => {
        const done = await q.query('UPDATE devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING id', [deviceId]);
        await q.query('DELETE FROM key_envelopes WHERE target_device_id = $1', [deviceId]);
        if (done.length) await audit(q, eventId, req.device, 'device.revoked', d.member_id, { deviceId });
      });
      hub.deviceRevoked(deviceId);
      res.json({ ok: true });
    }),
  );

  // ---- member removal -----------------------------------------------------------------------
  r.delete(
    '/events/:eventId/members/:memberId',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'members.remove');
      const { eventId, memberId } = req.params;
      const revoked = await db.tx(async (q) => {
        await lockEvent(q, eventId);
        const [m] = await q.query('SELECT removed_at FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        if (!m) throw new ApiError('member-not-found');
        if (m.removed_at) return null; // already removed: idempotent
        const isAdmin = await q.query("SELECT 1 AS x FROM member_roles WHERE event_id = $1 AND member_id = $2 AND role = 'admin'", [eventId, memberId]);
        if (isAdmin.length) {
          const others = await q.query("SELECT member_id FROM member_roles WHERE event_id = $1 AND role = 'admin' AND member_id <> $2", [eventId, memberId]);
          if (!others.length) throw new ApiError('last-admin');
        }
        const devices = (await q.query('SELECT id FROM devices WHERE event_id = $1 AND member_id = $2', [eventId, memberId])).map((d) => d.id);
        await q.query('UPDATE devices SET revoked_at = now() WHERE event_id = $1 AND member_id = $2 AND revoked_at IS NULL', [eventId, memberId]);
        for (const id of devices) await q.query('DELETE FROM key_envelopes WHERE target_device_id = $1', [id]);
        await q.query('UPDATE invites SET revoked_at = now() WHERE event_id = $1 AND member_id = $2 AND used_at IS NULL AND revoked_at IS NULL', [eventId, memberId]);
        await q.query('DELETE FROM member_roles WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        await q.query('UPDATE members SET removed_at = now() WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        await audit(q, eventId, req.device, 'member.removed', memberId, { deviceCount: devices.length });
        return devices;
      });
      if (revoked) {
        hub.memberRemoved(eventId, memberId);
        revoked.forEach((id) => hub.deviceRevoked(id));
      }
      res.json({ ok: true });
    }),
  );

  r.post(
    '/events/:eventId/members/:memberId/restore',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'members.remove');
      const { eventId, memberId } = req.params;
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        const [m] = await q.query('SELECT removed_at FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        if (!m) throw new ApiError('member-not-found');
        if (!m.removed_at) return;
        await q.query('UPDATE members SET removed_at = NULL WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        await audit(q, eventId, req.device, 'member.restored', memberId);
      });
      res.json({ ok: true, memberId, roles: [] });
    }),
  );

  // ---- E2E key distribution (server stores opaque data only) --------------------------------
  r.put(
    '/devices/me/public-key',
    auth,
    small,
    wrap(async (req, res) => {
      const publicKey = parsePublicKey(req.body?.publicKey);
      const d = req.device;
      await db.tx(async (q) => {
        const [cur] = await q.query('SELECT public_key FROM devices WHERE id = $1', [d.id]);
        // An envelope wrapped for a previous key is useless to the new key pair.
        if (cur?.public_key !== publicKey) await q.query('DELETE FROM key_envelopes WHERE target_device_id = $1', [d.id]);
        await q.query('UPDATE devices SET public_key = $2 WHERE id = $1', [d.id, publicKey]);
      });
      const has = await db.query('SELECT 1 AS x FROM key_envelopes WHERE target_device_id = $1', [d.id]);
      if (!has.length) hub.keyNeeded(d.eventId, d.id, d.memberId);
      res.json({ ok: true });
    }),
  );

  r.get(
    '/events/:eventId/devices/awaiting-key',
    ...member,
    wrap(async (req, res) => {
      const rows = await db.query(
        `SELECT d.id, d.member_id, d.label, d.public_key FROM devices d
         JOIN members m ON m.event_id = d.event_id AND m.member_id = d.member_id
         LEFT JOIN key_envelopes k ON k.target_device_id = d.id
         WHERE d.event_id = $1 AND d.revoked_at IS NULL AND m.removed_at IS NULL AND d.public_key IS NOT NULL
           AND k.id IS NULL
         ORDER BY d.created_at, d.id`,
        [req.params.eventId],
      );
      res.json({
        devices: rows.map((d) => ({ deviceId: d.id, memberId: d.member_id, label: d.label, publicKey: d.public_key })),
      });
    }),
  );

  r.post(
    '/events/:eventId/key-envelopes',
    ...member,
    envelopeLimiter,
    small,
    wrap(async (req, res) => {
      const { eventId } = req.params;
      const { targetDeviceId, wrappedKey } = req.body ?? {};
      const meta = req.body?.meta ?? null;
      need(typeof targetDeviceId === 'string' && ID_RE.test(targetDeviceId), 'targetDeviceId');
      need(typeof wrappedKey === 'string' && wrappedKey.length > 0 && Buffer.byteLength(wrappedKey) <= MAX_WRAPPED_KEY_BYTES, 'wrappedKey');
      need(meta === null || Buffer.byteLength(JSON.stringify(meta)) <= MAX_ENVELOPE_META_BYTES, 'meta');
      need(targetDeviceId !== req.device.id, 'targetDeviceId');
      await db.tx(async (q) => {
        await lockEvent(q, eventId);
        const [t] = await q.query(
          `SELECT d.id FROM devices d JOIN members m ON m.event_id = d.event_id AND m.member_id = d.member_id
           WHERE d.id = $1 AND d.event_id = $2 AND d.revoked_at IS NULL AND m.removed_at IS NULL`,
          [targetDeviceId, eventId],
        );
        if (!t) throw new ApiError('device-not-found');
        await q.query('DELETE FROM key_envelopes WHERE target_device_id = $1', [targetDeviceId]);
        await q.query(
          'INSERT INTO key_envelopes (id, event_id, target_device_id, from_device_id, wrapped_key, meta) VALUES ($1,$2,$3,$4,$5,$6)',
          [newId(), eventId, targetDeviceId, req.device.id, wrappedKey, meta === null ? null : JSON.stringify(meta)],
        );
        await audit(q, eventId, req.device, 'key.delivered', targetDeviceId, { fromDevice: req.device.id, toDevice: targetDeviceId });
      });
      hub.keyDelivered(targetDeviceId, req.device.id);
      res.json({ ok: true });
    }),
  );

  r.get(
    '/devices/me/key-envelope',
    auth,
    wrap(async (req, res) => {
      const [e] = await db.query('SELECT from_device_id, wrapped_key, meta, created_at FROM key_envelopes WHERE target_device_id = $1', [req.device.id]);
      if (!e) throw new ApiError('not-found');
      res.set('Cache-Control', 'no-store');
      res.json({
        fromDeviceId: e.from_device_id,
        wrappedKey: e.wrapped_key,
        meta: typeof e.meta === 'string' ? JSON.parse(e.meta) : e.meta,
        createdAt: new Date(e.created_at).toISOString(),
      });
    }),
  );

  // ---- audit --------------------------------------------------------------------------------
  r.get(
    '/events/:eventId/audit',
    ...member,
    wrap(async (req, res) => {
      requireAction(req, 'audit.read');
      const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
      const before = req.query.before === undefined ? null : Number(req.query.before);
      need(Number.isInteger(limit) && limit >= 1 && limit <= 200, 'limit');
      need(before === null || (Number.isInteger(before) && before > 0), 'before');
      const rows = await db.query(
        `SELECT id, actor_member, actor_device, action, target, details, at FROM audit_log
         WHERE event_id = $1 ${before ? 'AND id < $3' : ''} ORDER BY id DESC LIMIT $2`,
        before ? [req.params.eventId, limit + 1, before] : [req.params.eventId, limit + 1],
      );
      const page = rows.slice(0, limit);
      res.json({
        entries: page.map((e) => ({
          id: Number(e.id),
          actorMember: e.actor_member,
          actorDevice: e.actor_device,
          action: e.action,
          target: e.target,
          details: typeof e.details === 'string' ? JSON.parse(e.details) : e.details,
          at: new Date(e.at).toISOString(),
        })),
        nextBefore: rows.length > limit ? Number(page[page.length - 1].id) : null,
      });
    }),
  );

  return r;
}
