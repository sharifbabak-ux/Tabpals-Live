import express from 'express';
import rateLimit from 'express-rate-limit';
import { ApiError, OP_REASONS, errorBody } from './errors.js';
import { authMiddleware, requireEventMember } from './auth.js';
import { audit } from './audit.js';
import { lockEvent } from './db.js';
import { newId, newShortCode, newToken, normalizeShortCode, sha256 } from './crypto.js';
import { ROLES, can, checkOp } from './permissions.js';

export const MAX_OPS_PER_BATCH = 500;
export const MAX_OP_BYTES = 64 * 1024;
const MAX_MEMBERS_PER_EVENT = 200;

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
          await q.query('INSERT INTO devices (id, event_id, member_id, token_hash, label) VALUES ($1,$2,$3,$4,$5)', [
            deviceId,
            b.eventId,
            creator.memberId,
            sha256(token),
            clean(b.deviceLabel),
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
        for (const t of ['ops', 'audit_log', 'invites', 'devices', 'member_roles', 'members']) {
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
      const rows = await db.query(
        `SELECT seq, server_ts, member_id, device_id, payload FROM ops
         WHERE event_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3`,
        [req.params.eventId, after, limit + 1],
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
        db.query('SELECT member_id, display_name, created_at FROM members WHERE event_id = $1 ORDER BY created_at, member_id', [eventId]),
        db.query('SELECT member_id, role FROM member_roles WHERE event_id = $1', [eventId]),
        db.query('SELECT member_id FROM devices WHERE event_id = $1 AND revoked_at IS NULL', [eventId]),
      ]);
      res.json({
        members: members.map((m) => ({
          memberId: m.member_id,
          displayName: m.display_name,
          createdAt: new Date(m.created_at).toISOString(),
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
        const known = await q.query('SELECT 1 AS x FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
        if (!known.length) throw new ApiError('member-not-found');
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
      const [m] = await db.query('SELECT 1 AS x FROM members WHERE event_id = $1 AND member_id = $2', [eventId, memberId]);
      if (!m) throw new ApiError('member-not-found');
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
        await q.query('INSERT INTO devices (id, event_id, member_id, token_hash, label) VALUES ($1,$2,$3,$4,$5)', [deviceId, inv.event_id, inv.member_id, sha256(token), clean(deviceLabel)]);
        await audit(q, inv.event_id, { memberId: inv.member_id, id: deviceId }, 'invite.redeemed', inv.member_id, { inviteId: inv.id });
        const roles = (await q.query('SELECT role FROM member_roles WHERE event_id = $1 AND member_id = $2', [inv.event_id, inv.member_id])).map((x) => x.role);
        const [ev] = await q.query('SELECT title FROM events WHERE id = $1', [inv.event_id]);
        return { eventId: inv.event_id, memberId: inv.member_id, roles: ROLES.filter((x) => roles.includes(x)), eventTitle: ev.title };
      });
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
        if (done.length) await audit(q, eventId, req.device, 'device.revoked', d.member_id, { deviceId });
      });
      hub.deviceRevoked(deviceId);
      res.json({ ok: true });
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
