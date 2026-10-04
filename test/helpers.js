import { io as connect } from 'socket.io-client';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { migrate, wrapPool } from '../src/db.js';

const TABLES = ['key_envelopes', 'audit_log', 'ops', 'invites', 'devices', 'member_roles', 'members', 'events', 'schema_migrations'];

async function makeDb() {
  if (process.env.DATABASE_URL_TEST) {
    const { default: pg } = await import('pg');
    const db = wrapPool(new pg.Pool({ connectionString: process.env.DATABASE_URL_TEST, max: 5 }));
    for (const t of TABLES) await db.query(`DROP TABLE IF EXISTS ${t} CASCADE`);
    return db;
  }
  const { newDb } = await import('pg-mem');
  const { Pool } = newDb().adapters.createPg();
  return wrapPool(new Pool());
}

/** Boots a full server on an ephemeral port; cleaned up via t.after. */
export async function startServer(t, overrides = {}) {
  const db = await makeDb();
  await migrate(db);
  const config = loadConfig({}, { log: false, allowedOrigins: ['https://ok.example'], ...overrides });
  const { httpServer, io } = createApp({ db, config });
  await new Promise((r) => httpServer.listen(0, r));
  const url = `http://localhost:${httpServer.address().port}`;
  const sockets = [];
  t.after(async () => {
    sockets.forEach((s) => s.close());
    await io.close();
    await db.close().catch(() => {});
  });

  async function call(method, path, { token, body, headers } = {}) {
    const res = await fetch(url + path, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    return { status: res.status, body: json, headers: res.headers };
  }

  const socket = (token) => {
    const s = connect(url, { transports: ['websocket'], auth: { token }, reconnection: false });
    sockets.push(s);
    return s;
  };

  return { url, db, config, call, socket };
}

let n = 0;
export const uid = (p = 'x') => `${p}${Date.now().toString(36)}${(n++).toString(36)}`.toUpperCase();

/** Event with admin+treasurer "alice" and plain members "bob" and "carol", all with device tokens. */
export async function seedEvent(srv) {
  const eventId = uid('EV');
  const r = await srv.call('POST', '/v1/events', {
    body: {
      eventId,
      title: 'سفر شمال',
      creator: { memberId: 'alice', displayName: 'الف' },
      members: [
        { memberId: 'bob', displayName: 'ب' },
        { memberId: 'carol', displayName: 'ج' },
      ],
      deviceLabel: 'Android Chrome',
    },
  });
  if (r.status !== 201) throw new Error(`seed failed: ${JSON.stringify(r.body)}`);
  const alice = r.body.deviceToken;
  const invite = async (memberId) => {
    const inv = await srv.call('POST', `/v1/events/${eventId}/invites`, { token: alice, body: { memberId } });
    const red = await srv.call('POST', '/v1/invites/redeem', { body: { inviteToken: inv.body.inviteToken, deviceLabel: 'iPhone' } });
    return red.body.deviceToken;
  };
  return { eventId, alice, bob: await invite('bob'), carol: await invite('carol') };
}

export const makeOp = (over = {}) => ({
  id: uid('OP'),
  entity: 'vouchers',
  entityId: uid('V'),
  type: 'create',
  changes: { amount: { before: null, after: 1000 } },
  timestamp: Date.now(),
  deviceId: 'dev-client',
  ...over,
});

export const once = (s, ev) => new Promise((res) => s.once(ev, res));
