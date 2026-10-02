import test from 'node:test';
import assert from 'node:assert/strict';
import { makeOp, once, seedEvent, startServer, uid } from './helpers.js';
import { checkOp } from '../src/permissions.js';
import { CODE_ALPHABET } from '../src/crypto.js';
import { loadConfig } from '../src/config.js';

const postOps = (srv, ev, token, ops) => srv.call('POST', `/v1/events/${ev}/ops`, { token, body: { ops } });

test('health endpoint and test page flag', async (t) => {
  const srv = await startServer(t);
  assert.equal((await srv.call('GET', '/health')).body.status, 'ok');
  assert.equal((await srv.call('GET', '/')).status, 404);
  const on = await startServer(t, { enableTestPage: true });
  assert.equal((await on.call('GET', '/')).status, 200);
});

test('event creation: roles, token, /me, duplicates', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const me = await srv.call('GET', '/v1/me', { token: alice });
  assert.deepEqual(me.body.roles, ['admin', 'treasurer']);
  assert.equal(me.body.eventId, eventId);
  assert.deepEqual((await srv.call('GET', '/v1/me', { token: bob })).body.roles, ['member']);
  const dup = await srv.call('POST', '/v1/events', {
    body: { eventId, title: 't', creator: { memberId: 'z', displayName: 'z' }, deviceLabel: 'x' },
  });
  assert.equal(dup.status, 409);
  assert.equal(dup.body.error.code, 'event-exists');
  const bad = await srv.call('POST', '/v1/events', { body: { eventId: 'bad id!', title: 't' } });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'invalid-field');
  const rows = await srv.db.query('SELECT token_hash FROM devices');
  assert.ok(rows.every((r) => r.token_hash !== alice && /^[0-9a-f]{64}$/.test(r.token_hash)));
});

test('invite: create, redeem, single use, short code, expiry, revoke', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const inv = await srv.call('POST', `/v1/events/${eventId}/invites`, { token: alice, body: { memberId: 'bob' } });
  assert.equal(inv.status, 201);
  assert.match(inv.body.shortCode, new RegExp(`^[${CODE_ALPHABET}]{8}$`));
  assert.ok(Math.abs(new Date(inv.body.expiresAt) - (Date.now() + 7 * 86400e3)) < 60e3);

  const red = await srv.call('POST', '/v1/invites/redeem', { body: { inviteToken: inv.body.inviteToken, deviceLabel: 'Pixel' } });
  assert.equal(red.status, 200);
  assert.equal(red.body.memberId, 'bob');
  assert.equal(red.body.eventTitle, 'سفر شمال');
  assert.equal((await srv.call('GET', '/v1/me', { token: red.body.deviceToken })).body.memberId, 'bob');
  const again = await srv.call('POST', '/v1/invites/redeem', { body: { inviteToken: inv.body.inviteToken, deviceLabel: 'x' } });
  assert.equal(again.body.error.code, 'invite-used');
  const viaCode = await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: inv.body.shortCode, deviceLabel: 'x' } });
  assert.equal(viaCode.body.error.code, 'invite-used');

  const inv2 = await srv.call('POST', `/v1/events/${eventId}/invites`, { token: alice, body: { memberId: 'carol' } });
  const c = inv2.body.shortCode;
  const red2 = await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: `${c.slice(0, 4)}-${c.slice(4)}`.toLowerCase(), deviceLabel: 'x' } });
  assert.equal(red2.status, 200);
  assert.equal(red2.body.memberId, 'carol');

  const inv3 = await srv.call('POST', `/v1/events/${eventId}/invites`, { token: alice, body: { memberId: 'carol' } });
  await srv.db.query("UPDATE invites SET expires_at = now() - interval '1 minute' WHERE id = $1", [inv3.body.inviteId]);
  const exp = await srv.call('POST', '/v1/invites/redeem', { body: { inviteToken: inv3.body.inviteToken, deviceLabel: 'x' } });
  assert.equal(exp.status, 410);
  assert.equal(exp.body.error.code, 'invite-expired');

  const inv4 = await srv.call('POST', `/v1/events/${eventId}/invites`, { token: alice, body: { memberId: 'carol' } });
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}/invites/${inv4.body.inviteId}`, { token: alice })).status, 200);
  const rev = await srv.call('POST', '/v1/invites/redeem', { body: { inviteToken: inv4.body.inviteToken, deviceLabel: 'x' } });
  assert.equal(rev.body.error.code, 'invite-revoked');
  assert.equal((await srv.call('POST', `/v1/events/${eventId}/invites`, { token: bob, body: { memberId: 'carol' } })).status, 403);
  const stored = await srv.db.query('SELECT token_hash, short_code_hash FROM invites');
  assert.ok(stored.every((r) => r.token_hash.length === 64 && r.short_code_hash.length === 64));
  assert.equal((await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: 'ZZZZZZZZ', deviceLabel: 'x' } })).status, 404);
});

test('redeem is rate limited per IP (failures only)', async (t) => {
  const limits = { ...loadConfig().limits, redeemFailPer15Min: 3 };
  const srv = await startServer(t, { limits });
  for (let i = 0; i < 3; i++) {
    assert.equal((await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: 'AAAAAAAA', deviceLabel: 'x' } })).status, 404);
  }
  const blocked = await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: 'AAAAAAAA', deviceLabel: 'x' } });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error.code, 'rate-limited');
});

test('permission matrix unit checks', () => {
  const member = { memberId: 'm1', roles: ['member'] };
  const treasurer = { memberId: 't1', roles: ['treasurer'] };
  const admin = { memberId: 'a1', roles: ['admin'] };
  const op = (entity, type = 'create', entityId = 'x') => ({ entity, type, entityId });
  assert.equal(checkOp(member, op('vouchers')).reason, 'forbidden-entity');
  assert.ok(checkOp(treasurer, op('vouchers')).ok);
  assert.ok(checkOp(admin, op('orderLines')).ok);
  assert.ok(checkOp(member, op('memberProfile', 'update', 'm1')).ok);
  assert.equal(checkOp(member, op('memberProfile', 'update', 'm2')).reason, 'forbidden-profile');
  assert.equal(checkOp(treasurer, op('memberProfile', 'update', 'm2')).reason, 'forbidden-profile');
  assert.ok(checkOp(admin, op('memberProfile', 'update', 'm2')).ok);
  assert.equal(checkOp(admin, op('nothing')).reason, 'unknown-entity');
  assert.equal(checkOp(admin, op('vouchers', 'explode')).reason, 'unknown-type');
  assert.equal(checkOp(treasurer, op('events', 'purge')).reason, 'forbidden-purge');
});

test('ops: role enforcement, memberProfile, validation', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const voucher = makeOp();
  const profileOwn = makeOp({ entity: 'memberProfile', entityId: 'bob', type: 'update', changes: { iban: { before: null, after: 'enc:AAAA' } } });
  const profileOther = makeOp({ entity: 'memberProfile', entityId: 'carol', type: 'update' });
  const unknown = makeOp({ entity: 'mystery' });
  const r = await postOps(srv, eventId, bob, [voucher, profileOwn, profileOther, unknown, { nope: 1 }]);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.accepted.map((a) => a.opId), [profileOwn.id]);
  const reasons = Object.fromEntries(r.body.rejected.map((x) => [x.opId, x.reason]));
  assert.equal(reasons[voucher.id], 'forbidden-entity');
  assert.equal(reasons[profileOther.id], 'forbidden-profile');
  assert.equal(reasons[unknown.id], 'unknown-entity');
  assert.ok(r.body.rejected.some((x) => x.reason === 'bad-op'));

  const ok = await postOps(srv, eventId, alice, [voucher]);
  assert.equal(ok.body.accepted.length, 1);

  const huge = makeOp({ changes: { note: { before: null, after: 'x'.repeat(70 * 1024) } } });
  assert.equal((await postOps(srv, eventId, alice, [huge])).body.rejected[0].reason, 'op-too-large');
  assert.equal((await postOps(srv, eventId, alice, [])).status, 400);
  assert.equal((await postOps(srv, eventId, alice, Array.from({ length: 501 }, () => makeOp()))).status, 400);
});

test('ops: idempotent by op id, pagination, ordering', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const ops = Array.from({ length: 5 }, (_, i) => makeOp({ timestamp: 1_700_000_000_000 + i }));
  const first = await postOps(srv, eventId, alice, ops);
  assert.equal(first.body.accepted.length, 5);
  const seqs = first.body.accepted.map((a) => a.seq);
  assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b));
  const second = await postOps(srv, eventId, alice, [ops[2], makeOp()]);
  assert.equal(second.body.accepted[0].seq, seqs[2]);
  const count = await srv.db.query('SELECT count(*) AS n FROM ops WHERE event_id = $1', [eventId]);
  assert.equal(Number(count[0].n), 6);

  const p1 = await srv.call('GET', `/v1/events/${eventId}/ops?after=0&limit=4`, { token: bob });
  assert.equal(p1.body.ops.length, 4);
  assert.equal(p1.body.hasMore, true);
  assert.equal(p1.body.ops[0].op.id, ops[0].id);
  assert.equal(p1.body.ops[0].memberId, 'alice');
  const p2 = await srv.call('GET', `/v1/events/${eventId}/ops?after=${p1.body.lastSeq}&limit=4`, { token: bob });
  assert.equal(p2.body.ops.length, 2);
  assert.equal(p2.body.hasMore, false);
  const none = await srv.call('GET', `/v1/events/${eventId}/ops?after=${p2.body.lastSeq}`, { token: bob });
  assert.deepEqual([none.body.ops.length, none.body.lastSeq], [0, p2.body.lastSeq]);
  assert.equal((await srv.call('GET', `/v1/events/${eventId}/ops?limit=9999`, { token: bob })).status, 400);
});

test('non-member gets 404; unauthenticated 401', async (t) => {
  const srv = await startServer(t);
  const a = await seedEvent(srv);
  const b = await seedEvent(srv);
  for (const [m, p] of [
    ['GET', `/v1/events/${a.eventId}/ops`],
    ['GET', `/v1/events/${a.eventId}/members`],
    ['GET', `/v1/events/${a.eventId}/devices`],
    ['GET', `/v1/events/${a.eventId}/audit`],
    ['DELETE', `/v1/events/${a.eventId}`],
  ]) {
    const r = await srv.call(m, p, { token: b.alice });
    assert.equal(r.status, 404, `${m} ${p}`);
    assert.equal(r.body.error.code, 'event-not-found');
  }
  assert.equal((await srv.call('GET', `/v1/events/${a.eventId}/ops`)).status, 401);
  assert.equal((await srv.call('GET', '/v1/me', { token: 'x'.repeat(43) })).status, 401);
});

test('roles: admin only, last-admin protection, members list', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const put = (token, member, roles) => srv.call('PUT', `/v1/events/${eventId}/members/${member}/roles`, { token, body: { roles } });
  assert.equal((await put(bob, 'bob', ['admin'])).status, 403);
  assert.equal((await put(alice, 'alice', ['treasurer'])).body.error.code, 'last-admin');
  assert.equal((await put(alice, 'alice', ['member'])).body.error.code, 'last-admin');
  assert.equal((await put(alice, 'ghost', ['member'])).body.error.code, 'member-not-found');
  assert.equal((await put(alice, 'bob', ['boss'])).status, 400);
  assert.deepEqual((await put(alice, 'bob', ['treasurer', 'member'])).body.roles, ['treasurer', 'member']);
  assert.equal((await postOps(srv, eventId, bob, [makeOp()])).body.accepted.length, 1);
  assert.equal((await put(alice, 'bob', ['admin'])).status, 200);
  assert.equal((await put(alice, 'alice', ['member'])).status, 200);
  assert.equal((await put(bob, 'bob', ['member'])).body.error.code, 'last-admin');
  const list = await srv.call('GET', `/v1/events/${eventId}/members`, { token: bob });
  const byId = Object.fromEntries(list.body.members.map((m) => [m.memberId, m]));
  assert.deepEqual(byId.bob.roles, ['admin']);
  assert.equal(byId.bob.activeDevices, 1);
  const add = await srv.call('POST', `/v1/events/${eventId}/members`, { token: bob, body: { memberId: 'dan', displayName: 'د' } });
  assert.equal(add.status, 201);
  assert.equal((await srv.call('POST', `/v1/events/${eventId}/members`, { token: bob, body: { memberId: 'dan', displayName: 'د' } })).status, 409);
  assert.equal((await srv.call('POST', `/v1/events/${eventId}/members`, { token: alice, body: { memberId: 'eve', displayName: 'ه' } })).status, 403);
});

test('devices: revoke rejects immediately and disconnects socket; list scoping', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob, carol } = await seedEvent(srv);
  const bobDevices = await srv.call('GET', `/v1/events/${eventId}/devices`, { token: bob });
  assert.equal(bobDevices.body.devices.length, 1);
  const all = await srv.call('GET', `/v1/events/${eventId}/devices`, { token: alice });
  assert.equal(all.body.devices.length, 3);
  const bobId = bobDevices.body.devices[0].deviceId;
  const carolId = (await srv.call('GET', '/v1/me', { token: carol })).body.deviceId;
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}/devices/${carolId}`, { token: bob })).status, 403);

  const s = srv.socket(bob);
  await once(s, 'ready');
  const revoked = once(s, 'device-revoked');
  const closed = once(s, 'disconnect');
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}/devices/${bobId}`, { token: alice })).status, 200);
  assert.equal((await revoked).deviceId, bobId);
  await closed;
  const after = await srv.call('GET', '/v1/me', { token: bob });
  assert.equal(after.status, 401);
  assert.equal(after.body.error.code, 'device-revoked');
  assert.equal((await postOps(srv, eventId, bob, [makeOp({ entity: 'memberProfile', entityId: 'bob' })])).status, 401);
  const bad = srv.socket(bob);
  const err = await once(bad, 'connect_error');
  assert.equal(err.data.code, 'device-revoked');
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}/devices/${carolId}`, { token: carol })).status, 200);
});

test('audit log: admin only, paginated', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  await srv.call('PUT', `/v1/events/${eventId}/members/bob/roles`, { token: alice, body: { roles: ['treasurer'] } });
  assert.equal((await srv.call('GET', `/v1/events/${eventId}/audit`, { token: bob })).status, 403);
  const p1 = await srv.call('GET', `/v1/events/${eventId}/audit?limit=3`, { token: alice });
  assert.equal(p1.body.entries.length, 3);
  assert.ok(p1.body.nextBefore);
  assert.equal(p1.body.entries[0].action, 'roles.changed');
  const p2 = await srv.call('GET', `/v1/events/${eventId}/audit?limit=50&before=${p1.body.nextBefore}`, { token: alice });
  const actions = [...p1.body.entries, ...p2.body.entries].map((e) => e.action);
  for (const a of ['event.created', 'invite.created', 'invite.redeemed', 'roles.changed']) assert.ok(actions.includes(a), a);
  assert.equal(p2.body.nextBefore, null);
});

test('purge removes everything and disconnects sockets', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  await postOps(srv, eventId, alice, [makeOp()]);
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}`, { token: bob })).status, 403);
  const s = srv.socket(bob);
  await once(s, 'ready');
  const purged = once(s, 'event-purged');
  const closed = once(s, 'disconnect');
  assert.equal((await srv.call('DELETE', `/v1/events/${eventId}`, { token: alice })).status, 200);
  await purged;
  await closed;
  for (const table of ['ops', 'members', 'member_roles', 'devices', 'invites', 'audit_log']) {
    const r = await srv.db.query(`SELECT count(*) AS n FROM ${table} WHERE event_id = $1`, [eventId]);
    assert.equal(Number(r[0].n), 0, table);
  }
  assert.equal((await srv.db.query('SELECT id FROM events WHERE id = $1', [eventId])).length, 0);
  assert.equal((await srv.call('GET', '/v1/me', { token: alice })).status, 401);
});

test('socket: broadcast after accepted ops, roles-changed, auth required', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const other = await seedEvent(srv);
  const sBob = srv.socket(bob);
  const sOther = srv.socket(other.alice);
  const sNone = srv.socket('nope'.repeat(10));
  await Promise.all([once(sBob, 'ready'), once(sOther, 'ready')]);
  assert.equal((await once(sNone, 'connect_error')).data.code, 'unauthorized');

  let leaked = false;
  sOther.on('ops', () => (leaked = true));
  const got = once(sBob, 'ops');
  const op = makeOp();
  const r = await postOps(srv, eventId, alice, [op]);
  const msg = await got;
  assert.equal(msg.ops[0].op.id, op.id);
  assert.equal(msg.ops[0].seq, r.body.accepted[0].seq);
  assert.equal(msg.lastSeq, r.body.lastSeq);

  let dup = false;
  sBob.on('ops', () => (dup = true));
  await postOps(srv, eventId, alice, [op]);
  const roles = once(sBob, 'roles-changed');
  await srv.call('PUT', `/v1/events/${eventId}/members/bob/roles`, { token: alice, body: { roles: ['treasurer'] } });
  assert.deepEqual(await roles, { memberId: 'bob', roles: ['treasurer'] });
  assert.equal(dup, false, "dup");
  assert.equal(leaked, false, "leaked");
});

test('CORS allowlist and error shapes', async (t) => {
  const srv = await startServer(t);
  const good = await srv.call('GET', '/health', { headers: { origin: 'https://ok.example' } });
  assert.equal(good.headers.get('access-control-allow-origin'), 'https://ok.example');
  const evil = await srv.call('GET', '/health', { headers: { origin: 'https://evil.example' } });
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
  assert.equal((await srv.call('GET', '/v1/nothing')).body.error.code, 'not-found');
  const raw = await fetch(`${srv.url}/v1/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{oops' });
  assert.equal((await raw.json()).error.code, 'bad-json');
  const big = await srv.call('POST', '/v1/events', { body: { eventId: uid('E'), title: 'x'.repeat(300 * 1024) } });
  assert.equal(big.status, 413);
});
