import test from 'node:test';
import assert from 'node:assert/strict';
import { makeOp, once, seedEvent, startServer, uid } from './helpers.js';
import { checkOp } from '../src/permissions.js';

const ev = (id, p = '') => `/v1/events/${id}${p}`;
const sub = (entityId, type = 'update') =>
  makeOp({ entity: 'orderSubmissions', entityId, type, changes: { payload: { after: 'enc:v1:XYZ' } } });
const chk = (actor, entityId, type = 'update') => checkOp(actor, { entity: 'orderSubmissions', entityId, type });

const bob = { memberId: 'bob', roles: ['member'] };
const admin = { memberId: 'alice', roles: ['admin', 'treasurer', 'member'] };
const treasurer = { memberId: 'tina', roles: ['treasurer', 'member'] }; // treasurer who is not admin
const onlyAdmin = { memberId: 'adam', roles: ['admin'] };

test('checkOp orderSubmissions: plain member may write only own record (create/update/delete)', () => {
  for (const type of ['create', 'update', 'delete']) assert.deepEqual(chk(bob, 'order:S1:bob', type), { ok: true });
  assert.equal(chk(bob, 'order:S1:carol').reason, 'forbidden-order');
  for (const type of ['purge', 'archive', 'restore', 'logSend']) {
    assert.equal(chk(bob, 'order:S1:bob', type).reason, 'forbidden-order');
  }
  assert.equal(chk(bob, 'order:S1:bobby').reason, 'forbidden-order'); // exact match, not prefix
});

test('checkOp orderSubmissions: admin and treasurer may write any record and any op type', () => {
  for (const a of [admin, treasurer, onlyAdmin]) {
    for (const type of ['create', 'update', 'delete', 'archive', 'restore', 'purge']) {
      assert.deepEqual(chk(a, 'order:S1:bob', type), { ok: true });
      assert.deepEqual(chk(a, 'order:S1:' + a.memberId, type), { ok: true });
    }
  }
});

test('checkOp orderSubmissions: malformed ids are bad-op (for every role)', () => {
  for (const id of ['order:S1', 'order::x', 'order:S1:', 'foo:S1:x', 'order:S1:x:y', 'order', '', 'order:S1:bob:']) {
    for (const a of [bob, admin, treasurer]) assert.equal(chk(a, id).reason, 'bad-op', `${id} / ${a.memberId}`);
  }
});

test('checkOp: orderSessions permissions unchanged', () => {
  const op = { entity: 'orderSessions', entityId: 'S1', type: 'update' };
  assert.equal(checkOp(bob, op).reason, 'forbidden-entity');
  assert.ok(checkOp(treasurer, op).ok && checkOp(admin, op).ok);
});

test('API: mixed batch is split per op; accepted ops reach others via GET and socket', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob: bobT, carol } = await seedEvent(srv);
  const post = (token, ops) => srv.call('POST', ev(eventId, '/ops'), { token, body: { ops } });

  const carolSock = srv.socket(carol);
  await once(carolSock, 'ready');
  const seen = [];
  carolSock.on('ops', (m) => seen.push(...m.ops.map((o) => o.op.id)));

  const okCreate = sub('order:S1:bob', 'create');
  const okDelete = sub('order:S1:bob', 'delete');
  const otherMember = sub('order:S1:carol');
  const purgeOwn = sub('order:S1:bob', 'purge');
  const malformed = sub('order:S1');
  const sessions = makeOp({ entity: 'orderSessions', entityId: 'S1', type: 'create' });
  const r = await post(bobT, [okCreate, otherMember, purgeOwn, malformed, sessions, okDelete]);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.accepted.map((a) => a.opId), [okCreate.id, okDelete.id]);
  const why = Object.fromEntries(r.body.rejected.map((x) => [x.opId, x.reason]));
  assert.deepEqual(why, {
    [otherMember.id]: 'forbidden-order',
    [purgeOwn.id]: 'forbidden-order',
    [malformed.id]: 'bad-op',
    [sessions.id]: 'forbidden-entity',
  });
  assert.ok(r.body.rejected.every((x) => typeof x.message === 'string' && x.message));

  // only accepted ops are stored
  const stored = (await srv.db.query('SELECT op_id FROM ops WHERE event_id = $1 ORDER BY seq', [eventId])).map((x) => x.op_id);
  assert.deepEqual(stored, [okCreate.id, okDelete.id]);

  // other members receive them (GET and socket), unfiltered
  const got = (await srv.call('GET', ev(eventId, '/ops'), { token: carol })).body.ops.map((o) => o.op.id);
  assert.deepEqual(got, [okCreate.id, okDelete.id]);
  while (seen.length < 2) await new Promise((res) => setTimeout(res, 20));
  assert.deepEqual(seen, [okCreate.id, okDelete.id]);

  // carol cannot write bob's record; alice (admin+treasurer) can write anyone's
  assert.equal((await post(carol, [sub('order:S1:bob')])).body.rejected[0].reason, 'forbidden-order');
  const byAlice = sub('order:S1:bob', 'update');
  assert.equal((await post(alice, [byAlice])).body.accepted.length, 1);
});

test('API: treasurer (not admin) writes any member record; revoked role is enforced live', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob: bobT, carol } = await seedEvent(srv);
  const post = (token, ops) => srv.call('POST', ev(eventId, '/ops'), { token, body: { ops } });
  assert.equal((await post(bobT, [sub('order:S1:carol')])).body.rejected[0].reason, 'forbidden-order');
  await srv.call('PUT', ev(eventId, '/members/bob/roles'), { token: alice, body: { roles: ['treasurer', 'member'] } });
  assert.equal((await post(bobT, [sub('order:S1:carol', 'delete')])).body.accepted.length, 1);
  assert.equal((await post(bobT, [makeOp({ entity: 'orderSessions', entityId: 'S1', type: 'create' })])).body.accepted.length, 1);
  assert.equal((await post(carol, [sub('order:S1:bob')])).body.rejected[0].reason, 'forbidden-order');
});

test('entityId length: 200 accepted, 201 rejected; op id still capped at 128', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice } = await seedEvent(srv);
  const post = (ops) => srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops } });
  const pad = (n) => 'o'.repeat(n);
  const id200 = 'order:' + pad(200 - 'order:'.length - ':bob'.length) + ':bob';
  assert.equal(id200.length, 200);
  assert.equal((await post([sub(id200)])).body.accepted.length, 1);
  const plain200 = makeOp({ entityId: pad(200) });
  const plain201 = makeOp({ entityId: pad(201) });
  const r = await post([plain200, plain201]);
  assert.deepEqual(r.body.accepted.map((a) => a.opId), [plain200.id]);
  assert.equal(r.body.rejected[0].reason, 'bad-op');
  const longOpId = await post([makeOp({ id: pad(129) })]);
  assert.equal(longOpId.body.rejected[0].reason, 'bad-op');
  assert.equal((await post([makeOp({ id: pad(128) })])).body.accepted.length, 1);
});

test('event purge removes orderSubmissions ops too', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  assert.equal(
    (await srv.call('POST', ev(eventId, '/ops'), { token: bob, body: { ops: [sub('order:S1:bob', 'create')] } })).body.accepted.length,
    1,
  );
  const count = async () => Number((await srv.db.query("SELECT count(*) AS c FROM ops WHERE entity = 'orderSubmissions'"))[0].c);
  assert.equal(await count(), 1);
  assert.equal((await srv.call('DELETE', ev(eventId), { token: alice })).status, 200);
  assert.equal(await count(), 0);
});
