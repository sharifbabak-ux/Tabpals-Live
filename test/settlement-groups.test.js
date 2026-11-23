import test from 'node:test';
import assert from 'node:assert/strict';
import { makeOp, once, seedEvent, startServer, uid } from './helpers.js';
import { checkOp } from '../src/permissions.js';

const ev = (id, p = '') => `/v1/events/${id}${p}`;
const sg = (type, entityId = uid('SG')) =>
  makeOp({ entity: 'settlementGroups', entityId, type, changes: { name: { after: 'enc:v1:XYZ' } } });

test('checkOp settlementGroups: admin/treasurer ok, plain member forbidden-entity', () => {
  const bob = { memberId: 'bob', roles: ['member'] };
  const admin = { memberId: 'alice', roles: ['admin', 'treasurer', 'member'] };
  const treasurer = { memberId: 'tina', roles: ['treasurer', 'member'] };
  for (const type of ['create', 'update', 'delete']) {
    const op = { entity: 'settlementGroups', entityId: 'G1', type };
    assert.deepEqual(checkOp(admin, op), { ok: true });
    assert.deepEqual(checkOp(treasurer, op), { ok: true });
    assert.equal(checkOp(bob, op).reason, 'forbidden-entity');
  }
});

test('API: settlementGroups writes by admin and non-admin treasurer; member rejected; others receive via GET and socket', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob, carol } = await seedEvent(srv);
  const post = (token, ops) => srv.call('POST', ev(eventId, '/ops'), { token, body: { ops } });

  const carolSock = srv.socket(carol);
  await once(carolSock, 'ready');
  const seen = [];
  carolSock.on('ops', (m) => seen.push(...m.ops.map((o) => o.op.id)));

  const id = uid('SG');
  const ops = [sg('create', id), sg('update', id), sg('delete', id)];
  const r = await post(alice, ops);
  assert.deepEqual(r.body.accepted.map((a) => a.opId), ops.map((o) => o.id));

  const rej = await post(bob, [sg('create')]);
  assert.equal(rej.body.rejected[0].reason, 'forbidden-entity');

  await srv.call('PUT', ev(eventId, '/members/bob/roles'), { token: alice, body: { roles: ['treasurer', 'member'] } });
  const byTreasurer = [sg('create'), sg('update'), sg('delete')];
  const r2 = await post(bob, byTreasurer);
  assert.deepEqual(r2.body.accepted.map((a) => a.opId), byTreasurer.map((o) => o.id));

  const all = [...ops, ...byTreasurer].map((o) => o.id);
  const got = (await srv.call('GET', ev(eventId, '/ops'), { token: carol })).body.ops.map((o) => o.op.id);
  assert.deepEqual(got.filter((x) => all.includes(x)), all);
  while (seen.length < all.length) await new Promise((res) => setTimeout(res, 20));
  assert.deepEqual(seen, all);
});
