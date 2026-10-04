import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { makeOp, once, seedEvent, startServer, uid } from './helpers.js';
import { isEncryptedValue, checkOp } from '../src/permissions.js';

const jwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
const ev = (id, p = '') => `/v1/events/${id}${p}`;
const waitFor = (s, name, ms = 1500) =>
  Promise.race([once(s, name), new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout ${name}`)), ms))]);
const connected = async (srv, token) => {
  const s = srv.socket(token);
  await once(s, 'ready');
  return s;
};
const deviceIdOf = async (srv, token) => (await srv.call('GET', '/v1/me', { token })).body.deviceId;

test('invites list: statuses, admin only, no secrets', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  // seedEvent already produced two used invites (bob, carol)
  const pending = await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'bob' } });
  const toRevoke = await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'bob' } });
  await srv.call('DELETE', ev(eventId, `/invites/${toRevoke.body.inviteId}`), { token: alice });
  const expired = await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'carol' } });
  await srv.db.query("UPDATE invites SET expires_at = now() - interval '1 hour' WHERE id = $1", [expired.body.inviteId]);

  const list = await srv.call('GET', ev(eventId, '/invites'), { token: alice });
  assert.equal(list.status, 200);
  const by = Object.fromEntries(list.body.invites.map((i) => [i.inviteId, i]));
  assert.equal(by[pending.body.inviteId].status, 'pending');
  assert.equal(by[toRevoke.body.inviteId].status, 'revoked');
  assert.equal(by[expired.body.inviteId].status, 'expired');
  assert.equal(list.body.invites.filter((i) => i.status === 'used').length, 2);
  const used = list.body.invites.find((i) => i.status === 'used');
  assert.ok(used.usedAt);
  assert.equal(used.createdBy, 'alice');
  assert.deepEqual(Object.keys(used).sort(), ['createdAt', 'createdBy', 'expiresAt', 'inviteId', 'memberId', 'status', 'usedAt']);
  const raw = JSON.stringify(list.body);
  assert.ok(!raw.includes(pending.body.inviteToken) && !raw.includes(pending.body.shortCode));
  assert.equal((await srv.call('GET', ev(eventId, '/invites'), { token: bob })).status, 403);
});

test('remove member: full cleanup, sockets, ops kept, restore, last admin', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob, carol } = await seedEvent(srv);
  const op = makeOp({ entity: 'vouchers', entityId: 'V-bob' });
  await srv.call('POST', ev(eventId, '/ops'), { token: bob, body: { ops: [] } }); // 400, no effect
  await srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops: [op] } });
  const pend = await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'bob' } });
  await srv.call('PUT', ev(eventId, '/members/bob/roles'), { token: alice, body: { roles: ['treasurer', 'member'] } });

  const bobSock = await connected(srv, bob);
  const carolSock = await connected(srv, carol);
  const bobRevoked = waitFor(bobSock, 'device-revoked');
  const bobClosed = waitFor(bobSock, 'disconnect');
  const carolSees = waitFor(carolSock, 'member-removed');

  assert.equal((await srv.call('DELETE', ev(eventId, '/members/bob'), { token: carol })).status, 403);
  const del = await srv.call('DELETE', ev(eventId, '/members/bob'), { token: alice });
  assert.equal(del.status, 200);
  assert.deepEqual(await carolSees, { memberId: 'bob' });
  await bobRevoked;
  await bobClosed;
  assert.equal((await srv.call('GET', '/v1/me', { token: bob })).body.error.code, 'device-revoked');

  const members = (await srv.call('GET', ev(eventId, '/members'), { token: alice })).body.members;
  const b = members.find((m) => m.memberId === 'bob');
  assert.ok(b.removedAt);
  assert.deepEqual(b.roles, []);
  assert.equal(b.activeDevices, 0);
  assert.equal(members.find((m) => m.memberId === 'carol').removedAt, null);
  const inv = (await srv.call('GET', ev(eventId, '/invites'), { token: alice })).body.invites;
  assert.equal(inv.find((i) => i.inviteId === pend.body.inviteId).status, 'revoked');
  // ledger history stays
  const ops = await srv.call('GET', ev(eventId, '/ops'), { token: alice });
  assert.equal(ops.body.ops.length, 1);
  const audit = (await srv.call('GET', ev(eventId, '/audit'), { token: alice })).body.entries;
  assert.ok(audit.some((e) => e.action === 'member.removed' && e.target === 'bob'));

  // idempotent; cannot re-invite or set roles until restored
  assert.equal((await srv.call('DELETE', ev(eventId, '/members/bob'), { token: alice })).status, 200);
  const re = await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'bob' } });
  assert.equal(re.status, 409);
  assert.equal(re.body.error.code, 'member-removed');
  assert.equal((await srv.call('PUT', ev(eventId, '/members/bob/roles'), { token: alice, body: { roles: ['member'] } })).body.error.code, 'member-removed');
  assert.equal((await srv.call('POST', ev(eventId, '/members/bob/restore'), { token: carol })).status, 403);
  assert.equal((await srv.call('POST', ev(eventId, '/members/bob/restore'), { token: alice })).status, 200);
  const restored = (await srv.call('GET', ev(eventId, '/members'), { token: alice })).body.members.find((m) => m.memberId === 'bob');
  assert.equal(restored.removedAt, null);
  assert.deepEqual(restored.roles, []);
  assert.equal((await srv.call('PUT', ev(eventId, '/members/bob/roles'), { token: alice, body: { roles: ['member'] } })).status, 200);
  assert.equal((await srv.call('POST', ev(eventId, '/invites'), { token: alice, body: { memberId: 'bob' } })).status, 201);

  // last admin
  const last = await srv.call('DELETE', ev(eventId, '/members/alice'), { token: alice });
  assert.equal(last.status, 409);
  assert.equal(last.body.error.code, 'last-admin');
  assert.equal((await srv.call('DELETE', ev(eventId, '/members/nobody'), { token: alice })).body.error.code, 'member-not-found');
});

test('public keys: registration, validation, awaiting-key list', async (t) => {
  const srv = await startServer(t);
  const evId = uid('EV');
  const k1 = jwk();
  const created = await srv.call('POST', '/v1/events', {
    body: { eventId: evId, title: 't', creator: { memberId: 'alice', displayName: 'a' }, members: [{ memberId: 'bob', displayName: 'b' }], deviceLabel: 'x', publicKey: k1 },
  });
  assert.equal(created.status, 201);
  const alice = created.body.deviceToken;
  const inv = await srv.call('POST', ev(evId, '/invites'), { token: alice, body: { memberId: 'bob' } });
  const k2 = jwk();
  const key2 = JSON.stringify(k2);
  const red = await srv.call('POST', '/v1/invites/redeem', { body: { shortCode: inv.body.shortCode, deviceLabel: 'iPhone', publicKey: key2 } });
  assert.equal(red.status, 200);
  const bob = red.body.deviceToken;

  const aw = await srv.call('GET', ev(evId, '/devices/awaiting-key'), { token: bob });
  assert.equal(aw.status, 200);
  assert.equal(aw.body.devices.length, 2);
  const bobEntry = aw.body.devices.find((d) => d.deviceId === red.body.deviceId);
  assert.equal(bobEntry.memberId, 'bob');
  assert.equal(bobEntry.label, 'iPhone');
  assert.deepEqual(JSON.parse(bobEntry.publicKey), { kty: 'EC', crv: 'P-256', x: k2.x, y: k2.y });

  // replace via PUT; invalid keys rejected (incl. private keys)
  const k3 = jwk();
  assert.equal((await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: k3 } })).status, 200);
  const aw2 = (await srv.call('GET', ev(evId, '/devices/awaiting-key'), { token: alice })).body.devices;
  assert.equal(JSON.parse(aw2.find((d) => d.deviceId === red.body.deviceId).publicKey).x, k3.x);
  const priv = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
  for (const bad of [priv, { kty: 'RSA' }, 'not json', 42, undefined, JSON.stringify({ ...k3, pad: 'x'.repeat(3000) })]) {
    const r = await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: bad } });
    assert.equal(r.status, 400, JSON.stringify(bad)?.slice(0, 40));
  }
  assert.equal((await srv.call('PUT', '/v1/devices/me/public-key', { body: { publicKey: k3 } })).status, 401);
  const badCreate = await srv.call('POST', '/v1/events', {
    body: { eventId: uid('EV'), title: 't', creator: { memberId: 'a', displayName: 'a' }, deviceLabel: 'x', publicKey: priv },
  });
  assert.equal(badCreate.status, 400);
});

test('key envelopes: post, replace, fetch, isolation, cleanup, socket events', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob, carol } = await seedEvent(srv);
  const other = await seedEvent(srv);
  const aliceDev = await deviceIdOf(srv, alice);
  const bobDev = await deviceIdOf(srv, bob);
  const carolDev = await deviceIdOf(srv, carol);
  const aliceSock = await connected(srv, alice);
  const bobSock = await connected(srv, bob);

  // key-needed to event room when a device registers a key without an envelope
  const needed = waitFor(aliceSock, 'key-needed');
  assert.equal((await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: jwk() } })).status, 200);
  assert.deepEqual(await needed, { deviceId: bobDev, memberId: 'bob' });
  await srv.call('PUT', '/v1/devices/me/public-key', { token: carol, body: { publicKey: jwk() } });

  assert.equal((await srv.call('GET', '/v1/devices/me/key-envelope', { token: bob })).status, 404);

  const delivered = waitFor(bobSock, 'key-delivered');
  const body = { targetDeviceId: bobDev, wrappedKey: 'AAAA-wrapped-1', meta: { v: 1, iv: 'xyz' } };
  assert.equal((await srv.call('POST', ev(eventId, '/key-envelopes'), { token: alice, body })).status, 200);
  assert.deepEqual(await delivered, { deviceId: bobDev, fromDeviceId: aliceDev });
  const got = await srv.call('GET', '/v1/devices/me/key-envelope', { token: bob });
  assert.equal(got.status, 200);
  assert.equal(got.body.wrappedKey, 'AAAA-wrapped-1');
  assert.deepEqual(got.body.meta, { v: 1, iv: 'xyz' });
  assert.equal(got.body.fromDeviceId, aliceDev);

  // awaiting list no longer contains bob; carol still there
  let aw = (await srv.call('GET', ev(eventId, '/devices/awaiting-key'), { token: alice })).body.devices.map((d) => d.deviceId);
  assert.ok(!aw.includes(bobDev) && aw.includes(carolDev));

  // replace: newest wins, one row
  await srv.call('POST', ev(eventId, '/key-envelopes'), { token: carol, body: { targetDeviceId: bobDev, wrappedKey: 'AAAA-wrapped-2' } });
  assert.equal((await srv.call('GET', '/v1/devices/me/key-envelope', { token: bob })).body.wrappedKey, 'AAAA-wrapped-2');
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE target_device_id = $1', [bobDev])).length, 1);

  // rejections
  const post = (token, b, evId = eventId) => srv.call('POST', ev(evId, '/key-envelopes'), { token, body: b });
  assert.equal((await post(alice, { targetDeviceId: aliceDev, wrappedKey: 'x' })).status, 400); // self
  assert.equal((await post(alice, { targetDeviceId: 'nope', wrappedKey: 'x' })).status, 404);
  assert.equal((await post(alice, { targetDeviceId: bobDev, wrappedKey: 'x'.repeat(4097) })).status, 400);
  assert.equal((await post(alice, { targetDeviceId: bobDev, wrappedKey: 'x', meta: { a: 'y'.repeat(1100) } })).status, 400);
  assert.equal((await post(alice, { targetDeviceId: bobDev })).status, 400);
  assert.equal((await post(other.alice, { targetDeviceId: bobDev, wrappedKey: 'x' }, eventId)).status, 404); // non-member
  const otherDev = await deviceIdOf(srv, other.bob);
  assert.equal((await post(alice, { targetDeviceId: otherDev, wrappedKey: 'x' })).status, 404); // cross-event target
  assert.equal((await post(alice, { targetDeviceId: otherDev, wrappedKey: 'x' }, other.eventId)).status, 404); // not our event
  assert.equal((await srv.call('POST', ev(eventId, '/key-envelopes'), { body: { targetDeviceId: bobDev, wrappedKey: 'x' } })).status, 401);
  assert.equal((await srv.call('GET', ev(eventId, '/devices/awaiting-key'), { token: other.alice })).status, 404);
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE target_device_id = $1', [otherDev])).length, 0);

  // audit: ids only
  const entries = (await srv.call('GET', ev(eventId, '/audit'), { token: alice })).body.entries.filter((e) => e.action === 'key.delivered');
  assert.equal(entries.length, 2);
  assert.deepEqual(Object.keys(entries[0].details).sort(), ['fromDevice', 'toDevice']);
  assert.ok(!JSON.stringify(entries).includes('wrapped'));

  // revoking a device deletes its envelope; delivery to it is then refused
  assert.equal((await srv.call('DELETE', ev(eventId, `/devices/${bobDev}`), { token: alice })).status, 200);
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE target_device_id = $1', [bobDev])).length, 0);
  assert.equal((await post(alice, { targetDeviceId: bobDev, wrappedKey: 'x' })).status, 404);

  // removing a member deletes their devices' envelopes
  await post(alice, { targetDeviceId: carolDev, wrappedKey: 'AAAA' });
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE target_device_id = $1', [carolDev])).length, 1);
  await srv.call('DELETE', ev(eventId, '/members/carol'), { token: alice });
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE target_device_id = $1', [carolDev])).length, 0);
  aw = (await srv.call('GET', ev(eventId, '/devices/awaiting-key'), { token: alice })).body.devices.map((d) => d.deviceId);
  assert.ok(!aw.includes(carolDev));

  // purge removes envelopes too
  await srv.call('DELETE', ev(eventId), { token: alice });
  assert.equal((await srv.db.query('SELECT 1 FROM key_envelopes WHERE event_id = $1', [eventId])).length, 0);
});

test('re-registering the same key keeps the envelope; a new key drops it and asks again', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const bobDev = await deviceIdOf(srv, bob);
  const key = jwk();
  await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: key } });
  await srv.call('POST', ev(eventId, '/key-envelopes'), { token: alice, body: { targetDeviceId: bobDev, wrappedKey: 'W' } });
  await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: JSON.stringify(key) } });
  assert.equal((await srv.call('GET', '/v1/devices/me/key-envelope', { token: bob })).status, 200);
  await srv.call('PUT', '/v1/devices/me/public-key', { token: bob, body: { publicKey: jwk() } });
  assert.equal((await srv.call('GET', '/v1/devices/me/key-envelope', { token: bob })).status, 404);
});

test('envelope posts are rate limited per device', async (t) => {
  const srv = await startServer(t, { limits: { ...(await import('../src/config.js')).loadConfig().limits, envelopesPerMin: 3 } });
  const { eventId, alice, bob } = await seedEvent(srv);
  const bobDev = await deviceIdOf(srv, bob);
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await srv.call('POST', ev(eventId, '/key-envelopes'), { token: alice, body: { targetDeviceId: bobDev, wrappedKey: `k${i}` } })).status);
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
});

test('logSend audit: only non-sensitive fields', async (t) => {
  const srv = await startServer(t);
  const { eventId, alice } = await seedEvent(srv);
  const op = makeOp({
    entity: 'statements',
    entityId: 'ST-1',
    type: 'logSend',
    changes: { memberId: 'bob', channel: 'whatsapp', text: 'enc:v1:SECRET', amount: 12345 },
    message: 'سلام بدهی شما ۱۲۳۴۵',
    phone: '09120000000',
  });
  const r = await srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops: [op, op] } });
  assert.equal(r.body.accepted.length, 2);
  const entries = (await srv.call('GET', ev(eventId, '/audit'), { token: alice })).body.entries.filter((e) => e.action === 'statement.sent');
  assert.equal(entries.length, 1); // duplicate op does not double-audit
  assert.equal(entries[0].target, 'ST-1');
  assert.deepEqual(Object.keys(entries[0].details).sort(), ['channel', 'statementId', 'targetMemberId', 'timestamp']);
  assert.equal(entries[0].details.targetMemberId, 'bob');
  assert.equal(entries[0].details.channel, 'whatsapp');
  const raw = JSON.stringify(entries);
  for (const leak of ['SECRET', '12345', '0912', 'سلام']) assert.ok(!raw.includes(leak), leak);
  // a non-logSend op writes no statement.sent entry
  await srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops: [makeOp({ entity: 'statements', type: 'update' })] } });
  const again = (await srv.call('GET', ev(eventId, '/audit'), { token: alice })).body.entries.filter((e) => e.action === 'statement.sent');
  assert.equal(again.length, 1);
});

test('encrypted ledger values are stored verbatim', async (t) => {
  assert.ok(isEncryptedValue('enc:v1:abc') && !isEncryptedValue('enc:v2:abc') && !isEncryptedValue(5));
  const treasurer = { memberId: 'a', roles: ['treasurer'] };
  assert.ok(checkOp(treasurer, { entity: 'persons', entityId: 'p', type: 'update' }).ok);
  const srv = await startServer(t);
  const { eventId, alice, bob } = await seedEvent(srv);
  const enc = 'enc:v1:' + 'A'.repeat(2000);
  const op = makeOp({ entity: 'persons', entityId: 'P1', type: 'update', changes: { name: { before: 'enc:v1:old', after: enc } } });
  assert.equal((await srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops: [op] } })).body.accepted.length, 1);
  assert.equal((await srv.call('GET', ev(eventId, '/ops'), { token: bob })).body.ops[0].op.changes.name.after, enc);
  const huge = makeOp({ entity: 'persons', type: 'update', changes: { name: { after: 'enc:v1:' + 'A'.repeat(70000) } } });
  assert.equal((await srv.call('POST', ev(eventId, '/ops'), { token: alice, body: { ops: [huge] } })).body.rejected[0].reason, 'op-too-large');
});
