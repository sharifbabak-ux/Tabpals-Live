import test from 'node:test';
import assert from 'node:assert/strict';
import { io as connect } from 'socket.io-client';
import { createApp } from '../server.js';

const emit = (s, ev, data) => new Promise((res) => s.emit(ev, data, res));
const once = (s, ev) => new Promise((res) => s.once(ev, res));

test('room create, join and message delivery', async (t) => {
  const { httpServer, io } = createApp();
  await new Promise((r) => httpServer.listen(0, r));
  const url = `http://localhost:${httpServer.address().port}`;
  const a = connect(url, { transports: ['websocket'] });
  const b = connect(url, { transports: ['websocket'] });
  t.after(() => {
    a.close();
    b.close();
    io.close();
  });
  await Promise.all([once(a, 'connect'), once(b, 'connect')]);

  const health = await (await fetch(`${url}/health`)).json();
  assert.equal(health.status, 'ok');

  const created = await emit(a, 'create-room', { name: 'علی' });
  assert.ok(created.ok);
  assert.match(created.code, /^[A-HJ-NP-Z2-9]{6}$/);

  assert.equal((await emit(b, 'join-room', { code: 'ZZZZZZ', name: 'سارا' })).error, 'not-found');

  const joined = await emit(b, 'join-room', { code: created.code, name: 'سارا' });
  assert.ok(joined.ok);
  assert.equal(joined.members.length, 2);

  const got = once(b, 'message');
  assert.ok((await emit(a, 'message', { text: 'سلام' })).ok);
  const msg = await got;
  assert.equal(msg.text, 'سلام');
  assert.equal(msg.name, 'علی');

  assert.equal((await emit(a, 'message', { text: 'x'.repeat(501) })).error, 'too-long');
});
