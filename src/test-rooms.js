import express from 'express';
import { randomInt } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Old connectivity test page (in-memory rooms). Only mounted when ENABLE_TEST_PAGE=true.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no O/0/I/1
const CODE_LENGTH = 6;
const MAX_MEMBERS = 30;
const MAX_MESSAGE = 500;
const MAX_NAME = 24;
const MAX_IDLE_MS = 6 * 60 * 60 * 1000;
const MAX_EMPTY_MS = 30 * 60 * 1000;
const RATE_LIMIT = 10;

export function mountTestRooms(app, io) {
  const nsp = io.of('/test');
  app.use(express.static(path.join(__dirname, '..', 'public')));

  /** @type {Map<string, {members: Map<string,string>, lastActivity: number, emptySince: number|null}>} */
  const rooms = new Map();

  const newCode = () => {
    for (;;) {
      let c = '';
      for (let i = 0; i < CODE_LENGTH; i++) c += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
      if (!rooms.has(c)) return c;
    }
  };
  const cleanName = (n) =>
    typeof n === 'string' ? n.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_NAME) : '';
  const membersOf = (room) => [...room.members.values()];
  const broadcastMembers = (code) => {
    const room = rooms.get(code);
    if (room) nsp.to(code).emit('members', { code, members: membersOf(room) });
  };

  function leave(socket) {
    const code = socket.data.room;
    if (!code) return;
    socket.data.room = null;
    socket.leave(code);
    const room = rooms.get(code);
    if (!room) return;
    room.members.delete(socket.id);
    room.lastActivity = Date.now();
    if (room.members.size === 0) room.emptySince = Date.now();
    broadcastMembers(code);
  }

  nsp.on('connection', (socket) => {
    socket.data.room = null;
    let windowStart = Date.now();
    let count = 0;
    // returns true if the event is allowed
    const allow = (ack) => {
      const now = Date.now();
      if (now - windowStart >= 1000) {
        windowStart = now;
        count = 0;
      }
      if (++count > RATE_LIMIT) {
        if (typeof ack === 'function') ack({ ok: false, error: 'rate-limit' });
        return false;
      }
      return true;
    };
    const reply = (ack, data) => typeof ack === 'function' && ack(data);

    socket.on('ping-test', (ack) => reply(ack, { t: Date.now() }));

    socket.on('create-room', (payload, ack) => {
      if (!allow(ack)) return;
      const name = cleanName(payload?.name);
      if (!name) return reply(ack, { ok: false, error: 'bad-name' });
      leave(socket);
      const code = newCode();
      const room = { members: new Map([[socket.id, name]]), lastActivity: Date.now(), emptySince: null };
      rooms.set(code, room);
      socket.data.room = code;
      socket.join(code);
      reply(ack, { ok: true, code, members: membersOf(room) });
    });

    socket.on('join-room', (payload, ack) => {
      if (!allow(ack)) return;
      const name = cleanName(payload?.name);
      const code = typeof payload?.code === 'string' ? payload.code.trim().toUpperCase() : '';
      if (!name) return reply(ack, { ok: false, error: 'bad-name' });
      const room = rooms.get(code);
      if (!room) return reply(ack, { ok: false, error: 'not-found' });
      if (socket.data.room !== code) {
        if (room.members.size >= MAX_MEMBERS) return reply(ack, { ok: false, error: 'room-full' });
        leave(socket);
        socket.data.room = code;
        socket.join(code);
      }
      room.members.set(socket.id, name);
      room.emptySince = null;
      room.lastActivity = Date.now();
      reply(ack, { ok: true, code, members: membersOf(room) });
      broadcastMembers(code);
    });

    socket.on('leave-room', (_payload, ack) => {
      if (!allow(ack)) return;
      leave(socket);
      reply(ack, { ok: true });
    });

    socket.on('message', (payload, ack) => {
      if (!allow(ack)) return;
      const code = socket.data.room;
      const room = code && rooms.get(code);
      if (!room) return reply(ack, { ok: false, error: 'not-in-room' });
      const text = typeof payload?.text === 'string' ? payload.text : '';
      if (!text.trim()) return reply(ack, { ok: false, error: 'empty' });
      if (text.length > MAX_MESSAGE) return reply(ack, { ok: false, error: 'too-long' });
      room.lastActivity = Date.now();
      nsp.to(code).emit('message', {
        id: socket.id,
        name: room.members.get(socket.id),
        text,
        time: Date.now(),
      });
      reply(ack, { ok: true });
    });

    socket.on('disconnect', () => leave(socket));
  });

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [code, room] of rooms) {
      const idle = now - room.lastActivity > MAX_IDLE_MS;
      const emptyLong = room.emptySince !== null && now - room.emptySince > MAX_EMPTY_MS;
      if (idle || emptyLong) {
        nsp.to(code).emit('room-closed', { code });
        nsp.in(code).socketsLeave(code);
        rooms.delete(code);
      }
    }
  }, 60 * 1000);
  sweep.unref();

  return () => clearInterval(sweep);
}
