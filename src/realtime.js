import { Server } from 'socket.io';
import { authenticateToken } from './auth.js';
import { ApiError } from './errors.js';

const eventRoom = (id) => `event:${id}`;
const deviceRoom = (id) => `device:${id}`;

/** Attach Socket.IO to the http server. Returns {io, hub} — hub is what routes call after writes. */
export function attachRealtime(httpServer, { db, config }) {
  const io = new Server(httpServer, {
    cors: { origin: config.allowedOrigins, methods: ['GET', 'POST'] },
    maxHttpBufferSize: 4 * 1024,
    transports: ['websocket', 'polling'],
  });

  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      const d = await authenticateToken(db, typeof token === 'string' ? token : null);
      socket.data.device = d;
      next();
    } catch (err) {
      const e = new Error(err.message);
      e.data = { code: err instanceof ApiError ? err.code : 'internal-error' };
      next(e);
    }
  });

  io.on('connection', (socket) => {
    const d = socket.data.device;
    socket.join([eventRoom(d.eventId), deviceRoom(d.id)]);
    socket.emit('ready', { eventId: d.eventId, memberId: d.memberId, roles: d.roles });
  });

  const hub = {
    opsAccepted: (eventId, ops, lastSeq) => io.to(eventRoom(eventId)).emit('ops', { ops, lastSeq }),
    rolesChanged: (eventId, memberId, roles) => io.to(eventRoom(eventId)).emit('roles-changed', { memberId, roles }),
    deviceRevoked(deviceId) {
      io.to(deviceRoom(deviceId)).emit('device-revoked', { deviceId });
      io.in(deviceRoom(deviceId)).disconnectSockets(true);
    },
    eventPurged(eventId) {
      io.to(eventRoom(eventId)).emit('event-purged', { eventId });
      io.in(eventRoom(eventId)).disconnectSockets(true);
    },
  };
  return { io, hub };
}
