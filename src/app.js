import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { createServer } from 'node:http';
import { ApiError, errorBody } from './errors.js';
import { buildRouter } from './routes.js';
import { attachRealtime } from './realtime.js';
import { mountTestRooms } from './test-rooms.js';

export function createApp({ db, config }) {
  const app = express();
  const httpServer = createServer(app);
  const { io, hub } = attachRealtime(httpServer, { db, config });

  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Liara terminates TLS in front of the app
  app.use(helmet());

  // Log only method, route pattern, status, duration — never bodies, tokens, or raw paths.
  if (config.log) {
    app.use((req, res, next) => {
      const t0 = process.hrtime.bigint();
      res.on('finish', () => {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        const pattern = req.route ? `${req.baseUrl}${req.route.path}` : '(unmatched)';
        console.log(`${req.method} ${pattern} ${res.statusCode} ${ms.toFixed(0)}ms`);
      });
      next();
    });
  }

  app.use(
    cors({
      origin(origin, cb) {
        // No Origin header = non-browser client; browsers must be on the allowlist.
        cb(null, !origin || config.allowedOrigins.includes(origin) ? origin || false : false);
      },
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Authorization', 'Content-Type'],
      maxAge: 600,
    }),
  );
  app.use(
    rateLimit({
      windowMs: 60_000,
      limit: config.limits.globalPerMin,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      handler: (_req, res) => res.status(429).json(errorBody('rate-limited')),
    }),
  );

  app.get('/health', (_req, res) => res.json({ status: 'ok', time: Date.now() }));
  app.use('/v1', buildRouter({ db, config, hub }));

  let stopTestRooms = () => {};
  if (config.enableTestPage) stopTestRooms = mountTestRooms(app, io);

  app.use((_req, res) => res.status(404).json(errorBody('not-found')));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err instanceof ApiError) return res.status(err.status).json(errorBody(err.code, err.message));
    if (err.type === 'entity.too.large') return res.status(413).json(errorBody('payload-too-large'));
    if (err.type === 'entity.parse.failed') return res.status(400).json(errorBody('bad-json'));
    console.error('unhandled error:', err.name, err.code || ''); // never log message/stack: may echo input
    res.status(500).json(errorBody('internal-error'));
  });

  httpServer.on('close', stopTestRooms);
  return { app, httpServer, io, hub };
}
