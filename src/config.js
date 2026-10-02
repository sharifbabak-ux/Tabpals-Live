const DEFAULT_ORIGINS = 'https://sharifbabak-ux.github.io,https://tabpals.ir,https://app.tabpals.ir';

export function loadConfig(env = process.env, overrides = {}) {
  return {
    port: Number(env.PORT) || 3000,
    databaseUrl: env.DATABASE_URL,
    allowedOrigins: (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    enableTestPage: env.ENABLE_TEST_PAGE === 'true',
    inviteTtlMs: 7 * 24 * 60 * 60 * 1000,
    limits: {
      globalPerMin: 600, // per IP, all routes
      createPerHour: 20, // per IP, POST /v1/events
      redeemFailPer15Min: 10, // per IP, failed redeems only
      opsPerMin: 120, // per device, POST ops
    },
    log: true,
    ...overrides,
  };
}
