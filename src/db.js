import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

/** Wrap a pg Pool (or pg-mem pool) as {query, tx, close}. Parameterized SQL only. */
export function wrapPool(pool) {
  const runner = (client) => ({ query: (sql, params) => client.query(sql, params).then((r) => r.rows) });
  return {
    ...runner(pool),
    async tx(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(runner(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

export async function createPgDb(databaseUrl) {
  const { default: pg } = await import('pg');
  return wrapPool(new pg.Pool({ connectionString: databaseUrl, max: 10 }));
}

/** Run every migrations/*.sql not yet applied, each in its own transaction, in filename order. */
export async function migrate(db) {
  await db.query(
    'CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
  );
  const done = new Set((await db.query('SELECT name FROM schema_migrations')).map((r) => r.name));
  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort();
  for (const file of files) {
    if (done.has(file)) continue;
    const sql = await readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
    await db.tx(async (q) => {
      await q.query(sql);
      await q.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
    });
  }
}

// Serializes writers per event so seq order matches commit order, and so role/last-admin checks don't race.
export const lockEvent = (q, eventId) => q.query('SELECT id FROM events WHERE id = $1 FOR UPDATE', [eventId]);
