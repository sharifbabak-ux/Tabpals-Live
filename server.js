import { createApp } from './src/app.js';
import { loadConfig } from './src/config.js';
import { createPgDb, migrate } from './src/db.js';

const config = loadConfig();
if (!config.databaseUrl) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
const db = await createPgDb(config.databaseUrl);
await migrate(db);
const { httpServer } = createApp({ db, config });
httpServer.listen(config.port, () => console.log(`TabPals API listening on ${config.port}`));
