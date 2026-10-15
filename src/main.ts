import { applyMigrations } from "@kuzin4u/agentic-core";
import pg from "pg";
import { buildServer, parseEnv } from "./server.js";
import { paoNonceStore, paoPoolConfig, requireDatabaseUrl, startNoncePurge } from "./pao/stores.js";
import { PaoRequestVerifier } from "./pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "./registry/index.js";
import { loadParams } from "./shared/config.js";

const env = parseEnv(process.env.PLATFORM_ENV);
// Неверные стендовые параметры — отказ запуска (fail-closed).
const params = loadParams();
const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Недопустимый PORT=${process.env.PORT}`);
}
const host = process.env.HOST ?? "127.0.0.1";

// Хранилища шлюза ПАО (РП30 п. 4–6): sandbox без DATABASE_URL не запускается; dev без базы — память ядра, один процесс.
// Миграции ядра 001–004 — при запуске одним экземпляром, отдельным пулом без таймаута запроса; сбой — отказ запуска.
// Рабочий пул — с таймаутами соединения и запроса: зависшая база — 503, а не вечное ожидание (инвариант 3).
const databaseUrl = requireDatabaseUrl(env, process.env.DATABASE_URL);
if (databaseUrl) {
  const migrator = new pg.Pool({ connectionString: databaseUrl, max: 1 });
  migrator.on("error", (err) => console.error("PostgreSQL (миграции): сбой соединения пула", err));
  try {
    await applyMigrations(migrator);
  } catch (err) {
    console.error("PostgreSQL: миграции ядра не применены — отказ запуска (РП30 п. 5)", err);
    process.exit(1);
  } finally {
    await migrator.end();
  }
}
const pool = databaseUrl ? new pg.Pool(paoPoolConfig(databaseUrl)) : undefined;
// Сбой соединения в простое — в журнал, а не падение процесса; обращения получат 503 через сбой хранилища.
pool?.on("error", (err) => console.error("PostgreSQL: сбой соединения пула", err));
const nonces = paoNonceStore({ client: pool, skewSec: params.signature_skew_sec });

// Реестр в памяти до PostgreSQL (PS-06); допуск операторов по HTTP — после их аутентификации (SEC-1, расхождение №9).
const store = new InMemoryAgentRegistryStore();
const registry = new AgentRegistry(store, { keys: params });
const keys = new AgentKeys(store, { keys: params });
const verifier = new PaoRequestVerifier(
  { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
  { skewSec: params.signature_skew_sec, nonces },
);

const app = buildServer({ env, logger: true, pao: { verifier, keys, params } });
app.log.info({ params }, "стендовые параметры загружены");
if (!pool) app.log.warn("DATABASE_URL не задан (dev): nonce в памяти — один процесс, повтор после перезапуска не ловится");
const stopPurge = startNoncePurge(nonces, params.signature_skew_sec * 1000, (err) =>
  app.log.error({ err }, "ПАО: сбой очистки nonce"),
);
app.addHook("onClose", async () => {
  await stopPurge();
  await pool?.end();
});
// Штатная остановка: сервер, очистка nonce и пул закрываются вместе (РП30 п. 4).
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}

try {
  await app.listen({ port, host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
