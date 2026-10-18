import pg from "pg";
import { buildServer, parseEnv, parseTrustedProxies } from "./server.js";
import { ConsentJournal, MemoryConsentStore, PgConsentStore } from "./consent/index.js";
import { loadTrustedParticipants } from "./participants/trusted.js";
import { EventDeliverer, httpsTransport, startEventDelivery } from "./pao/delivery.js";
import { paoIdempotency } from "./pao/idempotency.js";
import { paoNonceStore, paoPoolConfig, requireDatabaseUrl, startNoncePurge } from "./pao/stores.js";
import { systemResolver } from "./pao/subscription.js";
import { PaoRequestVerifier } from "./pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "./registry/index.js";
import { loadParams } from "./shared/config.js";
import { applyPlatformMigrations } from "./shared/migrations.js";

const env = parseEnv(process.env.PLATFORM_ENV);
// Неверные стендовые параметры — отказ запуска (fail-closed).
const params = loadParams();
const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Недопустимый PORT=${process.env.PORT}`);
}
const host = process.env.HOST ?? "127.0.0.1";
// Доверенные прокси (РП32 п. 5): неверный список — отказ запуска.
const trustedProxies = parseTrustedProxies(process.env.PAO_TRUSTED_PROXIES);

// Хранилища шлюза ПАО (РП30 п. 4–6): sandbox без DATABASE_URL не запускается; dev без базы — память ядра, один процесс.
// Миграции ядра 001–004 и Платформы (100_consent, PS-06) — при запуске одним экземпляром, отдельным пулом без таймаута запроса; сбой — отказ запуска.
// Рабочий пул — с таймаутами соединения и запроса: зависшая база — 503, а не вечное ожидание (инвариант 3).
const databaseUrl = requireDatabaseUrl(env, process.env.DATABASE_URL);
if (databaseUrl) {
  const migrator = new pg.Pool({ connectionString: databaseUrl, max: 1 });
  migrator.on("error", (err) => console.error("PostgreSQL (миграции): сбой соединения пула", err));
  try {
    await applyPlatformMigrations(migrator);
  } catch (err) {
    console.error("PostgreSQL: миграции не применены — отказ запуска (РП30 п. 5)", err);
    process.exit(1);
  } finally {
    await migrator.end();
  }
}
const pool = databaseUrl ? new pg.Pool(paoPoolConfig(databaseUrl)) : undefined;
// Сбой соединения в простое — в журнал, а не падение процесса; обращения получат 503 через сбой хранилища.
pool?.on("error", (err) => console.error("PostgreSQL: сбой соединения пула", err));
const nonces = paoNonceStore({ client: pool, skewSec: params.signature_skew_sec });
const idempotency = paoIdempotency({ client: pool, ttlSec: params.idempotency_ttl_sec });

// Реестр в памяти до PostgreSQL (PS-06); допуск операторов по HTTP — после их аутентификации (SEC-1, расхождение №9).
const store = new InMemoryAgentRegistryStore();
const registry = new AgentRegistry(store, { keys: params });
const keys = new AgentKeys(store, { keys: params });
const verifier = new PaoRequestVerifier(
  { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
  { skewSec: params.signature_skew_sec, nonces },
);

// Доверенные ключи участников до PS-20 (РП36 п. 4): ключ эмулятора стенда и второй боевой участник — отказ запуска.
const trusted = loadTrustedParticipants(process.env.PARTICIPANT_KEYS_PATH, { stand: false });

// Журнал согласий (П2): PostgreSQL при DATABASE_URL, иначе (dev) — память ядра. Порядок отзыва — из записи участника (РП37).
// Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6).
const consentStore = pool ? new PgConsentStore(pool) : new MemoryConsentStore();
const consent = new ConsentJournal(consentStore, {
  revocationOrder: () => trusted.revocationOrder(),
  pushFor: (code, type) => registry.get(code)?.status === "ACTIVE" && (registry.subscription(code)?.events.includes(type) ?? false),
});

/** Проход доставки событий раз в секунду: меньше первой задержки повтора ядра (1 с). */
const EVENT_DELIVERY_EVERY_MS = 1000;

// Push-доставка с повтором (РП40 п. 4–5): системное разрешение имени и HTTPS с проверенным IP; стендовых портов нет.
const deliverer = new EventDeliverer({
  store: consentStore,
  agent: (c) => registry.get(c),
  subscription: (c) => registry.subscription(c),
  resolveHost: systemResolver,
  transport: httpsTransport,
  params,
  log: (level, fields, msg) => app.log[level](fields, msg),
});

const app = buildServer({
  env,
  logger: true,
  trustedProxies,
  // Подписка — в записи агента (РП40 п. 1); разрешение имени — системное (стендового порта здесь нет, РП40 п. 8).
  pao: { verifier, keys, idempotency, params, consent, subscriptions: { set: registry.subscribe.bind(registry) } },
  participants: { trusted, consent, params },
});
app.log.info({ params }, "стендовые параметры загружены");
if (!pool) app.log.warn("DATABASE_URL не задан (dev): nonce, идемпотентность и журнал согласий в памяти — один процесс, повтор после перезапуска не ловится");
const stopPurge = startNoncePurge(nonces, params.signature_skew_sec * 1000, (err) =>
  app.log.error({ err }, "ПАО: сбой очистки nonce"),
);
const stopDelivery = startEventDelivery(deliverer, EVENT_DELIVERY_EVERY_MS, (err) =>
  app.log.error({ err }, "ПАО: сбой прохода доставки событий"),
);
app.addHook("onClose", async () => {
  await stopPurge();
  await stopDelivery();
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
