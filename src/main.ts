import pg from "pg";
import { buildServer, parseEnv, parseTrustedProxies, type PlatformEnv } from "./server.js";
import { ConsentJournal, MemoryConsentStore, PgConsentStore } from "./consent/index.js";
import { MemoryLimitsStore, PgLimitsStore } from "./participants/limits.js";
import { ParticipantNotifier, PgParticipantNotificationStore, startParticipantNotifier } from "./participants/notifications.js";
import { loadTrustedParticipants, type TrustedParticipants } from "./participants/trusted.js";
import { ParticipantRequestVerifier } from "./participants/verify.js";
import { EventDeliverer, httpsTransport, startEventDelivery } from "./pao/delivery.js";
import { paoIdempotency } from "./pao/idempotency.js";
import { paoNonceStore, paoPoolConfig, requireDatabaseUrl, startNoncePurge } from "./pao/stores.js";
import { systemResolver } from "./pao/subscription.js";
import { PaoRequestVerifier } from "./pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "./registry/index.js";
import { loadParams, type Params } from "./shared/config.js";
import { applyPlatformMigrations } from "./shared/migrations.js";
import {
  diagRegistryProblems,
  paoSpecMatches,
  platformVersion,
  startPlatform,
  type StartupCheck,
  type StartupLog,
} from "./shared/selfcheck.js";
import { holdLedger, RESERVATION_EXPIRE_EVERY_MS, startReservationExpiry, StateService } from "./state/index.js";

// Самопроверка при старте (РП42 п. 4): каждый отказ запуска — проверка с кодом STARTUP_*, отчёт — до listen.
// Значения, которые проверки разбирают, нужны serve(); при ready: false serve() не вызывается.
let env: PlatformEnv | undefined;
let params: Params;
let port: number;
let host: string;
let trustedProxies: string[];
let databaseUrl: string | undefined;
let trusted: TrustedParticipants;

const checks: StartupCheck[] = [
  {
    // Среда, стендовые параметры, адрес и порт — отказ запуска при неверных (fail-closed).
    check: "params",
    fail: "STARTUP_PARAMS_INVALID",
    run: () => {
      env = parseEnv(process.env.PLATFORM_ENV);
      params = loadParams();
      port = Number(process.env.PORT ?? 8080);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Недопустимый PORT=${process.env.PORT}`);
      host = process.env.HOST ?? "127.0.0.1";
      return "ok";
    },
  },
  {
    // Доверенные прокси (РП32 п. 5): неверный список — отказ запуска.
    check: "proxies",
    fail: "STARTUP_PROXIES_INVALID",
    run: () => {
      trustedProxies = parseTrustedProxies(process.env.PAO_TRUSTED_PROXIES);
      return "ok";
    },
  },
  {
    // Хранилища шлюза ПАО (РП30 п. 4–6): sandbox без DATABASE_URL не запускается; dev без базы — память ядра, один процесс.
    check: "db.storage",
    fail: "STARTUP_DB_REQUIRED",
    run: () => {
      if (env === undefined) return "skip";
      databaseUrl = requireDatabaseUrl(env, process.env.DATABASE_URL);
      return databaseUrl ? "ok" : { warn: "STARTUP_DB_MEMORY" };
    },
  },
  {
    // Миграции ядра 001–004 и Платформы — при запуске одним экземпляром, отдельным пулом без таймаута запроса (РП30 п. 5).
    check: "db.migrations",
    fail: "STARTUP_DB_MIGRATIONS",
    run: async () => {
      if (!databaseUrl) return "skip";
      const migrator = new pg.Pool({ connectionString: databaseUrl, max: 1 });
      migrator.on("error", (err) => console.error("PostgreSQL (миграции): сбой соединения пула", err));
      try {
        await applyPlatformMigrations(migrator);
      } finally {
        await migrator.end();
      }
      return "ok";
    },
  },
  {
    // Отставание уведомителя участников (РП46 доп. п. 9 (о2)): признак, готовность не снимает; без базы — уведомителя нет.
    check: "participants.notify",
    fail: "STARTUP_DB_MIGRATIONS",
    run: async () => {
      if (!databaseUrl) return "skip";
      const probe = new pg.Pool({ connectionString: databaseUrl, max: 1 });
      probe.on("error", (err) => console.error("PostgreSQL (уведомитель): сбой соединения пула", err));
      try {
        const notifier = new ParticipantNotifier(new PgParticipantNotificationStore(probe), { horizonSec: params.participant_notify_horizon_sec });
        return (await notifier.lagging()) ? { warn: "PARTICIPANT_NOTIFY_LAGGING" } : "ok";
      } finally {
        await probe.end();
      }
    },
  },
  {
    // Доверенные ключи участников до PS-20 (РП36 п. 4): ключ эмулятора стенда и второй боевой участник — отказ запуска.
    check: "participants",
    fail: "STARTUP_PARTICIPANTS_INVALID",
    run: () => {
      trusted = loadTrustedParticipants(process.env.PARTICIPANT_KEYS_PATH, { stand: false });
      return "ok";
    },
  },
  {
    check: "pao.spec",
    fail: "STARTUP_PAO_SPEC_MISMATCH",
    run: () => {
      if (!paoSpecMatches()) throw new Error("копия ПАО agentic-core (версия или sha-256) не равна Платформе");
      return "ok";
    },
  },
  {
    check: "diag.registry",
    fail: "STARTUP_DIAG_INCOMPLETE",
    run: () => {
      const problems = diagRegistryProblems();
      if (problems.length > 0) throw new Error(problems.map((p) => `${p.code}: ${p.entry}${p.field ? ` (${p.field})` : ""}`).join("; "));
      return "ok";
    },
  },
];

// До buildServer журнала Fastify нет: отчёт — одной строкой JSON в stdout или stderr.
const log: StartupLog = (level, fields, msg) =>
  (level === "error" ? console.error : console.log)(JSON.stringify({ level, time: new Date().toISOString(), msg, ...fields }));

async function serve(): Promise<void> {
  // serve() вызывается только при готовности: params прошла, среда известна.
  if (env === undefined) throw new Error("среда не определена самопроверкой");
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

  // Журнал согласий (П2): PostgreSQL при DATABASE_URL, иначе (dev) — память ядра. Порядок отзыва — из записи участника (РП37).
  // Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6).
  const consentStore = pool ? new PgConsentStore(pool) : new MemoryConsentStore();
  const consent: ConsentJournal = new ConsentJournal(consentStore, {
    revocationOrder: () => trusted.revocationOrder(),
    pushFor: (code, type) => registry.get(code)?.status === "ACTIVE" && (registry.subscription(code)?.events.includes(type) ?? false),
    // Остаток для verify — из П3 (РП41 п. 10); state объявлен ниже, вызов — только при обращении.
    amountLeft: (id, limit) => state.amountLeft(id, limit),
  });

  // Бюджет мандата (П3, РП41): удержания ядра — PostgreSQL при DATABASE_URL, иначе (dev) память ядра; источник — журнал согласий.
  const state: StateService = new StateService(holdLedger(pool), consent, {
    reservationTtlSec: params.reservation_ttl_sec,
    log: (level, fields, msg) => app.log[level](fields, msg),
    exhausted: (id, payload) => consent.exhausted(id, payload),
  });

  /** Проход доставки событий раз в секунду: меньше первой задержки повтора ядра (1 с). */
  const EVENT_DELIVERY_EVERY_MS = 1000;
  /** Проход уведомителя участников: не реже наименьшего participant_notify_max_delay_sec (1 с). */
  const PARTICIPANT_NOTIFY_EVERY_MS = 1000;

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
    // Подпись запроса участника (РП46 (в)): nonce — в хранилище ПАО с приставкой participant: (одна очистка).
    participants: {
      trusted,
      consent,
      params,
      state,
      limits: pool ? new PgLimitsStore(pool) : new MemoryLimitsStore(),
      requests: new ParticipantRequestVerifier(trusted, { skewSec: params.signature_skew_sec, nonces }),
    },
  });
  app.log.info({ params }, "стендовые параметры загружены");
  if (!pool) app.log.warn("DATABASE_URL не задан (dev): nonce, идемпотентность, журнал согласий, удержания П3 и лимиты клиента в памяти — один процесс, повтор после перезапуска не ловится");
  const stopPurge = startNoncePurge(nonces, params.signature_skew_sec * 1000, (err) =>
    app.log.error({ err }, "ПАО: сбой очистки nonce"),
  );
  const stopDelivery = startEventDelivery(deliverer, EVENT_DELIVERY_EVERY_MS, (err) =>
    app.log.error({ err }, "ПАО: сбой прохода доставки событий"),
  );
  const stopExpiry = startReservationExpiry(state, RESERVATION_EXPIRE_EVERY_MS);
  // Уведомитель участников (РП46 доп. п. 7): раз в секунду — не реже participant_notify_max_delay_sec (≥ 1 с); только с
  // PostgreSQL — записи операций ADP рабочего сервера в базе.
  const stopNotify = pool
    ? startParticipantNotifier(
        new ParticipantNotifier(new PgParticipantNotificationStore(pool), {
          horizonSec: params.participant_notify_horizon_sec,
          log: (level, fields, msg) => app.log[level](fields, msg),
        }),
        PARTICIPANT_NOTIFY_EVERY_MS,
        (err) => app.log.error({ err }, "П10: сбой прохода уведомителя"),
      )
    : async () => {};
  app.addHook("onClose", async () => {
    await stopPurge();
    await stopDelivery();
    await stopExpiry();
    await stopNotify();
    await pool?.end();
  });
  // Штатная остановка: сервер, очистка nonce и пул закрываются вместе (РП30 п. 4).
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      void app.close().then(() => process.exit(0));
    });
  }

  await app.listen({ port, host });
}

const { exitCode } = await startPlatform(checks, { version: platformVersion(), log, listen: serve });
if (exitCode !== 0) process.exit(exitCode);
