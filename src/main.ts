import pg from "pg";
import { X509Certificate } from "node:crypto";
import {
  buildServer,
  parseEnv,
  parseTlsHostnames,
  parseTrustedProxies,
  PROXIES_REASONS,
  ProxiesError,
  type PlatformEnv,
  type ServerTls,
} from "./server.js";
import { ConsentJournal, MemoryConsentStore, PgConsentStore } from "./consent/index.js";
import { MemoryLimitsStore, PgLimitsStore } from "./participants/limits.js";
import { MemoryReadinessStore, PgReadinessStore } from "./participants/readiness.js";
import { OperationOutcomeCollector, PgOutcomeStore, startOutcomeCollector } from "./fulfilment/outcomes.js";
import { ParticipantNotifier, PgParticipantNotificationStore, startParticipantNotifier } from "./participants/notifications.js";
import { WebhookDeliverer } from "./participants/webhook.js";
import { loadTrustedParticipants, type TrustedParticipants } from "./participants/trusted.js";
import { ParticipantRequestVerifier } from "./participants/verify.js";
import { EventDeliverer, httpsTransport, startEventDelivery } from "./pao/delivery.js";
import { pushForRegistry } from "./pao/events.js";
import { paoIdempotency } from "./pao/idempotency.js";
import { paoNonceStore, paoPoolConfig, requireDatabaseUrl, startNoncePurge } from "./pao/stores.js";
import { systemResolver } from "./pao/subscription.js";
import { PaoRequestVerifier } from "./pao/verify.js";
import {
  AgentKeys,
  AgentRegistry,
  CA_KEY_REASONS,
  InMemoryAgentRegistryStore,
  loadCaFile,
  PgAgentRegistryStore,
  type AgentRegistryStore,
  type CsrRejection,
  type SandboxCa,
} from "./registry/index.js";
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
/** УЦ песочницы из PLATFORM_CA_KEY_PATH — только sandbox (РП66 п. 6): TLS, ступень 0 и выпуск сертификатов при допуске. */
let ca: SandboxCa | undefined;
/** Имена и адреса сертификата сервера из PLATFORM_TLS_HOSTNAMES — только sandbox (РП66 п. 4). */
let tlsHostnames: string[] | undefined;
/** Сертификат сервера (РП66 п. 4) — выпускается проверкой ca.key: сбой выпуска — отказ запуска с кодом (КТ1 К3.1 № 4). */
let serverCert: ReturnType<SandboxCa["issueServerCertificate"]> | undefined;

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
      // Имена сертификата сервера (РП66 п. 4) — настройка развёртывания, как PORT и HOST; dev без TLS их не читает (п. 7).
      if (env === "sandbox") tlsHostnames = parseTlsHostnames(process.env.PLATFORM_TLS_HOSTNAMES);
      return "ok";
    },
  },
  {
    // Доверенные прокси (РП32 п. 5): неверный список — отказ запуска. sandbox всегда с TLS в процессе (без файла УЦ не
    // запускается — РП66 п. 6): прокси перед ним только L4, X-Forwarded-For — от клиента, и непустой список дал бы агенту
    // обойти грубый лимит подстановкой адреса — отказ запуска (РП67 п. 1). dev — без изменений (п. 3); любая другая
    // среда — запрет по умолчанию (п. 7).
    check: "proxies",
    fail: "STARTUP_PROXIES_INVALID",
    reasons: PROXIES_REASONS,
    run: () => {
      trustedProxies = parseTrustedProxies(process.env.PAO_TRUSTED_PROXIES);
      if (env !== "dev" && trustedProxies.length > 0) {
        throw new ProxiesError("TLS_IN_PROCESS", "PAO_TRUSTED_PROXIES вне dev: TLS в процессе, прокси только L4 (РП67 п. 1, 7)");
      }
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
    // Ключ УЦ песочницы (РП66 п. 6): только sandbox; файл создаёт только npm run ca:init — здесь лишь чтение. dev файл не
    // читает (п. 7). Вид причины — в журнал отказа из закрытого перечня, текста исключения нет (РП42 доп. п. 12).
    // Сертификат сервера (РП66 п. 4) — здесь же, до отчёта: сбой выпуска — STARTUP_CA_KEY_INVALID с классом ошибки, без
    // вида причины (КТ1 К3.1 № 4). Ключ — только в памяти, новый при каждом запуске; срок — agent_cert_ttl_days от запуска
    // (продление — перезапуском). Возобновления сессии нет (К2.2). Имён нет — проверка params уже отказала (неверные
    // PORT, параметры или PLATFORM_TLS_HOSTNAMES): файл УЦ проверен, выпуск — skip, а не второй отказ с кодом ключа УЦ,
    // который вёл бы оператора к ca:init (КТ1 сессии 57 № 1; РП66 «Нюансы хвостов» п. 2).
    check: "ca.key",
    fail: "STARTUP_CA_KEY_INVALID",
    reasons: CA_KEY_REASONS,
    run: () => {
      if (env !== "sandbox") return "skip";
      ca = loadCaFile(process.env.PLATFORM_CA_KEY_PATH, new Date());
      if (tlsHostnames === undefined) return "skip";
      serverCert = ca.issueServerCertificate(tlsHostnames, new Date(), params.agent_cert_ttl_days, params.cert_not_before_backdate_sec);
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

  // Реестр агентов (РП64 п. 7, PS-05в ч. 2б-2): с DATABASE_URL — только PostgreSQL (sql/120, кэша нет — п. 3), без — память
  // (dev, один процесс; переноса данных нет). Допуск операторов по HTTP — после их аутентификации (SEC-1, расхождение №9).
  // Служба приостановления и хранилища П5 / П6 на PG сюда не подключаются до РП64 п. 6 (ч. 3) — страж main-wiring-guard.
  const store: AgentRegistryStore = pool ? new PgAgentRegistryStore(pool) : new InMemoryAgentRegistryStore();
  // sandbox (РП66 п. 3, 7): реестр выдаёт сертификат mTLS только по CSR заявления — CSR обязателен (required); вид причины
  // отказа CSR — в журнал процесса, оператору — KEY_INVALID (РП65 нюанс 9). dev — без УЦ: сертификаты не выдаются.
  const registry = new AgentRegistry(store, {
    keys: params,
    ...(ca
      ? {
          certificates: {
            ca,
            ttlDays: params.agent_cert_ttl_days,
            backdateSec: params.cert_not_before_backdate_sec,
            required: true,
            // app — только после buildServer (ниже); admit до него не вызывать: обращение к app здесь — ReferenceError.
            onRejected: (reason: CsrRejection) => app.log.info({ reason }, "П1: CSR заявления отклонён — KEY_INVALID"),
          },
        }
      : {}),
  });
  const keys = new AgentKeys(store, { keys: params });
  // Ступень 0 (РП66 п. 1): только sandbox, вместе с TLS (нюанс К3 п. 1); запись сертификата — из реестра на PG на каждом
  // обращении (РП64 п. 3); отметка предпроверки не старше revocation_propagation_max_ms (нюанс К3 п. 4–5).
  const verifier = new PaoRequestVerifier(
    { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
    {
      skewSec: params.signature_skew_sec,
      nonces,
      ...(ca
        ? {
            mtls: {
              ca: new X509Certificate(ca.certificateDer),
              getCertificate: (serial: string) => registry.getCertificate(serial),
              ticketMaxAgeMs: params.revocation_propagation_max_ms,
            },
          }
        : {}),
    },
  );
  // Сертификат сервера выпущен проверкой ca.key (РП66 п. 4, КТ1 К3.1 № 4).
  const tls: ServerTls | undefined =
    ca && serverCert ? { key: serverCert.privateKey, certificateDer: serverCert.certificateDer, caDer: ca.certificateDer } : undefined;
  // sandbox — только с TLS (РП66 п. 3, КТ1 К3.1 № 5): самопроверка без УЦ его не пропускает, а здесь — явно, до buildServer.
  if (env === "sandbox" && !tls) throw new Error("sandbox без TLS — запуск запрещён (РП66 п. 3)");

  // Журнал согласий (П2): PostgreSQL при DATABASE_URL, иначе (dev) — память ядра. Порядок отзыва — из записи участника (РП37).
  // Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6); agent.suspended — и
  // приостановленному (РП54 п. 9). Служба приостановления (AgentStatusService) подключается к HTTP оператора в PS-32.
  const consentStore = pool ? new PgConsentStore(pool) : new MemoryConsentStore();
  const consent: ConsentJournal = new ConsentJournal(consentStore, {
    revocationOrder: () => trusted.revocationOrder(),
    pushFor: pushForRegistry(registry),
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

  // Уведомитель участников (РП46 доп. п. 7) — только с PostgreSQL: записи операций ADP рабочего сервера в базе.
  // Состояние — в /health (ревью КТ1): остановившийся уведомитель виден мониторингу без журнала.
  const notifyStore = pool ? new PgParticipantNotificationStore(pool) : undefined;
  const notifier = notifyStore
    ? new ParticipantNotifier(notifyStore, {
        horizonSec: params.participant_notify_horizon_sec,
        log: (level, fields, msg) => app.log[level](fields, msg),
      })
    : undefined;

  // Сборщик итогов операций (РП52 п. 1 (а)) — так же только с PostgreSQL; события — в ленту журнала той же базы.
  const outcomes = pool
    ? new OperationOutcomeCollector(new PgOutcomeStore(pool), {
        horizonSec: params.operation_outcome_horizon_sec,
        maxDelaySec: params.operation_outcome_max_delay_sec,
        pushFor: pushForRegistry(registry),
        log: (level, fields, msg) => app.log[level](fields, msg),
      })
    : undefined;

  // Знак готовности продавца (РП57 п. 2–3): записи эквайрера и оператора — PostgreSQL при DATABASE_URL, иначе (dev) память.
  // Одно хранилище для ПИ-8 эквайрера, API продавцов и ПАО. Действие оператора по HTTP — с кабинетом оператора (PS-31).
  const readiness = pool ? new PgReadinessStore(pool) : new MemoryReadinessStore();

  const app = buildServer({
    env,
    logger: true,
    // TLS и ступень 0 — только вместе (РП66 нюанс К3 п. 1): buildServer отказывает при несогласованности.
    ...(tls ? { tls } : {}),
    ...(notifier ? { notifier } : {}),
    ...(outcomes ? { outcomes } : {}),
    trustedProxies,
    // Подписка — в записи агента (РП40 п. 1); разрешение имени — системное (стендового порта здесь нет, РП40 п. 8).
    pao: { verifier, keys, idempotency, params, consent, subscriptions: { set: registry.subscribe.bind(registry) }, readiness },
    // Обнаружение ПАО (РП60 п. 9–13): контур ключей sandbox, как у API продавцов.
    paoConfiguration: { contour: "sandbox", params },
    // Подпись запроса участника (РП46 (в)): nonce — в хранилище ПАО с приставкой participant: (одна очистка).
    participants: {
      trusted,
      consent,
      params,
      state,
      limits: pool ? new PgLimitsStore(pool) : new MemoryLimitsStore(),
      requests: new ParticipantRequestVerifier(trusted, { skewSec: params.signature_skew_sec, nonces }),
      // Лента уведомлений клиента (РП46 (б) п. 3) — из Outbox участника в базе; без базы уведомлений нет.
      ...(notifyStore ? { notifications: notifyStore } : {}),
      // Знак готовности от эквайрера (РП57 п. 2); допуск часов issued_at — окно подписи.
      readiness: { store: readiness, skewSec: params.signature_skew_sec },
      // Статус агента для эквайрера (РП57 п. 6) — тот же реестр и контур, что у API продавцов. Метаданные пакета и сверка
      // (п. 5) не подключены: сверка идёт по записи реквизита П5, а П5 в рабочем сервере нет (токен-сервис оператора, ПИ-4).
      agentStatus: { registry, contour: "sandbox" },
    },
    // API для продавцов (РП56, РП57 п. 3): среды dev и sandbox — контур ключей sandbox; контура оператора у сервера нет до PS-31.
    merchants: { registry, keys, contour: "sandbox", params, readiness },
  });
  app.log.info({ params }, "стендовые параметры загружены");
  // Отпечаток корневого УЦ — открытый, тот же, что вывел ca:init: оператор сверяет, что смонтирован прежний УЦ (РП66 п. 6).
  // Срок сертификата сервера — продления без перезапуска нет (КТ1 К3.1 № 1, «Открыто»): по нему оператор планирует перезапуск.
  if (ca) {
    app.log.info(
      {
        ca_fingerprint: ca.fingerprint,
        ca_not_after: ca.notAfter.toISOString(),
        tls_hostnames: tlsHostnames,
        server_cert_not_after: serverCert?.notAfter.toISOString(),
      },
      "УЦ песочницы загружен",
    );
  }
  if (!pool) app.log.warn("DATABASE_URL не задан (dev): реестр агентов, nonce, идемпотентность, журнал согласий, удержания П3 и лимиты клиента в памяти — один процесс, повтор после перезапуска не ловится");
  const stopPurge = startNoncePurge(nonces, params.signature_skew_sec * 1000, (err) =>
    app.log.error({ err }, "ПАО: сбой очистки nonce"),
  );
  const stopDelivery = startEventDelivery(deliverer, EVENT_DELIVERY_EVERY_MS, (err) =>
    app.log.error({ err }, "ПАО: сбой прохода доставки событий"),
  );
  const stopExpiry = startReservationExpiry(state, RESERVATION_EXPIRE_EVERY_MS);
  // Проход уведомителя раз в секунду — не реже participant_notify_max_delay_sec (≥ 1 с).
  const stopNotify = notifier
    ? startParticipantNotifier(notifier, PARTICIPANT_NOTIFY_EVERY_MS, (err) => app.log.error({ err }, "П10: сбой прохода уведомителя"))
    : async () => {};
  // Проход сборщика итогов — раз в operation_outcome_every_ms (< operation_outcome_max_delay_sec, граница загрузчика).
  const stopOutcomes = outcomes
    ? startOutcomeCollector(outcomes, params.operation_outcome_every_ms, (err) => app.log.error({ err }, "П8: сбой прохода сборщика итогов"))
    : async () => {};
  // Вебхук-сигнал банкам (РП46 (б) п. 3): адрес — из записи доверенного участника, проверка — как push агенту (РП40).
  const stopWebhook = notifyStore
    ? startEventDelivery(
        new WebhookDeliverer({
          store: notifyStore,
          notifyUrl: (code) => trusted.notifyUrl(code),
          resolveHost: systemResolver,
          transport: httpsTransport,
          params,
          log: (level, fields, msg) => app.log[level](fields, msg),
        }),
        EVENT_DELIVERY_EVERY_MS,
        (err) => app.log.error({ err }, "П10: сбой прохода вебхука"),
      )
    : async () => {};
  app.addHook("onClose", async () => {
    await stopPurge();
    await stopDelivery();
    await stopExpiry();
    await stopNotify();
    await stopOutcomes();
    await stopWebhook();
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
