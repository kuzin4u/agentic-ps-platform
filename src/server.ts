import { constants as cryptoConstants, X509Certificate, type KeyObject } from "node:crypto";
import type { ServerOptions as HttpsServerOptions } from "node:https";
import { isIP } from "node:net";
import Fastify, { LogController, type FastifyInstance, type FastifyRequest, type FastifyServerOptions } from "fastify";
import { adpRoutes, type AdpDeps } from "./adp/routes.js";
import type { CollectorHealth } from "./fulfilment/outcomes.js";
import type { NotifierHealth } from "./participants/notifications.js";
import {
  BYPASS_RETRY_AFTER_SEC,
  merchantApiRoutes,
  merchantApiUnavailable,
  type MerchantApiDeps,
} from "./participants/merchant-api.js";
import { participantRoutes, type ParticipantDeps } from "./participants/routes.js";
import { paoConfigurationRoutes, paoConfigurationUnavailable, type PaoConfigurationDeps } from "./pao/configuration.js";
import { paoNotFound, paoRoutes, type PaoDeps } from "./pao/routes.js";
import { frameworkErrors, paoUnavailable } from "./pao/transport.js";
import { withRequestSerializer } from "./http/request-log.js";
import { isServerName } from "./registry/ca/ca.js";

// Среды — SPEC §8, ARCHITECTURE «Среды». dev работает в памяти, без PostgreSQL.
export const ENVIRONMENTS = ["dev", "sandbox"] as const;
export type PlatformEnv = (typeof ENVIRONMENTS)[number];

export function parseEnv(value: string | undefined): PlatformEnv {
  const env = value ?? "dev";
  if (!(ENVIRONMENTS as readonly string[]).includes(env)) {
    throw new Error(`Неизвестная среда PLATFORM_ENV=${env}; допустимы: ${ENVIRONMENTS.join(", ")}`);
  }
  return env as PlatformEnv;
}

export interface ServerOptions {
  env: PlatformEnv;
  /** Журнал процесса Fastify: true — по умолчанию (main.ts), опции — поток для тестов записи (РП60 доп. 3). */
  logger?: FastifyServerOptions["logger"];
  /** Шлюз ПАО (П9); без него маршрутов /pao нет. */
  pao?: PaoDeps;
  /** Обнаружение ПАО — GET /.well-known/pao-configuration без подписи (РП60 п. 9–13); без него маршрута нет. */
  paoConfiguration?: PaoConfigurationDeps;
  /** Шлюз участников (П10, ПИ-8): подпись мандата по подписи участника (РП36); без него маршрутов /participants нет. */
  participants?: ParticipantDeps;
  /** API для продавцов и площадок (П10, РП56): каталог ключей агентов и статус агента, без подписи; без него маршрутов нет. */
  merchants?: MerchantApiDeps;
  /** Доверенные адреса прокси (РП32 п. 5); без них X-Forwarded-For не читается, ключ лимита — адрес соединения. */
  trustedProxies?: readonly string[];
  /**
   * Точка решения ADP (ПИ-1, РП43); без неё маршрута /adp нет. До SEC-1 — только стенд и тесты, main.ts её не
   * подключает (доп. РП43 п. 21): открытого порта с правом создавать резервы нет.
   */
  adp?: AdpDeps;
  /**
   * Уведомитель участников (РП46 доп. п. 7): его состояние — в /health (ревью КТ1), без обращения к базе; отставание —
   * признак с кодом PARTICIPANT_NOTIFY_LAGGING, статус ответа остаётся 200 (уведомления в решении о платеже не участвуют).
   */
  notifier?: { health(): NotifierHealth };
  /**
   * Сборщик итогов операций (РП52 п. 1 (а)): состояние — в /health так же, отставание — признак OPERATION_OUTCOME_LAGGING
   * («Дополнения» п. 2), статус ответа остаётся 200 (итог агенту отдаёт GET из записи операции).
   */
  outcomes?: { health(): CollectorHealth };
  /**
   * Режим «только BYPASS» (РП43 п. 8): самопроверка при старте не прошла. Неагентским — BYPASS, агентским — 503 без
   * решения; ПАО, П10 и точка решения не регистрируются; /health — 200 с mode и кодами непрошедших проверок; при входе
   * в режим — запись «тревога». В main.ts — вместе с маршрутом ADP (SEC-1, доп. РП43 п. 21–22).
   */
  bypassOnly?: BypassOnly;
  /**
   * TLS песочницы (РП66 п. 3): завершается процессом Платформы, сертификат клиента запрашивается, но рукопожатие без него не
   * обрывается — решение принимает ступень 0. Только вместе со ступенью 0 у шлюза ПАО (В1, решение владельца 28.10).
   */
  tls?: ServerTls;
}

export interface ServerTls {
  /** Закрытый ключ сертификата сервера — только в памяти процесса (РП66 п. 4). */
  readonly key: KeyObject;
  /** Сертификат сервера, DER — от УЦ песочницы. */
  readonly certificateDer: Buffer;
  /** Корневой сертификат УЦ песочницы, DER — единственный доверенный для сертификатов клиентов. */
  readonly caDer: Buffer;
}

/** Только TLS 1.3 (В3, решение владельца 28.10): повторного согласования нет — сертификат клиента на соединении не меняется. */
export const TLS_MIN_VERSION = "TLSv1.3";

/**
 * HTTPS-опции Fastify (РП66 п. 3): requestCert, без обрыва рукопожатия, доверенный — только УЦ песочницы. Возобновления
 * сессии нет (развилка № 8 (А), решение владельца 28.10). SSL_OP_NO_TICKET в TLS 1.3 не убирает билет совсем: OpenSSL
 * выдаёт билет с состоянием на сервере (stateful) вместо билета-блоба. Возобновления нет потому, что состояния на сервере
 * нет: кэша сессий у сервера Node нет без обработчиков newSession / resumeSession, и билет предъявить некуда (CI —
 * isSessionReused() === false). Каждое подключение — полное рукопожатие с сертификатом клиента.
 * Пересмотр — по нагрузочному тесту этапа 6 (тогда — короткий срок, не 300 с).
 */
function httpsOptions(t: ServerTls): HttpsServerOptions {
  return {
    secureOptions: cryptoConstants.SSL_OP_NO_TICKET,
    key: t.key.export({ format: "pem", type: "pkcs8" }),
    cert: new X509Certificate(t.certificateDer).toString(),
    ca: [new X509Certificate(t.caDer).toString()],
    requestCert: true,
    rejectUnauthorized: false,
    minVersion: TLS_MIN_VERSION,
  };
}

/**
 * TLS и ступень 0 — только вместе (В1, дополнение к РП66): TLS без ступени 0 принимал бы обращения по любому каналу (обход
 * нормы A2 п. 5.1), ступень 0 без TLS отвечала бы AGENT_UNKNOWN на всё. Несогласованность — отказ запуска.
 * Запасной запрет РП67 п. 6: TLS в процессе — прокси перед ним только L4, X-Forwarded-For приходит от клиента внутри TLS;
 * непустой trustedProxies дал бы агенту подставить адрес (Ш12) — отказ при любом месте вызова, не только в main.ts.
 */
function assertTlsMatchesMtls(opts: ServerOptions): void {
  const mtls = opts.pao?.verifier.mtls === true;
  if (opts.tls && opts.pao && !mtls) throw new Error("TLS без ступени 0 у шлюза ПАО — запуск запрещён (РП66, В1)");
  if (mtls && !opts.tls) throw new Error("ступень 0 без TLS — запуск запрещён (РП66, В1)");
  // Адресов списка в тексте нет: текст исключения может попасть в журнал.
  if (opts.tls && (opts.trustedProxies?.length ?? 0) > 0) throw new Error("TLS в процессе и доверенные прокси — запуск запрещён (РП67 п. 6)");
}

export interface BypassOnly {
  /** Непрошедшие проверки самопроверки — только имя и код реестра PLATFORM_DIAG, без текста исключений (РП42 доп. п. 12). */
  readonly failures: readonly { readonly check: string; readonly code: string }[];
  /** Запись «тревога» в журнал процесса; по умолчанию — журнал Fastify уровня fatal. */
  readonly alarm?: (fields: Record<string, unknown>, msg: string) => void;
}

/**
 * Транспортный предел длины параметра пути (РП57 доп. 1): по умолчанию у Fastify — 100, и merchant_id до 128 знаков
 * (processing-interface.yaml) получал бы 414 раньше обработчика и проверки обращения. Форму и длину параметра проверяет
 * обработчик (400 / 404 по ПАО §6 и ПИ-8); длиннее предела — 414 Fastify до проверки, общим правилом ПАО и ПИ.
 */
export const MAX_PATH_PARAM_LENGTH = 256;

/** Минимальная длина префикса доверенного прокси (РП32, дополнение п. 2); шире — отдельным решением. */
export const TRUSTED_PROXY_MIN_PREFIX = Object.freeze({ v4: 16, v6: 32 });

/**
 * Виды причины STARTUP_PROXIES_INVALID (РП67 п. 2) — закрытый перечень, только в журнал процесса: INVALID — список не по
 * правилу РП32 п. 5; TLS_IN_PROCESS — sandbox с непустым списком (TLS в процессе, X-Forwarded-For — от клиента).
 */
export const PROXIES_REASONS = ["INVALID", "TLS_IN_PROCESS"] as const;
export type ProxiesReason = (typeof PROXIES_REASONS)[number];

/** Отказ PAO_TRUSTED_PROXIES с видом причины; в журнал попадают только класс и вид причины (РП42 доп. п. 12). */
export class ProxiesError extends Error {
  constructor(
    readonly reason: ProxiesReason,
    message: string,
  ) {
    super(message);
    this.name = "ProxiesError";
  }
}

/**
 * PAO_TRUSTED_PROXIES — адреса и CIDR через запятую (РП32 п. 5). Пусто или нет — прокси не доверяем.
 * «true» («доверять всем») и всё, что не адрес и не CIDR, — отказ запуска: агент обошёл бы лимит подстановкой заголовка.
 * Префикс — не шире IPv4 /16 и IPv6 /32 (РП32, дополнение п. 2): иначе список из широких сетей — тот же «доверять всем».
 * Отказ — ProxiesError с видом причины INVALID (РП67 п. 2).
 */
export function parseTrustedProxies(value: string | undefined): string[] {
  const items = (value ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  for (const item of items) {
    const [addr, bits, extra] = item.split("/");
    // Зона IPv6 (fe80::1%eth0) — не адрес списка; префикс без ведущих нулей, /0 — «доверять всем».
    const v = addr?.includes("%") ? 0 : isIP(addr ?? "");
    const max = v === 6 ? 128 : 32;
    const min = v === 6 ? TRUSTED_PROXY_MIN_PREFIX.v6 : TRUSTED_PROXY_MIN_PREFIX.v4;
    const okBits = bits === undefined || (/^[1-9]\d{0,2}$/.test(bits) && Number(bits) >= min && Number(bits) <= max);
    if (v === 0 || extra !== undefined || !okBits) {
      throw new ProxiesError(
        "INVALID",
        `PAO_TRUSTED_PROXIES: «${item}» — не адрес и не CIDR или префикс шире IPv4 /16, IPv6 /32; доверять всем нельзя (РП32 п. 5)`,
      );
    }
  }
  return items;
}

/**
 * PLATFORM_TLS_HOSTNAMES — имена DNS и адреса IP сертификата сервера через запятую (РП66 п. 4; настройка развёртывания, а не
 * стендовый параметр). Нет, пусто или имя не по правилу (isServerName, в том числе последняя метка из цифр — КТ1 К3.2 № 7) —
 * отказ запуска STARTUP_PARAMS_INVALID: сертификат не на те имена клиент отверг бы, догадки нет.
 */
export function parseTlsHostnames(value: string | undefined): string[] {
  const items = (value ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  if (items.length === 0) throw new Error("PLATFORM_TLS_HOSTNAMES: не задан или пуст (РП66 п. 4)");
  for (const item of items) {
    if (!isServerName(item)) throw new Error(`PLATFORM_TLS_HOSTNAMES: «${item}» — не имя DNS в нижнем регистре и не адрес IP (РП66 п. 4)`);
  }
  return items;
}

// Журнал запросов (РП61, РП63 п. 12–13) — в `src/http/request-log.ts` (общий с экранами `src/ui/`); реэкспорт — для
// прежних импортов.
export { pathlessLogArgs, requestLogFields, withRequestSerializer } from "./http/request-log.js";

/** routeNotFound по умолчанию пишет сырой url строкой мимо сериализатора (РП61 п. 2); остальные записи — родительские. */
class PathlessLogController extends LogController {
  override routeNotFound(request: FastifyRequest): void {
    if (this.isLogDisabled(request)) return;
    request.log.info({ req: request }, "маршрут не найден");
  }
}

export function buildServer(opts: ServerOptions): FastifyInstance {
  assertTlsMatchesMtls(opts);
  const proxies = opts.trustedProxies ?? [];
  const common = {
    logger: withRequestSerializer(opts.logger),
    // Экземпляр берётся как есть: опции сервера disableRequestLogging и requestIdLogLabel он не наследует — задавать здесь.
    logController: new PathlessLogController(),
    trustProxy: proxies.length > 0 ? [...proxies] : false,
    routerOptions: { maxParamLength: MAX_PATH_PARAM_LENGTH },
    // 414 и 400 bad url — до маршрутизации, одним обработчиком на сервер: тело без пути и запись отказа (РП62 п. 1, 3, 5).
    frameworkErrors: frameworkErrors(opts.pao?.params.unavailable_retry_after_sec ?? BYPASS_RETRY_AFTER_SEC),
    // satisfies — опечатку в имени опции ловит tsc: через spread лишние свойства не проверяются (КТ1 сессии 57 № 3).
  } satisfies FastifyServerOptions;
  // С TLS — перегрузка Fastify для https.Server: опции https проверяет тип Fastify (КТ1 К3.2 № 10). FastifyInstance с
  // https.Server совместим с возвращаемым FastifyInstance по API маршрутов — приведения нет.
  const app: FastifyInstance = opts.tls ? Fastify({ ...common, https: httpsOptions(opts.tls) }) : Fastify(common);

  const bypass = opts.bypassOnly;
  if (bypass) {
    const failures = bypass.failures.map(({ check, code }) => ({ check, code }));
    // 200, а не 503: оркестратор не перезапускает процесс, и неагентские не теряют BYPASS (решение владельца, РП43 п. 8).
    app.get("/health", async () => ({ status: "ok", env: opts.env, mode: "bypass_only", failures }));
    void app.register(async (scope) => adpRoutes(scope, {}));
    // API для продавцов — 503, а не 404 (уточнение РП56 по № 42): каталог и статус без самопроверки не отдаются.
    void app.register(merchantApiUnavailable);
    // Обнаружение ПАО — 503 по ПАО §6 (РП60 п. 12): шлюза нет, агент отличает недоступность от отсутствия метода.
    void app.register(async (scope) => paoConfigurationUnavailable(scope, BYPASS_RETRY_AFTER_SEC));
    // Шлюз ПАО — 503 по §6 на любой путь /pao, а не 404 Fastify с путём в теле (РП62, дополнение к п. 1; КТ1 № 2).
    void app.register(async (scope) => paoUnavailable(scope, BYPASS_RETRY_AFTER_SEC), { prefix: "/pao" });
    const alarm = bypass.alarm ?? ((fields, msg) => app.log.fatal(fields, msg));
    alarm({ alarm: true, mode: "bypass_only", failures }, "Платформа: самопроверка не прошла — режим «только BYPASS», агентские операции не принимаются");
    return app;
  }

  // Живость процесса; к базе не обращается. Уведомитель — по последнему проходу этого процесса.
  const notifier = opts.notifier;
  const outcomes = opts.outcomes;
  app.get("/health", async () => ({
    status: "ok",
    env: opts.env,
    ...(notifier ? { participant_notify: notifier.health() } : {}),
    ...(outcomes ? { operation_outcome: outcomes.health() } : {}),
  }));

  // Проверка обращения — в отдельном контексте: /health её не проходит.
  const pao = opts.pao;
  if (pao) void app.register(async (scope) => paoRoutes(scope, pao));
  // Нет маршрута в /pao — 404 по ПАО §6 под грубым лимитом (РП62 п. 1); обработчик «не найдено» действует по префиксу.
  if (pao) void app.register(async (scope) => paoNotFound(scope, pao), { prefix: "/pao" });
  // Обнаружение ПАО — своим контекстом: без подписи, проверка обращения к нему не относится (РП60 п. 11).
  const configuration = opts.paoConfiguration;
  if (configuration) void app.register(async (scope) => paoConfigurationRoutes(scope, configuration));
  // Шлюз участников — своим контекстом: проверка обращения ПАО к нему не относится, подпись — в теле (РП36 п. 4).
  const participants = opts.participants;
  if (participants) void app.register(async (scope) => participantRoutes(scope, participants));
  // API для продавцов — своим контекстом: без подписи, проверки ПАО и ПИ-8 к нему не относятся (РП56).
  const merchants = opts.merchants;
  if (merchants) void app.register(async (scope) => merchantApiRoutes(scope, merchants));
  // ADP — своим контекстом: обращение процессинга, не агента; проверки ПАО к нему не относятся.
  const adp = opts.adp;
  if (adp) void app.register(async (scope) => adpRoutes(scope, adp));

  return app;
}
