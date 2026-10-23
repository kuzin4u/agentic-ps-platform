import { isIP } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { adpRoutes, type AdpDeps } from "./adp/routes.js";
import type { CollectorHealth } from "./fulfilment/outcomes.js";
import type { NotifierHealth } from "./participants/notifications.js";
import { merchantApiRoutes, merchantApiUnavailable, type MerchantApiDeps } from "./participants/merchant-api.js";
import { participantRoutes, type ParticipantDeps } from "./participants/routes.js";
import { paoRoutes, type PaoDeps } from "./pao/routes.js";

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
  logger?: boolean;
  /** Шлюз ПАО (П9); без него маршрутов /pao нет. */
  pao?: PaoDeps;
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
}

export interface BypassOnly {
  /** Непрошедшие проверки самопроверки — только имя и код реестра PLATFORM_DIAG, без текста исключений (РП42 доп. п. 12). */
  readonly failures: readonly { readonly check: string; readonly code: string }[];
  /** Запись «тревога» в журнал процесса; по умолчанию — журнал Fastify уровня fatal. */
  readonly alarm?: (fields: Record<string, unknown>, msg: string) => void;
}

/** Минимальная длина префикса доверенного прокси (РП32, дополнение п. 2); шире — отдельным решением. */
export const TRUSTED_PROXY_MIN_PREFIX = Object.freeze({ v4: 16, v6: 32 });

/**
 * PAO_TRUSTED_PROXIES — адреса и CIDR через запятую (РП32 п. 5). Пусто или нет — прокси не доверяем.
 * «true» («доверять всем») и всё, что не адрес и не CIDR, — отказ запуска: агент обошёл бы лимит подстановкой заголовка.
 * Префикс — не шире IPv4 /16 и IPv6 /32 (РП32, дополнение п. 2): иначе список из широких сетей — тот же «доверять всем».
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
      throw new Error(
        `PAO_TRUSTED_PROXIES: «${item}» — не адрес и не CIDR или префикс шире IPv4 /16, IPv6 /32; доверять всем нельзя (РП32 п. 5)`,
      );
    }
  }
  return items;
}

export function buildServer(opts: ServerOptions): FastifyInstance {
  const proxies = opts.trustedProxies ?? [];
  const app = Fastify({ logger: opts.logger ?? false, trustProxy: proxies.length > 0 ? [...proxies] : false });

  const bypass = opts.bypassOnly;
  if (bypass) {
    const failures = bypass.failures.map(({ check, code }) => ({ check, code }));
    // 200, а не 503: оркестратор не перезапускает процесс, и неагентские не теряют BYPASS (решение владельца, РП43 п. 8).
    app.get("/health", async () => ({ status: "ok", env: opts.env, mode: "bypass_only", failures }));
    void app.register(async (scope) => adpRoutes(scope, {}));
    // API для продавцов — 503, а не 404 (уточнение РП56 по № 42): каталог и статус без самопроверки не отдаются.
    void app.register(merchantApiUnavailable);
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
