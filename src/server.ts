import { isIP } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { adpRoutes, type AdpDeps } from "./adp/routes.js";
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
  /** Доверенные адреса прокси (РП32 п. 5); без них X-Forwarded-For не читается, ключ лимита — адрес соединения. */
  trustedProxies?: readonly string[];
  /**
   * Точка решения ADP (ПИ-1, РП43); без неё маршрута /adp нет. До SEC-1 — только стенд и тесты, main.ts её не
   * подключает (доп. РП43 п. 21): открытого порта с правом создавать резервы нет.
   */
  adp?: AdpDeps;
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

  // Живость процесса; к базе не обращается.
  app.get("/health", async () => ({ status: "ok", env: opts.env }));

  // Проверка обращения — в отдельном контексте: /health её не проходит.
  const pao = opts.pao;
  if (pao) void app.register(async (scope) => paoRoutes(scope, pao));
  // Шлюз участников — своим контекстом: проверка обращения ПАО к нему не относится, подпись — в теле (РП36 п. 4).
  const participants = opts.participants;
  if (participants) void app.register(async (scope) => participantRoutes(scope, participants));
  // ADP — своим контекстом: обращение процессинга, не агента; проверки ПАО к нему не относятся.
  const adp = opts.adp;
  if (adp) void app.register(async (scope) => adpRoutes(scope, adp));

  return app;
}
