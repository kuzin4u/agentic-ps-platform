// Грубый лимит частоты по адресу обращения — общая часть шлюза ПАО (РП32) и открытых адресов (РП73): ключ, окно, граница
// Retry-After. Контексты API для продавцов и шлюза участников ПИ-8 — addressRateLimit со своим счётчиком и ответом
// {code: RATE_LIMITED}; шлюз ПАО отвечает телом ПАО §6 (src/pao/routes.ts).
import rateLimit, { normalizeIP } from "@fastify/rate-limit";
import type { FastifyInstance, FastifyReply } from "fastify";

/** Окно грубого лимита (РП32 п. 2, 4; РП73 п. 2): 30 с — Retry-After не больше maxRetryAfterSec клиента ядра (РП24). */
export const ADDRESS_RATE_WINDOW_MS = 30_000;

/** Ключ лимита для IPv6 — подсеть /64 (РП32, дополнение п. 1): иначе клиент меняет адрес внутри своей /64 на каждом обращении. */
export const ADDRESS_RATE_IPV6_SUBNET = 64;

/** Граница Retry-After у 429 (РП24, РП32 дополнение п. 3): и при переводе часов назад. */
const MAX_RETRY_AFTER_SEC = 30;

/** Ключ лимита: IPv4 — как есть, IPv6 — начало своей /64, IPv4 в IPv6 — как IPv4. */
export const rateLimitKey = (ip: string): string => normalizeIP(ip, ADDRESS_RATE_IPV6_SUBNET);

/** Остаток окна в секундах для Retry-After: не больше границы РП24 и при переводе часов назад (РП32, дополнение п. 3). */
export const retryAfterSec = (computed: number): number =>
  Number.isFinite(computed) ? Math.min(Math.max(computed, 0), MAX_RETRY_AFTER_SEC) : MAX_RETRY_AFTER_SEC;

/**
 * Метка превышения у открытых адресов (РП73 п. 3): errorResponseBuilder выбрасывает её, обработчик ошибок контекста
 * отвечает addressLimitedReply — до своего разбора 4xx, иначе 429 стал бы 400 REQUEST_INVALID.
 */
export const ADDRESS_RATE_LIMITED = Object.freeze({ statusCode: 429, code: "RATE_LIMITED" });

/**
 * Грубый лимит по адресу у открытого контекста (РП73 п. 1–2): свой счётчик на контекст, хук onRequest — до чтения тела,
 * проверки подписи и обращений к хранилищам. Регистрируется до маршрутов контекста: плагин ставит хук маршрутам,
 * объявленным после него. Предел — целое ≥ 1, иначе отказ сборки (как paoCoarseLimit).
 */
export async function addressRateLimit(app: FastifyInstance, limit: number, param: string): Promise<void> {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error(`${param} — целое ≥ 1`);
  await app.register(rateLimit, {
    global: true,
    max: limit,
    timeWindow: ADDRESS_RATE_WINDOW_MS,
    keyGenerator: (req) => rateLimitKey(req.ip),
    errorResponseBuilder: () => ADDRESS_RATE_LIMITED,
  });
}

/**
 * Ответ превышения у открытых адресов (РП73 п. 3): 429 {code: RATE_LIMITED}, Retry-After ≤ 30, Cache-Control: no-store —
 * обычные ответы API продавцов кешируются, 429 продавец закешировать не должен.
 */
export function addressLimitedReply(reply: FastifyReply): FastifyReply {
  return reply
    .code(429)
    .header("retry-after", String(retryAfterSec(Number(reply.getHeader("retry-after")))))
    .header("cache-control", "no-store")
    .send({ code: "RATE_LIMITED" });
}
