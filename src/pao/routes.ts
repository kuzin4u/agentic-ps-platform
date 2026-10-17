// П9 Маршруты ПАО (AGENT-PROTOCOL.md §3). Каждое обращение проверяется до обработчика: агент → подпись → статус (РП23 п. 6).
// Изменяющий метод затем: Idempotency-Key → тело по схеме (REQUEST_INVALID) → захват ключа → обработчик (РП30 п. 3, РП31).
// /revoke — в PS-05б; POST /pao/v1/mandates — PS-06 К1.3 (РП33).
import rateLimit, { normalizeIP } from "@fastify/rate-limit";
import { IdempotencyConflict, IdempotencyInProgress } from "@kuzin4u/agentic-core";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AgentExcludedError, AgentNotActiveError, KeyInvalidError, type AgentKeys } from "../registry/agent-keys.js";
import type { ConsentJournal } from "../consent/journal.js";
import type { AgentRecord } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import type { AgentSelf } from "../shared/pao.js";
import { keyRegistrationBody, mandateRequestBody } from "./body.js";
import { consentErrorReply } from "./consent-errors.js";
import { paoError, type PaoErrorReply } from "./errors.js";
import {
  assertHandlerBudget,
  handlerDeadline,
  idempotencyKeyHash,
  PAO_HANDLER_BUDGET_MS,
  PAO_IDEMPOTENCY_LEASE_MS,
  type PaoIdempotency,
  PaoHandlerDeadline,
  type PaoReply,
} from "./idempotency.js";
import { PAO_DB_TIMEOUT_MS } from "./stores.js";
import type { PaoRequestVerifier } from "./verify.js";

export interface PaoDeps {
  readonly verifier: PaoRequestVerifier;
  readonly keys: AgentKeys;
  readonly idempotency: PaoIdempotency;
  /** Журнал согласий (П2): запрос мандата по ПАО. */
  readonly consent: ConsentJournal;
  readonly params: Pick<Params, "unavailable_retry_after_sec" | "pao_rate_limit_per_30s">;
  /** Монотонные часы предела обработчика (РП33 доп.); по умолчанию performance.now — в тестах подменяются. */
  readonly clock?: () => number;
}

/** Под ключом обработчику передаются хэш ключа и проверка предела времени перед записью (РП33 доп.). */
interface MutatingCtx {
  readonly keyHash: string;
  readonly beforeWrite: () => void;
}

/** Окно грубого лимита (РП32 п. 2, 4): 30 с — Retry-After не больше maxRetryAfterSec клиента ядра (РП24). */
export const PAO_RATE_WINDOW_MS = 30_000;

/** Ключ лимита для IPv6 — подсеть /64 (РП32, дополнение п. 1): иначе клиент меняет адрес внутри своей /64 на каждом обращении. */
export const PAO_RATE_IPV6_SUBNET = 64;

/** Граница Retry-After у 429 (РП24, РП32 дополнение п. 3): и при переводе часов назад. */
const MAX_RETRY_AFTER_SEC = 30;

/** Ключ лимита: IPv4 — как есть, IPv6 — начало своей /64, IPv4 в IPv6 — как IPv4. */
export const rateLimitKey = (ip: string): string => normalizeIP(ip, PAO_RATE_IPV6_SUBNET);

/** Метка превышения лимита: errorResponseBuilder выбрасывает её, обработчик ошибок области отвечает телом ПАО §6. */
const RATE_LIMITED = Object.freeze({ statusCode: 429, code: "RATE_LIMITED" });

declare module "fastify" {
  interface FastifyRequest {
    /** Агент из реестра после проверки обращения; класс и уровень — только отсюда (инвариант 5). */
    paoAgent?: AgentRecord;
  }
}

/** Путь и запрос — как пришли, без декодирования: их подписал агент (ПАО §2). */
function target(req: FastifyRequest): { path: string; query: string } {
  const url = req.raw.url ?? "";
  const q = url.indexOf("?");
  return q < 0 ? { path: url, query: "" } : { path: url.slice(0, q), query: url.slice(q + 1) };
}

export async function paoRoutes(app: FastifyInstance, deps: PaoDeps): Promise<void> {
  // Предел обработчика с таймаутом базы — меньше аренды ключа (РП33 доп. п. 8).
  assertHandlerBudget(PAO_HANDLER_BUDGET_MS, PAO_DB_TIMEOUT_MS, PAO_IDEMPOTENCY_LEASE_MS);
  const clock = deps.clock ?? (() => performance.now());
  const limit = deps.params.pao_rate_limit_per_30s;
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("pao_rate_limit_per_30s — целое ≥ 1");
  // Первый слой лимита (РП32): по адресу, хук onRequest — до проверки обращения и до чтения тела; неподписанный поток
  // тоже ограничен. Retry-After ставит плагин до выброса метки. Маршруты — ниже: хук onRoute плагина видит каждый.
  await app.register(rateLimit, {
    global: true,
    max: limit,
    timeWindow: PAO_RATE_WINDOW_MS,
    keyGenerator: (req) => rateLimitKey(req.ip),
    errorResponseBuilder: () => RATE_LIMITED,
  });
  // Тело — строкой, как подписано: content-digest считается от байтов, а не от разобранного JSON. Любой тип содержимого —
  // строкой (UTF-8): тело с чужим типом доходит до проверки обращения и схемы и получает ответ ПАО §6, а не 415 Fastify.
  // Ответы Fastify до шлюза остаются: тело больше bodyLimit (413), неразборный Content-Type (STATUS «Открыто»).
  const asString = (_req: FastifyRequest, body: string | Buffer, done: (err: null, body: string) => void) =>
    done(null, String(body));
  app.addContentTypeParser("application/json", { parseAs: "string" }, asString);
  app.addContentTypeParser("*", { parseAs: "string" }, asString);

  const send = (reply: FastifyReply, e: PaoErrorReply): FastifyReply => {
    // ПАО §2: Retry-After и с ответами 503 — из стендовых параметров (РП24).
    if (e.http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
    return reply.code(e.http).send(e.body);
  };

  app.setErrorHandler((err, _req, reply) => {
    if (err === RATE_LIMITED) {
      // Остаток окна плагин считает по Date.now(): при переводе часов назад он больше окна — обрезаем до границы РП24.
      const computed = Number(reply.getHeader("retry-after"));
      const retryAfter = Number.isFinite(computed) ? Math.min(Math.max(computed, 0), MAX_RETRY_AFTER_SEC) : MAX_RETRY_AFTER_SEC;
      void reply.header("retry-after", String(retryAfter));
      return reply.code(429).send(paoError("RATE_LIMITED").body);
    }
    return reply.send(err);
  });

  app.addHook("preHandler", async (req, reply) => {
    const { path, query } = target(req);
    const body = typeof req.body === "string" ? req.body : "";
    const r = await deps.verifier.verify({ method: req.method, path, query, headers: req.headers, body });
    if (!r.ok) {
      // Сбой источника — в журнал процесса, не в ответ агенту (повторный аудит PS-04 №4).
      if (r.cause !== undefined) req.log.error({ err: r.cause }, "ПАО: сбой источника (реестр, ключи, хранилище nonce) при проверке обращения");
      return send(reply, paoError(r.code, r.norm));
    }
    req.paoAgent = r.agent;
  });

  // Свой статус, класс, уровень, действующие ключи — из реестра (ПАО §3, A2, ПС01). rate_limit_per_min — в PS-05.
  app.get("/pao/v1/agent", async (req): Promise<AgentSelf> => {
    const agent = req.paoAgent as AgentRecord;
    return {
      agent_code: agent.agent_code,
      operator: agent.operator,
      class: agent.class,
      level: agent.level,
      status: agent.status,
      keys: deps.keys.list(agent.agent_code).filter((k) => k.status === "ACTIVE"),
    };
  });

  /**
   * Изменяющий метод под ключом идемпотентности (РП30 п. 3, РП31): без ключа — IDEMPOTENCY_REQUIRED, тело не по схеме —
   * REQUEST_INVALID, оба до захвата: неполный запрос ключ не занимает. Хэш — от метода, пути, запроса и сырого тела.
   * Ответ обработчика (2xx, 4xx) сохраняется; 5xx обработчика уходит со своим кодом (STATE_UNAVAILABLE), исключение —
   * 503 UPSTREAM_UNAVAILABLE; в обоих случаях захват снимает ядро, повтор исполняется заново.
   */
  async function mutating<T>(
    req: FastifyRequest,
    reply: FastifyReply,
    parse: (raw: string) => T | undefined,
    handler: (agent: AgentRecord, input: T, ctx: MutatingCtx) => PaoReply | Promise<PaoReply>,
  ): Promise<FastifyReply> {
    const agent = req.paoAgent as AgentRecord;
    const key = req.headers["idempotency-key"];
    if (typeof key !== "string" || key === "") return send(reply, paoError("IDEMPOTENCY_REQUIRED"));
    const raw = typeof req.body === "string" ? req.body : "";
    const input = parse(raw);
    if (input === undefined) return send(reply, paoError("REQUEST_INVALID"));
    const { path, query } = target(req);
    const keyHash = idempotencyKeyHash(key);
    let r: PaoReply;
    try {
      r = (
        await deps.idempotency(agent.agent_code).run(
          keyHash,
          { method: req.method, path, query, body: raw },
          async () => {
            // Предел — от захвата ключа: аренда отсчитывается от него же.
            const out = await handler(agent, input, { keyHash, beforeWrite: handlerDeadline(PAO_HANDLER_BUDGET_MS, clock) });
            // 5xx не сохраняется (РП30 п. 3): исключение снимает захват, повтор исполняется заново; ответ — как вернул обработчик.
            if (out.status >= 500) throw new UnstoredReply({ http: out.status, body: out.body as PaoErrorReply["body"] });
            return out;
          },
        )
      ).result;
    } catch (err) {
      if (err instanceof IdempotencyConflict) return send(reply, paoError("IDEMPOTENCY_CONFLICT"));
      if (err instanceof UnstoredReply) return send(reply, err.reply);
      // Тот же ключ ещё выполняется — 503 same_key (РП30 п. 3); предел обработчика исчерпан (РП33 доп. п. 8) — 503,
      // предупреждение; сбой хранилища или обработчика — 503 и ошибка в журнале процесса.
      if (err instanceof PaoHandlerDeadline) req.log.warn({ agent_code: agent.agent_code }, err.message);
      else if (!(err instanceof IdempotencyInProgress)) req.log.error({ err }, "ПАО: сбой хранилища идемпотентности или обработчика");
      return send(reply, paoError("UPSTREAM_UNAVAILABLE"));
    }
    return reply.code(r.status).send(r.body);
  }

  // Регистрация своего ключа (ПАО §3, A2 п. 5.3, РП23 п. 2–4): срок и перекрытие — в реестре; причина отказа агенту
  // не раскрывается (РП31 п. 2) — она в журнале процесса. Только ACTIVE: смена ключа приостановленным — через оператора (PS-31).
  app.post("/pao/v1/agent/keys", async (req, reply) =>
    mutating(req, reply, keyRegistrationBody, (agent, input) => {
      try {
        // Свой действующий ключ повторно — тот же Key, 201 (РП23 доп. 7): повтор после потерянного ответа.
        const added = deps.keys.register(agent.agent_code, input, { requireActive: true });
        const key = deps.keys.list(agent.agent_code).find((k) => k.kid === added.kid);
        if (!key) throw new Error("ПАО: ключ после регистрации не найден");
        return { status: 201, body: key };
      } catch (err) {
        if (err instanceof KeyInvalidError) {
          req.log.info({ agent_code: agent.agent_code, reason: err.reason }, "ПАО: ключ не принят (РП23 п. 2–3)");
          return reply4xx(paoError("KEY_INVALID", "A2 п. 5.1"));
        }
        // Приостановлен или исключён между проверкой обращения и вставкой ключа — как отказ по статусу (РП23 п. 6.3).
        if (err instanceof AgentNotActiveError || err instanceof AgentExcludedError) {
          return reply4xx(paoError("AGENT_SUSPENDED", "A2 п. 7.1"));
        }
        throw err;
      }
    }),
  );

  // Запрос мандата (ПАО §3, A7 п. 1–3; РП33): PENDING_SIGNATURE, подпись — у принципала в банке. agent_code — из
  // проверенного обращения (инвариант 5). id — от (агент, ключ): повтор находит записанный мандат (РП33 доп.). Отказ журнала — код ПАО по РП33 п. 1; причина (поле) — только в журнал процесса.
  app.post("/pao/v1/mandates", async (req, reply) =>
    mutating(req, reply, mandateRequestBody, async (agent, input, ctx) => {
      try {
        return { status: 201, body: await deps.consent.request(agent.agent_code, ctx.keyHash, input, ctx.beforeWrite) };
      } catch (err) {
        const e = consentErrorReply(err);
        if (!e) throw err;
        if (e.http >= 500) req.log.error({ err, agent_code: agent.agent_code }, "ПАО: журнал согласий — состояние не подтверждено");
        else req.log.info({ agent_code: agent.agent_code, reason: (err as Error).message }, "ПАО: мандат не записан");
        return reply4xx(e);
      }
    }),
  );
}

const reply4xx = (e: PaoErrorReply): PaoReply => ({ status: e.http, body: e.body });

/** Ответ 5xx обработчика — тело ПАО §6: не сохраняется под ключом (РП30 п. 3), но уходит агенту с кодом обработчика. */
class UnstoredReply extends Error {
  constructor(readonly reply: PaoErrorReply) {
    super(`ПАО: ответ ${reply.http} не сохраняется`);
  }
}
