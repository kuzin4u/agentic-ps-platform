// П9 Маршруты ПАО (AGENT-PROTOCOL.md §3). Каждое обращение проверяется до обработчика: агент → подпись → статус (РП23 п. 6).
// Изменяющий метод затем: Idempotency-Key → тело по схеме (REQUEST_INVALID) → захват ключа → обработчик (РП30 п. 3, РП31).
// /revoke — в PS-05б; POST /pao/v1/mandates — PS-06 К1.3 (РП33); GET /pao/v1/mandates/{id} — К2.2.
import rateLimit, { normalizeIP } from "@fastify/rate-limit";
import { IdempotencyConflict, IdempotencyInProgress } from "@kuzin4u/agentic-core";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AgentExcludedError, AgentNotActiveError, KeyInvalidError, type AgentKeys } from "../registry/agent-keys.js";
import type { ConsentJournal } from "../consent/journal.js";
import { MANDATE_ID } from "../consent/model.js";
import type { AgentRecord, AgentSubscription } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import type { AgentSelf, Credential } from "../shared/pao.js";
import { CONFIRMATION_ID, type ConfirmationRecord } from "../confirm/model.js";
import type { ConfirmationStore } from "../confirm/store.js";
import { CREDENTIAL_REF } from "../credentials/model.js";
import type { Credentials } from "../credentials/service.js";
import { operationFor, operationsFor, type OperationViewDeps } from "../fulfilment/view.js";
import { credentialRequestBody, hasPaymentDetails, keyRegistrationBody, mandateRequestBody, subscriptionBody } from "./body.js";
import { consentErrorReply } from "./consent-errors.js";
import { EVENT_ID, EventCursorUnknown } from "./events.js";
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
import { checkSubscriptionUrl, resolveGlobal, STAND_PORT, systemResolver, withTimeout, type HostResolver } from "./subscription.js";
import type { PaoRequestVerifier } from "./verify.js";

export interface PaoDeps {
  readonly verifier: PaoRequestVerifier;
  readonly keys: AgentKeys;
  readonly idempotency: PaoIdempotency;
  /** Журнал согласий (П2): запрос мандата по ПАО. */
  readonly consent: ConsentJournal;
  readonly params: Pick<
    Params,
    "unavailable_retry_after_sec" | "pao_rate_limit_per_30s" | "event_page_max" | "event_subscription_allow_hosts"
  >;
  /** Подписка в записи агента (РП40 п. 1, С6); без неё PUT /pao/v1/subscription не регистрируется. */
  readonly subscriptions?: {
    readonly set: (agent_code: string, subscription: AgentSubscription) => AgentSubscription;
  };
  /** Разрешение имени адреса подписки (РП40 п. 2–4); по умолчанию — системное, на стенде — стендовое (п. 8). */
  readonly resolveHost?: HostResolver;
  /**
   * Агентские реквизиты (П5, РП47); без них POST /pao/v1/credentials не регистрируется: токен-сервис оператора (ПИ-4)
   * в рабочем сервере не подключён — только стенд и тесты.
   */
  readonly credentials?: Pick<Credentials, "issue" | "replay" | "get">;
  /**
   * Запросы подтверждения П6 (РП51 п. 8–10); без них GET /pao/v1/confirmations/{id} не регистрируется: П6 в рабочем
   * сервере не подключено — только стенд и тесты. now — часы Платформы для истечения при чтении (п. 6).
   */
  readonly confirmations?: {
    readonly store: Pick<ConfirmationStore, "get" | "expire">;
    readonly now: () => Date;
    readonly upk_page_base_url: string;
  };
  /**
   * Записи операций ADP и итоги П8 (РП52 п. 10, РП53 п. 10); без них GET /pao/v1/operations/{op_ref} не регистрируется:
   * ADP в рабочем сервере не подключена — только стенд и тесты.
   */
  readonly operations?: OperationViewDeps;
  /** Стенд (РП40 п. 8): только он принимает стендовые порты; в рабочем сервере стендовый порт — отказ запуска. */
  readonly stand?: boolean;
  /** Монотонные часы предела обработчика (РП33 доп.); по умолчанию performance.now — в тестах подменяются. */
  readonly clock?: () => number;
}

/** Под ключом обработчику передаются хэш ключа и проверка предела времени перед записью (РП33 доп.). */
interface MutatingCtx {
  readonly keyHash: string;
  readonly beforeWrite: () => void;
}

/** Ответ обработчика: агенту — status и body; под ключом — stored, если тело хранить нельзя (РП48 (в): криптограмма). */
interface HandlerReply extends PaoReply {
  readonly stored?: PaoReply;
}

interface MutatingOpts<T> {
  readonly forbidPaymentDetails?: boolean;
  /** Повтор под ключом с сохранённым 2xx: ответ собирается заново из сохранённого (РП48 (в)); без него — сохранённый как есть. */
  readonly replay?: (agent: AgentRecord, input: T, stored: PaoReply) => Promise<PaoReply>;
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
    /** Ключ, которым подписано обращение (РП23): в запись отказа агента от полномочий (РП38 п. 3). */
    paoKid?: string;
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
    req.paoKid = r.kid;
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
    handler: (agent: AgentRecord, input: T, ctx: MutatingCtx) => HandlerReply | Promise<HandlerReply>,
    opts: MutatingOpts<T> = {},
  ): Promise<FastifyReply> {
    const agent = req.paoAgent as AgentRecord;
    const key = req.headers["idempotency-key"];
    if (typeof key !== "string" || key === "") return send(reply, paoError("IDEMPOTENCY_REQUIRED"));
    const raw = typeof req.body === "string" ? req.body : "";
    // Реквизиты карты в теле — 422 CREDENTIALS_FORBIDDEN до схемы и захвата ключа: номер не попадает ни в хранилище
    // идемпотентности, ни в журнал процесса (инвариант 1); в журнал — только код агента.
    if (opts.forbidPaymentDetails && hasPaymentDetails(raw)) {
      req.log.warn({ agent_code: agent.agent_code }, "ПАО: в теле запроса платёжные реквизиты — отклонено");
      return send(reply, paoError("CREDENTIALS_FORBIDDEN", "A3 п. 2"));
    }
    const input = parse(raw);
    if (input === undefined) return send(reply, paoError("REQUEST_INVALID"));
    const { path, query } = target(req);
    const keyHash = idempotencyKeyHash(key);
    let r: PaoReply;
    // Ответ первого исполнения, когда под ключом хранится другое тело (stored, РП48 (в)): агенту — он целиком. Без stored
    // агенту — ответ ядра (канонический JSON), как и при повторе: первый ответ и повтор совпадают побайтно.
    let fresh: PaoReply | undefined;
    try {
      const run = await deps.idempotency(agent.agent_code).run(
        keyHash,
        { method: req.method, path, query, body: raw },
        async () => {
          // Предел — от захвата ключа: аренда отсчитывается от него же.
          const out = await handler(agent, input, { keyHash, beforeWrite: handlerDeadline(PAO_HANDLER_BUDGET_MS, clock) });
          // 5xx не сохраняется (РП30 п. 3): исключение снимает захват, повтор исполняется заново; ответ — как вернул обработчик.
          if (out.status >= 500) throw new UnstoredReply({ http: out.status, body: out.body as PaoErrorReply["body"] });
          if (out.stored === undefined) return { status: out.status, body: out.body };
          fresh = { status: out.status, body: out.body };
          return out.stored;
        },
      );
      if (!run.replayed) r = fresh ?? run.result;
      else if (opts.replay && run.result.status < 300) {
        r = await opts.replay(agent, input, run.result);
        // Пересборка даёт либо тот же статус, либо 5xx (повтор позже): окончательный отказ при сохранённом 2xx нарушил
        // бы идемпотентность (РП30 п. 3) — агент бросил бы выданный реквизит. Иное — не подтверждено, инцидент.
        if (r.status < 500 && r.status !== run.result.status) {
          const code = (r.body as { readonly code?: unknown } | null)?.code;
          const credential_ref = (run.result.body as { readonly credential_ref?: unknown } | null)?.credential_ref;
          req.log.warn(
            { agent_code: agent.agent_code, status: r.status, code, credential_ref, incident: true },
            "ПАО: пересборка повтора дала другой статус",
          );
          r = reply4xx(paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
        }
      } else r = run.result;
    } catch (err) {
      if (err instanceof IdempotencyConflict) return send(reply, paoError("IDEMPOTENCY_CONFLICT"));
      if (err instanceof UnstoredReply) return send(reply, err.reply);
      // Тот же ключ ещё выполняется — 503 same_key (РП30 п. 3); предел обработчика исчерпан (РП33 доп. п. 8) — 503,
      // предупреждение; сбой хранилища или обработчика — 503 и ошибка в журнале процесса.
      if (err instanceof PaoHandlerDeadline) req.log.warn({ agent_code: agent.agent_code }, err.message);
      else if (!(err instanceof IdempotencyInProgress)) req.log.error({ err }, "ПАО: сбой хранилища идемпотентности или обработчика");
      return send(reply, paoError("UPSTREAM_UNAVAILABLE"));
    }
    // 5xx пересборки при повторе — с Retry-After, как 5xx обработчика.
    if (r.status >= 500) return send(reply, { http: r.status, body: r.body as PaoErrorReply["body"] });
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

  // Агентский реквизит на заказ (ПАО §4, РП47 п. 4–5): agent_code — из проверенного обращения (инвариант 5); отказ П5 —
  // код ПАО, причина — в журнал процесса; отказ журнала — по consentErrorReply. 5xx не сохраняется под ключом (РП30 п. 3).
  // Под ключом — ответ без криптограммы; повтор под ключом пересчитывает её по записи реквизита (РП48 (в)).
  const credentials = deps.credentials;
  if (credentials) {
    app.post("/pao/v1/credentials", async (req, reply) =>
      mutating(req, reply, credentialRequestBody, async (agent, input, ctx) => {
        if (!MANDATE_ID.test(input.mandate_id)) return reply4xx(paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
        try {
          const r = await credentials.issue(agent.agent_code, input, ctx.beforeWrite);
          if (r.ok) return { status: 201, body: r.credential, stored: { status: 201, body: withoutCryptogram(r.credential) } };
          req.log.info({ agent_code: agent.agent_code, mandate_id: input.mandate_id, code: r.code }, "ПАО: реквизит не выдан");
          return reply4xx(paoError(r.code, r.norm, r.message));
        } catch (err) {
          const e = consentErrorReply(err);
          if (!e) throw err;
          req.log.error({ err, agent_code: agent.agent_code }, "ПАО: журнал согласий — состояние не подтверждено");
          return reply4xx(e);
        }
      }, {
        forbidPaymentDetails: true,
        replay: async (agent, input, stored) => {
          const ref = (stored.body as { readonly credential_ref?: unknown } | null)?.credential_ref;
          if (typeof ref !== "string") {
            req.log.warn({ agent_code: agent.agent_code, incident: true }, "ПАО: сохранённый ответ реквизита без credential_ref");
            return reply4xx(paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
          }
          const r = await credentials.replay(agent.agent_code, input, ref);
          if (r.ok) return { status: stored.status, body: r.credential };
          req.log.info({ agent_code: agent.agent_code, mandate_id: input.mandate_id, code: r.code }, "ПАО: повтор реквизита под ключом не собран");
          return reply4xx(paoError(r.code, r.norm, r.message));
        },
      }),
    );

    // Реквизит по ссылке (ПАО §4, РП49 (г)): только свой — агент из проверенного обращения (инвариант 5); чужой и
    // неизвестный — один ответ 409 CREDENTIAL_INVALID. Тот же Credential, что при повторе: криптограмма — пересчётом.
    app.get<{ Params: { ref: string } }>("/pao/v1/credentials/:ref", async (req, reply) => {
      const agent = req.paoAgent as AgentRecord;
      // Не по форме credential_ref — тот же ответ, что у неизвестного, до хранилища (решение владельца 21.10, ревью К2б):
      // иначе %00 на PostgreSQL — ошибка text и 503 с Retry-After вместо окончательного отказа.
      if (!CREDENTIAL_REF.test(req.params.ref)) return send(reply, paoError("CREDENTIAL_INVALID"));
      const r = await credentials.get(agent.agent_code, req.params.ref);
      if (r.ok) return reply.code(200).send(r.credential);
      req.log.info({ agent_code: agent.agent_code, code: r.code }, "ПАО: реквизит по ссылке не отдан");
      return send(reply, paoError(r.code, r.norm, r.message));
    });
  }

  // Отказ агента от полномочий (ПАО §3, A7 п. 6; РП38 п. 3–4): только свой мандат, под ключом идемпотентности; запись
  // MANDATE_RELINQUISHED — при PENDING_SIGNATURE или ACTIVE, иначе текущий мандат без записи. Отказ от INTENT отзывает его CART (РП35).
  app.post<{ Params: { id: string } }>("/pao/v1/mandates/:id/relinquish", async (req, reply) => {
    const id = req.params.id;
    return mutating(req, reply, emptyBody, async (agent) => {
      if (!MANDATE_ID.test(id)) return reply4xx(paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
      try {
        const m = await deps.consent.relinquish(id, agent.agent_code, req.paoKid as string);
        if (!m) return reply4xx(paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
        req.log.info({ agent_code: agent.agent_code, mandate_id: id, status: m.status }, "ПАО: отказ агента от полномочий");
        return { status: 200, body: m };
      } catch (err) {
        const e = consentErrorReply(err);
        if (!e) throw err;
        req.log.error({ err, agent_code: agent.agent_code }, "ПАО: журнал согласий — состояние не подтверждено");
        return reply4xx(e);
      }
    });
  });

  // Мандат этого агента (ПАО §3, A7; PS-06 К2.2): статус — свёртка записей на момент чтения, а не сохранённый ответ
  // запроса. Чужой, неизвестный и не по форме id — один ответ 404 MANDATE_NOT_FOUND: чужой неотличим от неизвестного.
  // Цепочка нарушена или состояние не определяется — 503 STATE_UNAVAILABLE (инвариант 3); сбой хранилища — 503 UPSTREAM_UNAVAILABLE.
  const readMandate =
    (read: (id: string, agent_code: string) => Promise<object | undefined>) =>
    async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply): Promise<FastifyReply> => {
      const agent = req.paoAgent as AgentRecord;
      const id = req.params.id;
      if (!MANDATE_ID.test(id)) return send(reply, paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
      try {
        const m = await read(id, agent.agent_code);
        if (!m) return send(reply, paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
        return reply.code(200).send(m);
      } catch (err) {
        const e = consentErrorReply(err);
        if (e) {
          req.log.error({ err, agent_code: agent.agent_code }, "ПАО: журнал согласий — состояние не подтверждено");
          return send(reply, e);
        }
        req.log.error({ err }, "ПАО: сбой журнала согласий при чтении мандата");
        return send(reply, paoError("UPSTREAM_UNAVAILABLE"));
      }
    };
  app.get<{ Params: { id: string } }>("/pao/v1/mandates/:id", readMandate((id, code) => deps.consent.get(id, code)));

  // Проверка без предмета (ПАО §3, A7 п. 9.2; РП38 п. 6): {outcome, amount_left, valid_to, as_of}; остаток до PS-09 — предел.
  app.get<{ Params: { id: string } }>("/pao/v1/mandates/:id/verify", readMandate((id, code) => deps.consent.verify(id, code)));

  // Выписка (ПАО §3, A7 п. 9.3; РП38 п. 7): цепочка журнала для проверки без Платформы; нарушенная — 200 integrity BROKEN.
  app.get<{ Params: { id: string } }>("/pao/v1/mandates/:id/evidence", async (req, reply) =>
    readMandate(async (id, code) => {
      const ev = await deps.consent.evidence(id, code);
      if (ev?.integrity === "BROKEN") req.log.error({ agent_code: code, mandate_id: id }, "ПАО: выписка — цепочка журнала согласий нарушена");
      return ev;
    })(req, reply),
  );

  // Подписка на события (ПАО §5; РП40 п. 1–3): адрес — https, порт 443, имя из списка разрешённых, все адреса имени
  // глобальные; иначе 400 REQUEST_INVALID, причина — в журнал процесса (только хост, без пути: путь может нести секрет
  // агента). Временный сбой и таймаут DNS — 503 STATE_UNAVAILABLE: не сохраняется под ключом, повтор тем же ключом
  // (дополнение РП40 п. 3). Подписка заменяется целиком и действует на события после неё;
  // недоставленные уходят по текущей подписке (дополнение РП40 п. 11). SUSPENDED/EXCLUDED — 403 до обработчика (п. 6–7).
  if (deps.resolveHost && STAND_PORT in deps.resolveHost && deps.stand !== true) {
    throw new Error("ПАО: стендовое разрешение имени в рабочем сервере — отказ запуска (РП40 п. 8)");
  }
  const subscriptions = deps.subscriptions;
  const resolveHost = withTimeout(deps.resolveHost ?? systemResolver, PAO_DB_TIMEOUT_MS);
  if (subscriptions) {
    app.put("/pao/v1/subscription", async (req, reply) =>
      mutating(req, reply, subscriptionBody, async (agent, input, ctx) => {
        const refuse = (reason: string, host: string | undefined): PaoReply => {
          req.log.info({ agent_code: agent.agent_code, reason, host }, "ПАО: адрес подписки не принят (РП40 п. 2)");
          return reply4xx(paoError("REQUEST_INVALID", "ПАО §5"));
        };
        const form = checkSubscriptionUrl(input.url, deps.params.event_subscription_allow_hosts);
        if (!form.ok) return refuse(form.reason, form.host);
        const addrs = await resolveGlobal(form.host, resolveHost);
        if (!addrs.ok && addrs.reason === "resolve_failed") {
          req.log.warn({ agent_code: agent.agent_code, host: form.host }, "ПАО: адрес подписки не проверен — сбой разрешения имени");
          const e = paoError("STATE_UNAVAILABLE", "ПАО §5");
          return { status: e.http, body: e.body };
        }
        if (!addrs.ok) return refuse(addrs.reason, form.host);
        ctx.beforeWrite();
        return { status: 200, body: subscriptions.set(agent.agent_code, { url: form.url, events: input.events }) };
      }),
    );
  }

  // Запрос подтверждения создаёт ADP с итогом из сообщения процессинга (РП50, инвариант 5): в 1.4.x метода нет —
  // 400 REQUEST_INVALID без записи и без захвата ключа (РП51 п. 11); судьба метода — ПАО 1.5.0.
  app.post("/pao/v1/confirmations", async (req, reply) => {
    req.log.info({ agent_code: (req.paoAgent as AgentRecord).agent_code }, "ПАО: POST /pao/v1/confirmations в 1.4.x не поддерживается");
    return send(reply, paoError("REQUEST_INVALID", "ПАО §3"));
  });

  // Запрос подтверждения этого агента (ПАО §3; РП51 п. 8–10). Чужой, неизвестный и не по форме id — один ответ
  // 400 REQUEST_INVALID: кода «не найден» в 1.4.0 нет (404 CONFIRMATION_NOT_FOUND — ПАО 1.5.0). PENDING после срока
  // переводится в EXPIRED этим чтением (событие confirmation.expired, п. 6). Сбой П6 — 503 STATE_UNAVAILABLE.
  const confirmations = deps.confirmations;
  if (confirmations) {
    app.get<{ Params: { id: string } }>("/pao/v1/confirmations/:id", async (req, reply) => {
      const agent = req.paoAgent as AgentRecord;
      const id = req.params.id;
      if (!CONFIRMATION_ID.test(id)) return send(reply, paoError("REQUEST_INVALID", "ПАО §3"));
      try {
        let r = await confirmations.store.get(id);
        if (!r || r.agent_code !== agent.agent_code) return send(reply, paoError("REQUEST_INVALID", "ПАО §3"));
        const now = confirmations.now().toISOString();
        if (r.status === "PENDING" && !(r.expires_at > now)) {
          await confirmations.store.expire(id, now);
          r = await confirmations.store.get(id);
          if (!r) throw new Error("confirmations: запрос пропал после истечения");
        }
        return reply.code(200).send(confirmationView(r, confirmations.upk_page_base_url));
      } catch (err) {
        req.log.error({ err, agent_code: agent.agent_code }, "ПАО: П6 — состояние запроса подтверждения не подтверждено");
        return send(reply, paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
      }
    });
  }

  // Операция этого агента (ПАО §5; РП52 п. 10, РП53 п. 10): итог — из записи итога, а без неё — из решения в записи
  // операции ADP, независимо от сборщика. Чужая, неизвестная, без установленного агента и без итога — один ответ
  // 400 REQUEST_INVALID (OPERATION_NOT_FOUND — ПАО 1.5.0). SUSPENDED/EXCLUDED — 403 до обработчика. Сбой — 503.
  const operations = deps.operations;
  if (operations) {
    app.get<{ Params: { op_ref: string } }>("/pao/v1/operations/:op_ref", async (req, reply) => {
      const agent = req.paoAgent as AgentRecord;
      try {
        const op = await operationFor(operations, agent.agent_code, req.params.op_ref);
        if (!op) return send(reply, paoError("REQUEST_INVALID", "ПАО §5"));
        return reply.code(200).send(op);
      } catch (err) {
        req.log.error({ err, agent_code: agent.agent_code }, "ПАО: П8 — итог операции не прочитан");
        return send(reply, paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
      }
    });

    // Операции этого агента по мандату (ПАО §5; РП55 п. 6): мандат — как у GET мандата (чужой, неизвестный, не по форме и
    // без параметра — один ответ 404 MANDATE_NOT_FOUND); операции — только с итогом, по времени решения; записей больше
    // event_page_max — 400 REQUEST_INVALID (постраничный вывод — ПАО 1.5.0). В YAML 1.4.0 — только 200 (расхождение № 41).
    const list = operations.list;
    if (list) {
      app.get<{ Querystring: Record<string, unknown> }>("/pao/v1/operations", async (req, reply) => {
        const agent = req.paoAgent as AgentRecord;
        const id = req.query.mandate_id;
        if (typeof id !== "string" || !MANDATE_ID.test(id)) return send(reply, paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
        try {
          if (!(await deps.consent.get(id, agent.agent_code))) return send(reply, paoError("MANDATE_NOT_FOUND", "A7 п. 9.1"));
        } catch (err) {
          const e = consentErrorReply(err);
          req.log.error({ err, agent_code: agent.agent_code }, "ПАО: журнал согласий — мандат списка операций не прочитан");
          return send(reply, e ?? paoError("UPSTREAM_UNAVAILABLE"));
        }
        try {
          const r = await operationsFor({ ...operations, list }, agent.agent_code, id, deps.params.event_page_max);
          if (!r.ok) return send(reply, paoError("REQUEST_INVALID", "ПАО §5"));
          return reply.code(200).send(r.operations);
        } catch (err) {
          req.log.error({ err, agent_code: agent.agent_code }, "ПАО: П8 — операции по мандату не прочитаны");
          return send(reply, paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
        }
      });
    }
  }

  // Лента событий этого агента (ПАО §5; РП39 п. 7): после курсора after, по номеру, не больше event_page_max.
  // after не по форме, пустой или повторённый — 400 REQUEST_INVALID, как и чужой или неизвестный (одинаково).
  // Ответы 400/401/403/503 объявляются в ПАО 1.5.0 (РП39 п. 8, № 20). Событие — сигнал, статус — через GET мандата.
  app.get<{ Querystring: Record<string, unknown> }>("/pao/v1/events", async (req, reply) => {
    const agent = req.paoAgent as AgentRecord;
    const after = req.query.after;
    if (after !== undefined && (typeof after !== "string" || !EVENT_ID.test(after))) {
      return send(reply, paoError("REQUEST_INVALID", "ПАО §5"));
    }
    try {
      return reply.code(200).send(await deps.consent.events(agent.agent_code, after, deps.params.event_page_max));
    } catch (err) {
      if (err instanceof EventCursorUnknown) return send(reply, paoError("REQUEST_INVALID", "ПАО §5"));
      req.log.error({ err }, "ПАО: сбой ленты событий");
      return send(reply, paoError("UPSTREAM_UNAVAILABLE"));
    }
  });
}

/** Тело отказа агента от полномочий — пустое (РП38 п. 3). */
const emptyBody = (raw: string): true | undefined => (raw === "" ? true : undefined);

const reply4xx = (e: PaoErrorReply): PaoReply => ({ status: e.http, body: e.body });

/**
 * Confirmation ПАО 1.4.0 (РП51 п. 9–10): USED — как APPROVED с той же ссылкой (значения USED в перечне нет до 1.5.0;
 * погашение агент узнаёт из итога операции); ссылка — только у APPROVED и USED. link — страница УПК без сумм и ссылки.
 */
const confirmationView = (r: ConfirmationRecord, upkBase: string) => ({
  id: r.confirmation_id,
  status: r.status === "USED" ? "APPROVED" : r.status,
  link: `${upkBase}/c/${r.confirmation_id}`,
  confirmation_ref: r.status === "APPROVED" || r.status === "USED" ? r.confirmation_ref : null,
  expires_at: r.expires_at,
});

/** Реквизит для хранения под ключом (РП48 (в)): без значения криптограммы — его в базе Платформы нет (РП47 п. 3, 10). */
function withoutCryptogram(c: Credential): Credential {
  const payload = { ...c.payload };
  delete payload.cryptogram;
  return { ...c, payload };
}

/** Ответ 5xx обработчика — тело ПАО §6: не сохраняется под ключом (РП30 п. 3), но уходит агенту с кодом обработчика. */
class UnstoredReply extends Error {
  constructor(readonly reply: PaoErrorReply) {
    super(`ПАО: ответ ${reply.http} не сохраняется`);
  }
}
