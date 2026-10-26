// П9 Маршруты ПАО (AGENT-PROTOCOL.md §3). Каждое обращение проверяется до обработчика: агент → подпись → статус (РП23 п. 6).
// Изменяющий метод затем: Idempotency-Key → тело по схеме (REQUEST_INVALID) → захват ключа → обработчик (РП30 п. 3, РП31).
// /revoke — PS-05б ч. 1 (РП60); POST /pao/v1/mandates — PS-06 К1.3 (РП33); GET /pao/v1/mandates/{id} — К2.2.
import rateLimit, { normalizeIP, type CreateRateLimitOptions } from "@fastify/rate-limit";
import { IdempotencyConflict, IdempotencyInProgress } from "@kuzin4u/agentic-core";
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AgentExcludedError, AgentNotActiveError, KeyInvalidError, KeyNotFoundError, type AgentKeys } from "../registry/agent-keys.js";
import { KID_FORM } from "../registry/keys.js";
import type { ConsentJournal } from "../consent/journal.js";
import { MANDATE_ID } from "../consent/model.js";
import type { AgentRecord, AgentSubscription } from "../registry/model.js";
import { agentRateLimitProblems, type Params } from "../shared/config.js";
import type { AgentSelf, Credential } from "../shared/pao.js";
import { CONFIRMATION_ID, type ConfirmationRecord } from "../confirm/model.js";
import type { ConfirmationStore } from "../confirm/store.js";
import { CREDENTIAL_REF } from "../credentials/model.js";
import type { Credentials } from "../credentials/service.js";
import { operationFor, operationsFor, type OperationViewDeps } from "../fulfilment/view.js";
import { publicReadiness, type ReadinessStore } from "../participants/readiness.js";
import { isMerchantId } from "../participants/trusted.js";
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
import { errFields, logTransportReject, PAO_BODY_LIMIT_BYTES, paoTransportError } from "./transport.js";
import { checkSubscriptionUrl, resolveGlobal, STAND_PORT, systemResolver, withTimeout, type HostResolver } from "./subscription.js";
import { SIGNED_HEADERS, type PaoAuthResult, type PaoRequestVerifier } from "./verify.js";

export interface PaoDeps {
  readonly verifier: PaoRequestVerifier;
  readonly keys: AgentKeys;
  readonly idempotency: PaoIdempotency;
  /** Журнал согласий (П2): запрос мандата по ПАО. */
  readonly consent: ConsentJournal;
  readonly params: Pick<
    Params,
    | "unavailable_retry_after_sec"
    | "pao_rate_limit_per_30s"
    | AgentRateParam
    | "event_page_max"
    | "event_subscription_allow_hosts"
  >;
  /** Подписка в записи агента (РП40 п. 1, С6); без неё PUT /pao/v1/subscription не регистрируется. */
  readonly subscriptions?: {
    readonly set: (agent_code: string, subscription: AgentSubscription) => Promise<AgentSubscription>;
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
  /**
   * Знак готовности продавца (РП57 п. 3–4); без хранилища GET /pao/v1/merchants/{merchant_id}/readiness не
   * регистрируется. В agent-protocol.yaml пути нет до ПАО 1.5.0 (как № 41).
   */
  readonly readiness?: Pick<ReadinessStore, "current">;
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

/** Остаток окна в секундах для Retry-After: не больше границы РП24 и при переводе часов назад (РП32, дополнение п. 3). */
const retryAfterSec = (computed: number): number =>
  Number.isFinite(computed) ? Math.min(Math.max(computed, 0), MAX_RETRY_AFTER_SEC) : MAX_RETRY_AFTER_SEC;

/** Параметры второго слоя по уровням агента (РП63 п. 4). */
const AGENT_RATE_PARAMS = Object.freeze({
  1: "pao_agent_rate_limit_per_min_l1",
  2: "pao_agent_rate_limit_per_min_l2",
  3: "pao_agent_rate_limit_per_min_l3",
} as const);
type AgentRateParam = (typeof AGENT_RATE_PARAMS)[keyof typeof AGENT_RATE_PARAMS];

/** Счётчиков второго слоя в памяти (РП63 п. 7): при вытеснении счётчик агента обнуляется; агентов на порядки меньше. */
const AGENT_RATE_CACHE = 10_000;

/**
 * Предел второго слоя в минуту для уровня агента (РП63 п. 4–5). Уровень вне таблицы — L1, строжайший (инвариант 3);
 * inTable — для записи в журнал. Его же отдаёт AgentSelf.rate_limit_per_min (п. 6).
 */
export function agentRateLimitPerMin(params: Pick<Params, AgentRateParam>, level: number): { perMin: number; inTable: boolean } {
  const key = Object.hasOwn(AGENT_RATE_PARAMS, level) ? AGENT_RATE_PARAMS[level as keyof typeof AGENT_RATE_PARAMS] : undefined;
  return key ? { perMin: params[key], inTable: true } : { perMin: params.pao_agent_rate_limit_per_min_l1, inTable: false };
}

declare module "fastify" {
  interface FastifyRequest {
    /** Агент из реестра после проверки обращения; класс и уровень — только отсюда (инвариант 5). */
    paoAgent?: AgentRecord;
    /** Ключ, которым подписано обращение (РП23): в запись отказа агента от полномочий (РП38 п. 3). */
    paoKid?: string;
  }
}

/**
 * Все значения заголовка по сырым заголовкам (РП62 п. 6): req.headers склеивает повтор через «, ». По rawHeaders, а не
 * headersDistinct — его нет у запроса light-my-request (inject), а сырые пары есть и там, и у Node.
 */
function headerValues(req: FastifyRequest, name: string): string[] {
  const raw = req.raw.rawHeaders ?? [];
  const values: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) if (raw[i]!.toLowerCase() === name) values.push(raw[i + 1]!);
  return values;
}

/** Методы с телом; у прочих тело — признак подмены (РП62 п. 7). */
const BODY_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH"]);

/** Заголовки для проверки обращения: повтор подписываемого — массивом, Node склеил бы его через «, » (РП62 п. 6). */
function verifyHeaders(req: FastifyRequest): Record<string, string | readonly string[] | undefined> {
  const headers: Record<string, string | readonly string[] | undefined> = { ...req.headers };
  for (const name of SIGNED_HEADERS) {
    const all = headerValues(req, name);
    if (all.length > 1) headers[name] = all;
  }
  return headers;
}

/** У метода без тела пришло тело — Content-Length не 0 или Transfer-Encoding (РП62 п. 7). */
function unexpectedBody(req: FastifyRequest): boolean {
  const cl = req.headers["content-length"];
  return !BODY_METHODS.has(req.method) && ((cl !== undefined && cl !== "0") || req.headers["transfer-encoding"] !== undefined);
}

/** Путь и запрос — как пришли, без декодирования: их подписал агент (ПАО §2). */
function target(req: FastifyRequest): { path: string; query: string } {
  const url = req.raw.url ?? "";
  const q = url.indexOf("?");
  return q < 0 ? { path: url, query: "" } : { path: url.slice(0, q), query: url.slice(q + 1) };
}

/**
 * Первый слой лимита (РП32): по адресу, хук onRequest — до проверки обращения и до чтения тела; неподписанный поток тоже
 * ограничен. Retry-After ставит плагин до выброса метки; 429 — тело ПАО §6. Счётчик — свой у каждой области, где вызвана
 * (шлюз ПАО, обнаружение — РП60 п. 11). Маршруты области — после вызова: хук onRoute плагина видит каждый.
 */
export async function paoCoarseLimit(
  app: FastifyInstance,
  limit: number,
  /** Прочие ошибки области (РП62 п. 1); без него — ответ Fastify. Обработчик ошибок у области один (Fastify 5). */
  otherError?: (err: FastifyError, req: FastifyRequest, reply: FastifyReply) => FastifyReply,
): Promise<void> {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("pao_rate_limit_per_30s — целое ≥ 1");
  await app.register(rateLimit, {
    global: true,
    max: limit,
    timeWindow: PAO_RATE_WINDOW_MS,
    keyGenerator: (req) => rateLimitKey(req.ip),
    errorResponseBuilder: () => RATE_LIMITED,
  });
  app.setErrorHandler((err: FastifyError, req, reply) => {
    if (err === RATE_LIMITED) {
      // Остаток окна плагин считает по Date.now(): при переводе часов назад он больше окна — обрезаем до границы РП24.
      void reply.header("retry-after", String(retryAfterSec(Number(reply.getHeader("retry-after")))));
      return reply.code(429).send(paoError("RATE_LIMITED").body);
    }
    return otherError ? otherError(err, req, reply) : reply.send(err);
  });
}

/**
 * Ошибки области шлюза до обработчика и исключения кода (РП62 п. 1): 413 и 4xx разбора — тело §6 (REQUEST_INVALID при
 * HTTP Fastify у 413, 400 у прочих), 5xx — 503 UPSTREAM_UNAVAILABLE: под ключом 5xx не сохраняется (РП33 п. 6).
 */
function paoTransportFailure(retryAfterSec: number) {
  return (err: FastifyError, req: FastifyRequest, reply: FastifyReply): FastifyReply => {
    const status = err.statusCode;
    if (status !== undefined && status >= 400 && status < 500) {
      const e = paoTransportError(status === 413 ? 413 : 400);
      logTransportReject(req, { reject: err.code ?? "UNKNOWN", status: e.http, pao_code: e.body.code });
      return reply.code(e.http).send(e.body);
    }
    const e = paoError("UPSTREAM_UNAVAILABLE");
    logTransportReject(req, { reject: "UNHANDLED", status: e.http, pao_code: e.body.code, err });
    return reply.code(e.http).header("retry-after", String(retryAfterSec)).send(e.body);
  };
}

/**
 * Нет маршрута в области /pao (РП62 п. 1): 404 с телом §6 (REQUEST_INVALID до ПАО 1.5.0) под грубым лимитом по адресу —
 * свой счётчик, тот же предел (как обнаружение, РП60 п. 11); несуществующие пути лимит не обходят (аудит К4.3 № 6).
 * Регистрируется с префиксом /pao: обработчик «не найдено» Fastify действует по префиксу контекста. Лимит и ответ — в
 * onRequest, до разбора тела (КТ1 № 1): тело несуществующего пути не читается — иначе ошибка разбора отвечала бы мимо
 * счётчика, а предел тела у контекста 404 — серверный 1 МиБ (Fastify 5.12, context.js), не предел области.
 */
export async function paoNotFound(app: FastifyInstance, deps: Pick<PaoDeps, "params">): Promise<void> {
  await paoCoarseLimit(app, deps.params.pao_rate_limit_per_30s, paoTransportFailure(deps.params.unavailable_retry_after_sec));
  const notFound = (req: FastifyRequest, reply: FastifyReply): FastifyReply => {
    const e = paoTransportError(404);
    logTransportReject(req, { reject: "NOT_FOUND", status: e.http, pao_code: e.body.code });
    return reply.code(e.http).send(e.body);
  };
  // Хуки контекста без маршрутов действуют только на его 404; порядок — лимит, затем ответ.
  app.addHook("onRequest", app.rateLimit());
  app.addHook("onRequest", async (req, reply) => notFound(req, reply));
  app.setNotFoundHandler(notFound);
}

export async function paoRoutes(app: FastifyInstance, deps: PaoDeps): Promise<void> {
  // Предел обработчика с таймаутом базы — меньше аренды ключа (РП33 доп. п. 8).
  assertHandlerBudget(PAO_HANDLER_BUDGET_MS, PAO_DB_TIMEOUT_MS, PAO_IDEMPOTENCY_LEASE_MS);
  const clock = deps.clock ?? (() => performance.now());
  await paoCoarseLimit(app, deps.params.pao_rate_limit_per_30s, paoTransportFailure(deps.params.unavailable_retry_after_sec));
  // Порядок значений держит «вне таблицы — L1, строжайший» (РП63 доп. 1): параметры в обход загрузчика — тот же отказ.
  const problems = agentRateLimitProblems(deps.params);
  if (problems.length > 0) throw new Error(problems.join("; "));
  // Второй слой (РП63 п. 1–7): по коду агента после верной подписи, окно 30 с, предел — половина минутного. Через
  // createRateLimit, а не app.rateLimit(): хук плагина отмечает запрос после первого слоя и второй пропустил бы; ответ —
  // свой, своих заголовков x-ratelimit-* второй слой не ставит (п. 2). Хранилище — своё, не общее с первым слоем.
  // cache в типах CreateRateLimitOptions 11.2.0 не объявлен, но дочернее хранилище его читает (LocalStore.child).
  // skipOnError, allowList и ban — явно (РП63 доп. 3): иначе наследуются от настроек первого слоя (mergeParams плагина),
  // и fail-open первого слоя молча стал бы fail-open второго. groupId берётся из config.rateLimit маршрута — у маршрутов
  // ПАО его нет.
  const agentLimitOpts: CreateRateLimitOptions & { readonly cache: number; readonly ban: number } = {
    keyGenerator: (req) => (req.paoAgent as AgentRecord).agent_code,
    max: (req) => agentRateLimitPerMin(deps.params, (req.paoAgent as AgentRecord).level).perMin / 2,
    timeWindow: PAO_RATE_WINDOW_MS,
    cache: AGENT_RATE_CACHE,
    skipOnError: false,
    allowList: [],
    ban: -1,
  };
  const agentLimit = app.createRateLimit(agentLimitOpts);
  // Запись «уровень вне таблицы» — один раз на пару (agent_code, уровень) в процессе, а не на каждое обращение (РП63 доп. 6
  // п. 8; КТ1 PS-05б ч. 4 № 12). Пар не больше записей реестра: второй слой — после предпроверки, неизвестный агент получает
  // 401 до него. При переполнении множество очищается, и запись появится снова — допустимо.
  const warnedLevels = new Set<string>();
  // Тело — строкой, как подписано: content-digest считается от байтов, а не от разобранного JSON. Любой тип содержимого —
  // строкой (UTF-8): тело с чужим типом доходит до проверки обращения и схемы и получает ответ ПАО §6, а не 415 Fastify.
  // Тело больше PAO_BODY_LIMIT_BYTES (413) и неразборный Content-Type — тоже §6, обработчиком ошибок области (РП62 п. 1, 4).
  const asString = (_req: FastifyRequest, body: string | Buffer, done: (err: null, body: string) => void) =>
    done(null, String(body));
  const parse = { parseAs: "string", bodyLimit: PAO_BODY_LIMIT_BYTES } as const;
  app.addContentTypeParser("application/json", parse, asString);
  app.addContentTypeParser("*", parse, asString);

  const send = (reply: FastifyReply, e: PaoErrorReply): FastifyReply => {
    // ПАО §2: Retry-After и с ответами 503 — из стендовых параметров (РП24).
    if (e.http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
    return reply.code(e.http).send(e.body);
  };

  /** Отказ проверки обращения агенту; сбой источника — в журнал процесса, не в ответ (повторный аудит PS-04 №4). */
  const authFail = (req: FastifyRequest, reply: FastifyReply, r: Extract<PaoAuthResult, { ok: false }>): FastifyReply => {
    // Исключение — только имя, код, стек (РП62 доп. 2): detail и where PostgreSQL могут нести значения запроса.
    if (r.cause !== undefined) req.log.error({ err: errFields(r.cause) }, "ПАО: сбой источника (реестр, ключи, хранилище nonce) при проверке обращения");
    return send(reply, paoError(r.code, r.norm));
  };

  // Предпроверка до чтения тела (РП63 п. 9–10; задел № 12): HEAD, %, повтор заголовков, агент в реестре, тело у метода
  // без тела. Хуком onRequest маршрута, а не области: хук области шёл бы раньше хука лимита плагина (тот ставится на
  // маршрут через onRoute), и неподписанный поток читал бы реестр без лимита (РП32 п. 1). Этот onRoute — после плагина,
  // поэтому на маршруте порядок «лимит → предпроверка».
  const precheck = async (req: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
    // HEAD — 404 по §6, как нет маршрута (РП62 п. 8). Проверкой метода, а не exposeHeadRoute из onRoute: Fastify 5.12
    // решает о HEAD-маршруте до хуков onRoute (lib/route.js). Лимит к этому моменту посчитан хуком маршрута.
    if (req.method === "HEAD") {
      const e = paoTransportError(404);
      logTransportReject(req, { reject: "NOT_FOUND", status: e.http, pao_code: e.body.code });
      return reply.code(e.http).send(e.body);
    }
    const { path, query } = target(req);
    // Кодирование в пути ПАО не нужно ни одному идентификатору, а маршрутизатор путь декодирует: /pao/v1/%61gent вёл бы в
    // /pao/v1/agent по подписи над другим путём (РП62 п. 8).
    if (path.includes("%")) return send(reply, paoError("REQUEST_INVALID"));
    const r = await deps.verifier.precheck({ method: req.method, path, query, headers: verifyHeaders(req), unexpectedBody: unexpectedBody(req) });
    return r ? authFail(req, reply, r) : undefined;
  };
  app.addHook("onRoute", (route) => {
    const own = route.onRequest === undefined ? [] : Array.isArray(route.onRequest) ? route.onRequest : [route.onRequest];
    route.onRequest = [...own, precheck];
  });

  app.addHook("preHandler", async (req, reply) => {
    const { path, query } = target(req);
    const body = typeof req.body === "string" ? req.body : "";
    const r = await deps.verifier.verify({
      method: req.method,
      path,
      query,
      headers: verifyHeaders(req),
      body,
      unexpectedBody: unexpectedBody(req),
    });
    if (!r.ok) return authFail(req, reply, r);
    req.paoAgent = r.agent;
    req.paoKid = r.kid;
    // Второй слой — только после верной подписи: чужой x-agent-code квоту агента не тратит (РП63 п. 1, инвариант 5).
    const level = agentRateLimitPerMin(deps.params, r.agent.level);
    const warnKey = `${r.agent.agent_code}\u0000${String(r.agent.level)}`;
    if (!level.inTable && !warnedLevels.has(warnKey)) {
      if (warnedLevels.size >= AGENT_RATE_CACHE) warnedLevels.clear();
      warnedLevels.add(warnKey);
      // agent_level, а не level: level — уровень самой записи pino, поле затёрло бы его.
      req.log.warn({ agent_code: r.agent.agent_code, agent_level: r.agent.level }, "ПАО: уровень агента вне таблицы лимита — предел L1");
    }
    const limit = await agentLimit(req);
    if (!limit.isAllowed && limit.isExceeded) {
      void reply.header("retry-after", String(retryAfterSec(limit.ttlInSeconds)));
      return reply.code(429).send(paoError("RATE_LIMITED").body);
    }
  });

  // Свой статус, класс, уровень, действующие ключи — из реестра (ПАО §3, A2, ПС01); rate_limit_per_min — предел второго
  // слоя для уровня агента, тот, что применяется (РП63 п. 6).
  app.get("/pao/v1/agent", async (req): Promise<AgentSelf> => {
    const agent = req.paoAgent as AgentRecord;
    return {
      agent_code: agent.agent_code,
      operator: agent.operator,
      class: agent.class,
      level: agent.level,
      status: agent.status,
      keys: (await deps.keys.list(agent.agent_code)).filter((k) => k.status === "ACTIVE"),
      rate_limit_per_min: agentRateLimitPerMin(deps.params, agent.level).perMin,
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
    // Два Idempotency-Key — неоднозначность: Node склеил бы их в ключ «a, b» (РП62 п. 6).
    if (headerValues(req, "idempotency-key").length > 1) return send(reply, paoError("REQUEST_INVALID"));
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
      // Текст исключения в журнал не идёт (РП64 п. 9): предел — полем.
      if (err instanceof PaoHandlerDeadline) {
        req.log.warn({ agent_code: agent.agent_code, budget_ms: err.budgetMs }, "ПАО: обработчик дольше предела — запись не начата");
      }
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
    mutating(req, reply, keyRegistrationBody, async (agent, input) => {
      try {
        // Свой действующий ключ повторно — тот же Key, 201 (РП23 доп. 7): повтор после потерянного ответа.
        const added = await deps.keys.register(agent.agent_code, input, { requireActive: true });
        const key = (await deps.keys.list(agent.agent_code)).find((k) => k.kid === added.kid);
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

  // Отзыв своего ключа (ПАО §3, A2 п. 5.4; РП23 п. 5, доп. 3; РП60 п. 1–4): любой свой, в том числе последний и тот, которым
  // подписан сам запрос; повторный — тот же Key. Чужой, неизвестный и не по форме kid — один ответ 422 KEY_INVALID (РП60 п. 2).
  // Приостановленному — можно, исключённому — 403 на проверке обращения (РП60 п. 3). Действует на следующую проверку подписи.
  app.post<{ Params: { kid: string } }>("/pao/v1/agent/keys/:kid/revoke", async (req, reply) => {
    const kid = req.params.kid;
    return mutating(req, reply, emptyBody, async (agent) => {
      // Признак — в журнал процесса (РП60 доп. 3): чужой и неизвестный kid по форме — как есть, не по форме — только длина.
      const notFound = (fields: Record<string, unknown>) => {
        req.log.info({ agent_code: agent.agent_code, ...fields }, "ПАО: отзыв — у агента нет такого ключа (РП60 п. 2)");
        return reply4xx(paoError("KEY_INVALID", "A2 п. 5.4"));
      };
      if (!KID_FORM.test(kid)) return notFound({ reason: "MALFORMED", kid_length: kid.length });
      try {
        await deps.keys.revoke(agent.agent_code, kid);
      } catch (err) {
        if (err instanceof KeyNotFoundError) return notFound({ reason: err.reason, kid });
        throw err;
      }
      const key = (await deps.keys.list(agent.agent_code)).find((k) => k.kid === kid);
      if (!key) throw new Error("ПАО: ключ после отзыва не найден");
      req.log.info({ agent_code: agent.agent_code, kid, self: kid === req.paoKid }, "ПАО: агент отозвал свой ключ");
      return { status: 200, body: key };
    });
  });

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
        // Причина — кодом, не текстом исключения: в message ConsentKeyReused — mandate_id без маски (КТ1 PS-05в ч. 1 № 3,
        // РП61 нюанс 3).
        else req.log.info({ agent_code: agent.agent_code, reason: (err as { reason?: unknown }).reason ?? (err as Error).name }, "ПАО: мандат не записан");
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
        return { status: 200, body: await subscriptions.set(agent.agent_code, { url: form.url, events: input.events }) };
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

  // Знак готовности продавца агенту (ПАО §4; РП57 п. 3–4): только через ПАО — зону агент берёт из записи Платформы, а не
  // со слов витрины. Без причины приостановления; неизвестный продавец — NONE; no-store — ответ личный. SUSPENDED/EXCLUDED
  // — 403 до обработчика. В agent-protocol.yaml пути нет до ПАО 1.5.0 (контрактный тест фиксирует отсутствие).
  const readiness = deps.readiness;
  if (readiness) {
    app.get<{ Params: { merchant_id: string } }>("/pao/v1/merchants/:merchant_id/readiness", async (req, reply) => {
      const agent = req.paoAgent as AgentRecord;
      const merchant_id = req.params.merchant_id;
      if (!isMerchantId(merchant_id)) return send(reply, paoError("REQUEST_INVALID", "ПАО §3"));
      try {
        const view = publicReadiness(await readiness.current(merchant_id));
        return reply.code(200).header("cache-control", "no-store").send(view);
      } catch (err) {
        req.log.error({ err, agent_code: agent.agent_code, merchant_id }, "ПАО: знак готовности продавца не прочитан");
        return send(reply, paoError("STATE_UNAVAILABLE", "A3 п. 4.5"));
      }
    });
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
