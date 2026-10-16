// П9 Маршруты ПАО (AGENT-PROTOCOL.md §3). Каждое обращение проверяется до обработчика: агент → подпись → статус (РП23 п. 6).
// Изменяющий метод затем: Idempotency-Key → тело по схеме (REQUEST_INVALID) → захват ключа → обработчик (РП30 п. 3, РП31).
// /revoke — в PS-05 часть 3.
import { IdempotencyConflict, IdempotencyInProgress } from "@kuzin4u/agentic-core";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AgentExcludedError, AgentNotActiveError, KeyInvalidError, type AgentKeys } from "../registry/agent-keys.js";
import { toPaoKey } from "../registry/keys.js";
import type { AgentRecord } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import type { AgentSelf } from "../shared/pao.js";
import { keyRegistrationBody } from "./body.js";
import { paoError, type PaoErrorReply } from "./errors.js";
import { idempotencyKeyHash, type PaoIdempotency, type PaoReply } from "./idempotency.js";
import type { PaoRequestVerifier } from "./verify.js";

export interface PaoDeps {
  readonly verifier: PaoRequestVerifier;
  readonly keys: AgentKeys;
  readonly idempotency: PaoIdempotency;
  readonly params: Pick<Params, "unavailable_retry_after_sec">;
}

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
   * Ответ обработчика (2xx, 4xx) сохраняется; исключение обработчика — 503, захват снимает ядро, повтор исполняется заново.
   */
  async function mutating<T>(
    req: FastifyRequest,
    reply: FastifyReply,
    parse: (raw: string) => T | undefined,
    handler: (agent: AgentRecord, input: T) => PaoReply,
  ): Promise<FastifyReply> {
    const agent = req.paoAgent as AgentRecord;
    const key = req.headers["idempotency-key"];
    if (typeof key !== "string" || key === "") return send(reply, paoError("IDEMPOTENCY_REQUIRED"));
    const raw = typeof req.body === "string" ? req.body : "";
    const input = parse(raw);
    if (input === undefined) return send(reply, paoError("REQUEST_INVALID"));
    const { path, query } = target(req);
    let r: PaoReply;
    try {
      r = (
        await deps.idempotency(agent.agent_code).run(
          idempotencyKeyHash(key),
          { method: req.method, path, query, body: raw },
          async () => {
            const out = handler(agent, input);
            // 5xx не сохраняется (РП30 п. 3): исключение снимает захват, повтор исполняется заново.
            if (out.status >= 500) throw new Error(`ПАО: обработчик вернул ${out.status}`);
            return out;
          },
        )
      ).result;
    } catch (err) {
      if (err instanceof IdempotencyConflict) return send(reply, paoError("IDEMPOTENCY_CONFLICT"));
      // Тот же ключ ещё выполняется — 503 same_key (РП30 п. 3); сбой хранилища или обработчика — 503 и журнал процесса.
      if (!(err instanceof IdempotencyInProgress)) req.log.error({ err }, "ПАО: сбой хранилища идемпотентности или обработчика");
      return send(reply, paoError("UPSTREAM_UNAVAILABLE"));
    }
    return reply.code(r.status).send(r.body);
  }

  // Регистрация своего ключа (ПАО §3, A2 п. 5.3, РП23 п. 2–4): срок и перекрытие — в реестре; причина отказа агенту
  // не раскрывается (РП31 п. 2) — она в журнале процесса. Только ACTIVE: смена ключа приостановленным — через оператора (PS-31).
  app.post("/pao/v1/agent/keys", async (req, reply) =>
    mutating(req, reply, keyRegistrationBody, (agent, input) => {
      try {
        const added = deps.keys.register(agent.agent_code, input, { requireActive: true });
        return { status: 201, body: toPaoKey(added, new Date(added.valid_from)) };
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
}

const reply4xx = (e: PaoErrorReply): PaoReply => ({ status: e.http, body: e.body });
