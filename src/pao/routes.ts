// П9 Маршруты ПАО (AGENT-PROTOCOL.md §3). Каждое обращение проверяется до обработчика: агент → подпись → статус (РП23 п. 6).
// POST /pao/v1/agent/keys и /revoke — в PS-05 вместе с идемпотентностью.
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { AgentKeys } from "../registry/agent-keys.js";
import type { AgentRecord } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import type { AgentSelf } from "../shared/pao.js";
import { paoError } from "./errors.js";
import type { PaoRequestVerifier } from "./verify.js";

export interface PaoDeps {
  readonly verifier: PaoRequestVerifier;
  readonly keys: AgentKeys;
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
  // Тело — строкой, как подписано: content-digest считается от байтов, а не от разобранного JSON.
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => done(null, body));

  app.addHook("preHandler", async (req, reply) => {
    const { path, query } = target(req);
    const body = typeof req.body === "string" ? req.body : "";
    const r = deps.verifier.verify({ method: req.method, path, query, headers: req.headers, body });
    if (!r.ok) {
      const e = paoError(r.code, r.norm);
      // ПАО §2: Retry-After и с ответами 503 — из стендовых параметров (РП24).
      if (e.http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(e.http).send(e.body);
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
}
