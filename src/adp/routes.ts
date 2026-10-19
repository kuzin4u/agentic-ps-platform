// ПИ-1 POST /adp/v1/decide (РП43 п. 1, 3, 8, доп. п. 20): BYPASS — по двум полям тела до любой другой проверки;
// агентским — решение ADP (200 с согласованной парой, РП19), некорректное сообщение — 400, иначе — 503 без решения:
// процессинг ставит ADP_UNAVAILABLE. В режиме «только BYPASS» (ready: false) агентским — 503.
// До SEC-1 маршрут подключают только стенд и тесты, не main.ts (доп. РП43 п. 21).
import type { FastifyInstance } from "fastify";
import type { CanonicalMessage, Decision } from "../shared/canonical.generated.js";
import { parseDecision } from "../shared/codes.js";
import { AdpRequestInvalid, isBypass, type Adp } from "./decide.js";

export interface AdpDeps {
  /** Точка решения; в режиме «только BYPASS» её нет — хранилища не подтверждены самопроверкой. */
  readonly adp?: Adp;
}

const BYPASS: Decision = Object.freeze({ decision: "BYPASS", reason: null, decided_in_ms: 0 });
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export async function adpRoutes(app: FastifyInstance, deps: AdpDeps): Promise<void> {
  app.post("/adp/v1/decide", async (req, reply) => {
    const body = req.body;
    // Тело не объект и вид инструмента не прочитать — неагентской её не признать: 400 (у процессинга — ADP_UNAVAILABLE).
    if (!isObject(body) || !isObject(body.instrument)) return reply.code(400).send({});
    const msg = body as unknown as CanonicalMessage;
    if (isBypass(msg)) return BYPASS;
    const adp = deps.adp;
    if (!adp) return reply.code(503).send({});
    if (msg.msg_type !== "AUTH_REQUEST") return reply.code(400).send({});
    let d: Decision;
    try {
      d = await adp.decide(msg);
    } catch (e) {
      if (e instanceof AdpRequestInvalid) return reply.code(400).send({});
      req.log.error({ err: e, op_ref: msg.op_ref }, "ADP: решение не принято — 503, у процессинга ADP_UNAVAILABLE");
      return reply.code(503).send({});
    }
    // Несогласованная пара не уходит процессингу: это дефект, а не решение (РП19 п. 3).
    try {
      parseDecision(d, "adp");
    } catch (e) {
      req.log.error({ err: e, op_ref: msg.op_ref }, "ADP: несогласованная пара — 503");
      return reply.code(503).send({});
    }
    return d;
  });
}
