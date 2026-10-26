// П10 API для продавцов и площадок, ч. 1 (РП56): каталог ключей агентов и статус агента — без подписи и без входа.
// Каталог — только своего контура ключей (РП56 п. 2); сбой реестра — 503, а не пустой каталог: пустой продавец
// закешировал бы как «все ключи отозваны» (инвариант 3). Ч. 2 (РП57 п. 3): статус знака готовности продавца; подаёт знак
// и присылает метаданные пакета эквайрер по ПИ-8, а не продавец по этому API.
import type { FastifyInstance, FastifyReply } from "fastify";
import type { AgentJwks } from "../registry/jwks.js";
import type { AgentRecord, Contour } from "../registry/model.js";
import { isAgentCode } from "../registry/code.js";
import type { Params } from "../shared/config.js";
import { publicReadiness, type ReadinessStore } from "./readiness.js";
import { isMerchantId } from "./trusted.js";

export interface MerchantApiDeps {
  readonly registry: { get(agent_code: string): Promise<AgentRecord | undefined> };
  readonly keys: { jwks(contour: Contour): Promise<AgentJwks> };
  /** Контур ключей сервера: среды dev и sandbox — sandbox (РП56 п. 2). */
  readonly contour: Contour;
  readonly params: Pick<Params, "merchant_jwks_max_age_sec" | "merchant_readiness_max_age_sec" | "unavailable_retry_after_sec">;
  /** Знак готовности (РП57 п. 3); без хранилища адреса знака нет. */
  readonly readiness?: Pick<ReadinessStore, "current">;
}

/** Адрес каталога (РП56 п. 1). */
export const AGENT_KEYS_PATH = "/.well-known/agent-keys";
export const JWK_SET_CONTENT_TYPE = "application/jwk-set+json";
/** Статус агента для продавца (РП56 п. 4). */
export const AGENT_STATUS_PATH = "/merchants/v1/agents/:code";
/** Статус знака готовности продавца (РП57 п. 3). */
export const MERCHANT_READINESS_PATH = "/merchants/v1/merchants/:id/readiness";
/**
 * Retry-After в режиме «только BYPASS» (уточнение РП56 по № 42): параметры могли не загрузиться, а сам режим снимается
 * только перезапуском — верхняя граница РП24.
 */
export const BYPASS_RETRY_AFTER_SEC = 30;

/**
 * Режим «только BYPASS» (РП43 п. 8; уточнение РП56 по № 42, РП57 п. 3): все адреса — 503 UPSTREAM_UNAVAILABLE с
 * Retry-After и без Cache-Control, а не 404: 404 продавец закешировал бы как «каталога нет» дольше, чем сбой.
 */
export async function merchantApiUnavailable(app: FastifyInstance): Promise<void> {
  const unavailable = async (_req: unknown, reply: FastifyReply) =>
    reply.code(503).header("retry-after", String(BYPASS_RETRY_AFTER_SEC)).send({ code: "UPSTREAM_UNAVAILABLE" });
  app.get(AGENT_KEYS_PATH, unavailable);
  app.get(AGENT_STATUS_PATH, unavailable);
  app.get(MERCHANT_READINESS_PATH, unavailable);
}

/**
 * Статус агента для продавца и эквайрера (РП56 п. 4, РП57 п. 6): только код, статус и класс из реестра. Неизвестный, не по
 * форме и чужого контура — undefined (один ответ 404); сбой реестра — отклонённое обещание (503).
 */
export async function agentStatusView(
  deps: Pick<MerchantApiDeps, "registry" | "contour">,
  code: string,
): Promise<{ agent_code: string; status: AgentRecord["status"]; class: AgentRecord["class"] } | undefined> {
  if (!isAgentCode(code)) return undefined;
  const rec = await deps.registry.get(code);
  if (!rec || rec.contour !== deps.contour) return undefined;
  return { agent_code: rec.agent_code, status: rec.status, class: rec.class };
}

export async function merchantApiRoutes(app: FastifyInstance, deps: MerchantApiDeps): Promise<void> {
  const unavailable = (reply: FastifyReply) =>
    reply.code(503).header("retry-after", String(deps.params.unavailable_retry_after_sec)).send({ code: "UPSTREAM_UNAVAILABLE" });
  // Отказы Fastify до обработчика — тело `{code}`, как у ПИ-8.
  app.setErrorHandler((err: { statusCode?: number }, _req, reply) => {
    const http = err.statusCode ?? 500;
    if (http >= 400 && http < 500) return reply.code(400).send({ code: "REQUEST_INVALID" });
    return unavailable(reply);
  });

  app.get(AGENT_KEYS_PATH, async (req, reply) => {
    let jwks: AgentJwks;
    try {
      jwks = await deps.keys.jwks(deps.contour);
    } catch (e) {
      req.log.error({ err: e }, "API продавцов: каталог ключей агентов недоступен");
      return unavailable(reply);
    }
    return reply
      .header("content-type", JWK_SET_CONTENT_TYPE)
      .header("cache-control", `public, max-age=${deps.params.merchant_jwks_max_age_sec}`)
      // Байтами: у строки Fastify дописал бы `; charset=utf-8`, а у application/jwk-set+json параметров нет (RFC 7517 §8.5).
      .send(Buffer.from(JSON.stringify(jwks)));
  });

  // Статус агента (РП56 п. 4): только код, статус и класс из реестра; сведений об операторе и принципалах нет (A2 п. 1.2).
  // Неизвестный, не по форме и чужого контура — один ответ 404: продавец не отличает «нет» от «не в этом контуре».
  app.get<{ Params: { code: string } }>(AGENT_STATUS_PATH, async (req, reply) => {
    let view: Awaited<ReturnType<typeof agentStatusView>>;
    try {
      view = await agentStatusView(deps, req.params.code);
    } catch (e) {
      req.log.error({ err: e }, "API продавцов: реестр агентов недоступен");
      return unavailable(reply);
    }
    return view ?? reply.code(404).send({ code: "AGENT_UNKNOWN" });
  });

  // Знак готовности продавца (РП57 п. 3): открытое сведение, без подписи; причины приостановления нет. Неизвестный
  // продавец — NONE, а не 404: перечни эквайреров не раскрываются. Кэш — свой параметр, а не срок каталога ключей.
  const readiness = deps.readiness;
  if (readiness) {
    app.get<{ Params: { id: string } }>(MERCHANT_READINESS_PATH, async (req, reply) => {
      const merchant_id = req.params.id;
      if (!isMerchantId(merchant_id)) return reply.code(400).send({ code: "REQUEST_INVALID" });
      let view;
      try {
        view = publicReadiness(await readiness.current(merchant_id));
      } catch (e) {
        req.log.error({ err: e, merchant_id }, "API продавцов: хранилище знака готовности недоступно");
        return unavailable(reply);
      }
      return reply.header("cache-control", `public, max-age=${deps.params.merchant_readiness_max_age_sec}`).send(view);
    });
  }
}
