// GET /.well-known/pao-configuration (PS-05б ч. 1, РП60 п. 9–13): строго по схеме Configuration ПАО 1.4.0, без подписи,
// грубый лимит по адресу — свой счётчик, Cache-Control: no-cache; стенд и рабочая сборка — та же функция buildServer.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { parse } from "yaml";
import { PAO_CONFIGURATION_PATH, paoConfiguration } from "../../src/pao/configuration.js";
import { paoIdempotency } from "../../src/pao/idempotency.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { memoryConsent } from "../support/consent.js";
import { coarseLimit } from "../support/rate-limit.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8"), { maxAliasCount: -1 });
const EXPECTED = { versions: ["1.4.0"], sunset: {}, platform_keys: [], algorithms: ["ed25519"] };

describe("GET /.well-known/pao-configuration на стенде (РП60 п. 9, 11, 13)", () => {
  let s: Stand | undefined;
  afterEach(async () => {
    await s?.app.close();
  });

  it("без подписи → 200, ровно versions / sunset / platform_keys / algorithms, Cache-Control: no-cache", async () => {
    s = stand();
    const res = await s.app.inject({ method: "GET", url: PAO_CONFIGURATION_PATH });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-cache");
    expect(res.json()).toEqual(EXPECTED);
  });

  it("подписанное обращение агента — тот же ответ: проверка обращения ПАО к методу не относится", async () => {
    s = stand();
    const a = newAgentSide();
    expect(s.admit(buyerApplication("nspk:agent:buyref-01:v3", a), "op").admitted).toBe(true);
    const res = await signedInject(s.app, a, "nspk:agent:buyref-01:v3", { path: PAO_CONFIGURATION_PATH });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(EXPECTED);
  });
});

describe("GET /.well-known/pao-configuration — схема ПАО 1.4.0 (РП60 п. 9)", () => {
  const schema = pao.components.schemas.Configuration;

  it("поля ответа — только из схемы; versions — полная версия info.version, не v1", () => {
    const body = paoConfiguration("sandbox");
    for (const k of Object.keys(body)) expect(Object.keys(schema.properties)).toContain(k);
    expect(body).not.toHaveProperty("endpoints");
    expect(body.versions).toEqual([pao.info.version]);
    for (const alg of body.algorithms ?? []) expect(schema.properties.algorithms.items.enum).toContain(alg);
  });

  it("контур оператора — algorithms пусто: ГОСТ — после точки расширения РП5", () => {
    expect(paoConfiguration("operator").algorithms).toEqual([]);
  });

  it("путь объявлен в YAML: только 200 со ссылкой на Configuration", () => {
    const op = pao.paths[PAO_CONFIGURATION_PATH].get;
    expect(Object.keys(op.responses)).toEqual(["200"]);
    expect(op.responses["200"].content["application/json"].schema.$ref).toBe("#/components/schemas/Configuration");
  });
});

describe("GET /.well-known/pao-configuration в buildServer (рабочая сборка, РП60 п. 11, 13)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  it("без paoConfiguration — маршрута нет (404)", async () => {
    app = buildServer({ env: "dev" });
    expect((await app.inject({ method: "GET", url: PAO_CONFIGURATION_PATH })).statusCode).toBe(404);
  });

  it("грубый лимит по адресу — свой счётчик: сверх предела 429 RATE_LIMITED по ПАО §6 с Retry-After", async () => {
    const params = { ...loadParams(), pao_rate_limit_per_30s: 2 };
    app = buildServer({ env: "dev", paoConfiguration: { contour: "sandbox", params } });
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) codes.push((await app.inject({ method: "GET", url: PAO_CONFIGURATION_PATH })).statusCode);
    expect(codes).toEqual([200, 200, 429]);
    const res = await app.inject({ method: "GET", url: PAO_CONFIGURATION_PATH });
    expect(res.json()).toEqual({ code: "RATE_LIMITED", message: expect.any(String), retry: "same_key" });
    expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
    expect(Number(res.headers["retry-after"])).toBeLessThanOrEqual(30);
  });

  it("счётчики конфигурации и шлюза ПАО раздельны: исчерпание одного не даёт 429 другому (РП60 п. 11; остаточный риск v0.26.0)", async () => {
    const params = coarseLimit(2);
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    app = buildServer({
      env: "dev",
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
      paoConfiguration: { contour: "sandbox", params },
    });
    const conf = async () => (await app!.inject({ method: "GET", url: PAO_CONFIGURATION_PATH })).statusCode;
    const gate = async () => (await app!.inject({ method: "GET", url: "/pao/v1/agent" })).statusCode;
    expect([await conf(), await conf(), await conf()]).toEqual([200, 200, 429]);
    // Шлюз — свой счётчик: без подписи 401, а не 429 исчерпанной конфигурации; затем исчерпывается сам.
    expect([await gate(), await gate(), await gate()]).toEqual([401, 401, 429]);
    expect(await conf()).toBe(429);
  });
});
