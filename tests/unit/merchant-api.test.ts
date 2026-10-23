// РП56 (PS-30 ч. 1): API для продавцов — каталог ключей агентов по адресу и статус агента, без подписи; каталог своего контура.
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  AgentKeys,
  AgentRegistry,
  DEFAULT_KEY_ALGORITHMS,
  ED25519,
  InMemoryAgentRegistryStore,
} from "../../src/registry/index.js";
import { AGENT_KEYS_PATH, JWK_SET_CONTENT_TYPE, type MerchantApiDeps } from "../../src/participants/merchant-api.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { createMerchants, createStand, type MerchantsStand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { letters } from "../support/opaque.js";

const params = loadParams();
const NOW = new Date("2026-10-23T10:00:00Z");
const code = (tag: string): string => `nspk:agent:${tag}-${letters()}:v1`;
const publicKey = (): string =>
  generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");
const application = (agent_code: string, extra: Record<string, unknown> = {}) => ({
  agent_code,
  class: "BUYER",
  model: "buyer-agent-ref",
  runtime: "python-3.12",
  alg: "ed25519",
  public_key: publicKey(),
  ...extra,
});

/** Одно хранилище с агентами обоих контуров; контур оператора — ed25519 вместо ГОСТ до точки расширения РП5. */
function twoContours() {
  const store = new InMemoryAgentRegistryStore();
  const algorithms = { ...DEFAULT_KEY_ALGORITHMS, operator: [ED25519] };
  const opts = { keys: params, now: () => NOW, algorithms };
  const registry = new AgentRegistry(store, opts);
  const keys = new AgentKeys(store, opts);
  const sandbox = code("mapi-sbx");
  const operator = code("mapi-opr");
  expect(registry.admit(application(sandbox), { contour: "sandbox", operator: "op-s" }).admitted).toBe(true);
  expect(
    registry.admit(application(operator, { conformance_run_ref: "RUN-1" }), { contour: "operator", operator: "op-o" }).admitted,
  ).toBe(true);
  return { registry, keys, sandbox, operator };
}

const server = (deps: Partial<MerchantApiDeps> & Pick<MerchantApiDeps, "registry" | "keys">) =>
  buildServer({ env: "dev", merchants: { contour: "sandbox", params, ...deps } });

describe("РП56 п. 2: каталог своего контура", () => {
  it("jwks(contour) — только агенты этого контура", () => {
    const { keys, sandbox, operator } = twoContours();
    expect(keys.jwks("sandbox").keys.map((k) => k.agent_code)).toEqual([sandbox]);
    expect(keys.jwks("operator").keys.map((k) => k.agent_code)).toEqual([operator]);
  });
});

describe("РП56 п. 1: GET /.well-known/agent-keys", () => {
  it("без подписи; jwk-set+json, Cache-Control public, max-age = merchant_jwks_max_age_sec; ключи своего контура", async () => {
    const { registry, keys, sandbox } = twoContours();
    const r = await server({ registry, keys }).inject({ method: "GET", url: AGENT_KEYS_PATH });
    expect(r.statusCode).toBe(200);
    expect(r.headers["content-type"]).toBe(JWK_SET_CONTENT_TYPE);
    expect(r.headers["cache-control"]).toBe(`public, max-age=${params.merchant_jwks_max_age_sec}`);
    expect(r.json()).toEqual(keys.jwks("sandbox"));
    expect(r.json().keys.map((k: { agent_code: string }) => k.agent_code)).toEqual([sandbox]);
  });

  it("сбой реестра — 503 UPSTREAM_UNAVAILABLE с Retry-After, а не пустой каталог (инвариант 3)", async () => {
    const { registry } = twoContours();
    const broken = { jwks: () => { throw new Error("реестр недоступен"); } };
    const r = await server({ registry, keys: broken }).inject({ method: "GET", url: AGENT_KEYS_PATH });
    expect(r.statusCode).toBe(503);
    expect(r.headers["retry-after"]).toBe(String(params.unavailable_retry_after_sec));
    expect(r.headers["cache-control"]).toBeUndefined();
    expect(r.json()).toEqual({ code: "UPSTREAM_UNAVAILABLE" });
  });
});

describe("РП56 п. 4: GET /merchants/v1/agents/{code}", () => {
  const status = (deps: Parameters<typeof server>[0], c: string) =>
    server(deps).inject({ method: "GET", url: `/merchants/v1/agents/${encodeURIComponent(c)}` });

  it("без подписи: только agent_code, status, class — оператора и принципалов нет (A2 п. 1.2)", async () => {
    const { registry, keys, sandbox } = twoContours();
    const r = await status({ registry, keys }, sandbox);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ agent_code: sandbox, status: "ACTIVE", class: "BUYER" });
  });

  it("SUSPENDED и EXCLUDED отдаются статусом, а не 404", async () => {
    const { registry, keys, sandbox } = twoContours();
    registry.changeStatus(sandbox, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    expect((await status({ registry, keys }, sandbox)).json().status).toBe("SUSPENDED");
    registry.changeStatus(sandbox, { to: "EXCLUDED", ground: "WITHDRAWN" });
    expect((await status({ registry, keys }, sandbox)).json().status).toBe("EXCLUDED");
  });

  it("неизвестный, не по форме и агент другого контура — один ответ 404 AGENT_UNKNOWN", async () => {
    const { registry, keys, operator } = twoContours();
    for (const c of [code("mapi-none"), "not-a-code", operator]) {
      const r = await status({ registry, keys }, c);
      expect(r.statusCode).toBe(404);
      expect(r.json()).toEqual({ code: "AGENT_UNKNOWN" });
    }
  });

  it("сбой реестра — 503 UPSTREAM_UNAVAILABLE с Retry-After", async () => {
    const { keys, sandbox } = twoContours();
    const broken = { get: () => { throw new Error("реестр недоступен"); } };
    const r = await status({ registry: broken, keys }, sandbox);
    expect(r.statusCode).toBe(503);
    expect(r.headers["retry-after"]).toBe(String(params.unavailable_retry_after_sec));
    expect(r.json()).toEqual({ code: "UPSTREAM_UNAVAILABLE" });
  });
});

describe("РП56 п. 1–3 на стенде: адрес и витрины — одна функция каталога, срок кэша из параметров", () => {
  let m: MerchantsStand | undefined;
  afterEach(async () => {
    await m?.close();
    m = undefined;
  });

  it("стенд отдаёт каталог и статус по адресам API для продавцов", async () => {
    const s = createStand();
    const a = newAgentSide();
    const A = code("mapi-stand");
    expect(s.admit(buyerApplication(A, a), "op-a").admitted).toBe(true);
    const keysRes = await s.app.inject({ method: "GET", url: AGENT_KEYS_PATH });
    expect(keysRes.json().keys.map((k: { kid: string }) => k.kid)).toEqual([a.kid]);
    const st = await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${A}` });
    expect(st.json()).toEqual({ agent_code: A, status: "ACTIVE", class: "BUYER" });
  });

  it("приостановление: витрина принимает агента до merchant_jwks_max_age_sec из кэша, затем KEY_UNKNOWN", async () => {
    const s = createStand();
    s.setClock(NOW);
    const a = newAgentSide();
    const A = code("mapi-cache");
    expect(s.admit(buyerApplication(A, a), "op-a").admitted).toBe(true);
    m = createMerchants(s);
    const call = () => merchantCall(m!.app, { side: a, agentCode: A, now: s.now(), path: "/v1/shops/SHOP-1042/catalog" });
    expect((await call()).statusCode).toBe(200);
    await s.suspendAgent(A, "KEY_COMPROMISE");
    expect((await s.app.inject({ method: "GET", url: AGENT_KEYS_PATH })).json().keys).toEqual([]);
    const maxAgeMs = s.params.merchant_jwks_max_age_sec * 1000;
    s.setClock(new Date(NOW.getTime() + maxAgeMs - 1));
    expect((await call()).statusCode).toBe(200);
    s.setClock(new Date(NOW.getTime() + maxAgeMs));
    const r = await call();
    expect(r.statusCode).toBe(401);
    expect(r.json().code).toBe("KEY_UNKNOWN");
  });
});
