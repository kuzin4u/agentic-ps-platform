// ПС01 · позитив · П1 · Допуск оператора агента и выдача ключа (A2 п. 3–5, ФП1, РП21, РП23).
// Сертификат mTLS из ожидаемого результата — SEC-1 (joint-plan); остальное — здесь.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const CODE = "nspk:agent:buyref-01:v3";
const OPERATOR = "buyref-operator";

describe("ПС01: допуск оператора агента и выдача ключа", () => {
  let s: Stand;
  let side: AgentSide;

  beforeEach(() => {
    s = stand();
    side = newAgentSide();
  });
  afterEach(async () => {
    await s.app.close();
  });

  const admit = () => s.registry.admit(buyerApplication(CODE, side), { contour: "sandbox", operator: OPERATOR });

  it("заявление оператора BuyerAgent → решение о допуске: код, класс BUYER, уровень 1, ключ, ACTIVE", () => {
    const d = admit();
    expect(d).toMatchObject({
      admitted: true,
      record: { agent_code: CODE, issuer: "nspk:agent", class: "BUYER", level: 1, status: "ACTIVE", operator: OPERATOR },
      key: { kid: side.kid, alg: "ed25519", public_key: side.publicKey, revoked_at: null },
    });
  });

  it("GET /pao/v1/agent возвращает статус, класс, уровень, ключи из реестра и предел частоты по уровню", async () => {
    admit();
    const res = await signedInject(s.app, side, CODE);
    expect(res.statusCode).toBe(200);
    const self = res.json();
    expect(self).toEqual({
      agent_code: CODE,
      operator: OPERATOR,
      class: "BUYER",
      level: 1,
      status: "ACTIVE",
      keys: [
        {
          kid: side.kid,
          alg: "ed25519",
          public_key: side.publicKey,
          valid_from: expect.any(String),
          valid_to: expect.any(String),
          status: "ACTIVE",
        },
      ],
      // Предел второго слоя для уровня 1 — из параметров стенда (РП63 п. 6).
      rate_limit_per_min: s.params.pao_agent_rate_limit_per_min_l1,
    });
    const days = (Date.parse(self.keys[0].valid_to) - Date.parse(self.keys[0].valid_from)) / 86_400_000;
    expect(days).toBe(s.params.key_ttl_days);
  });

  it("класс и уровень в строке запроса и заголовках игнорируются — только реестр (инвариант 5)", async () => {
    admit();
    const res = await signedInject(s.app, side, CODE, {
      query: "class=SELLER&level=9&status=ACTIVE",
      headers: { "x-agent-class": "SELLER", "x-agent-level": "9" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ class: "BUYER", level: 1 });
  });

  it("статус — из реестра в момент обращения: приостановление видно сразу", async () => {
    admit();
    s.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" });
    const res = await signedInject(s.app, side, CODE);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: "SUSPENDED" });
  });

  it("без подписи — 401 по ПАО §6, тело только code/message/norm/retry", async () => {
    admit();
    const res = await s.app.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": CODE } });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({
      code: "SIGNATURE_INVALID",
      message: expect.any(String),
      norm: "A2 п. 5.1",
      retry: "after_fix",
    });
  });

  it("/health не требует подписи", async () => {
    expect((await s.app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
  });

  it("класс и уровень в теле запроса игнорируются: POST /pao/v1/agent/keys, затем GET /pao/v1/agent — из реестра (инвариант 5)", async () => {
    admit();
    const next = newAgentSide();
    const res = await signedInject(s.app, side, CODE, {
      method: "POST",
      path: "/pao/v1/agent/keys",
      body: JSON.stringify({ alg: "ed25519", public_key: next.publicKey, class: "OPERATOR", level: 3, status: "ACTIVE" }),
      headers: { "idempotency-key": "ps01-class" },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).not.toHaveProperty("class");
    const self = (await signedInject(s.app, next, CODE)).json();
    expect(self).toMatchObject({ class: "BUYER", level: 1, status: "ACTIVE" });
    expect(s.registry.get(CODE)).toMatchObject({ class: "BUYER", level: 1 });
  });
  it.todo("сертификат mTLS, связанный с agent_code, выдаётся при допуске — РП27, PS-05");
});
