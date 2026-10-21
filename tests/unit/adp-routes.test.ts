// ПИ-1 POST /adp/v1/decide (PS-10 К2.2, РП43 п. 1, 3, 8, доп. п. 20–21): BYPASS по двум полям тела до остальных проверок,
// агентским — решение ADP с согласованной парой, некорректное сообщение — 400, сбой — 503 без решения; стенд отдаёт
// маршрут, main.ts до SEC-1 — нет.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Adp, MemoryOperationStore } from "../../src/adp/index.js";
import { buildServer } from "../../src/server.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { createStand } from "../../src/stand/index.js";
import { agentToken, agentTokenCredentials } from "../support/agent-token.js";
import { A, cartUnder, decide, mk, setup } from "../support/state.js";

/** Как пришло от процессинга; агентская — с AGENT_TOKEN (agentToken, РП48 (а)). */
const raw = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => ({
  op_ref: "OPKC-ROUTE-1",
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount: 10_000,
  currency: "RUB",
  merchant: { id: "MER-1042", mcc: "5462" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: A, mandate_id: "mnd_x" },
  ...over,
});
const auth = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => agentToken(raw(over));
const plain = (): CanonicalMessage => {
  const m = raw();
  delete m.aoi;
  return m;
};

function server() {
  const c = setup();
  const adp = new Adp({
    agents: { get: (code) => (code === A ? { status: "ACTIVE", level: 1 } : undefined) },
    mandates: { get: (id, a) => c.consent.adpMandate(id, a) },
    clientLimits: { get: async () => [] },
    state: c.state,
    operations: new MemoryOperationStore(),
    credentials: agentTokenCredentials,
    params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
  });
  return { c, adp, app: buildServer({ env: "dev", adp: { adp } }) };
}

const post = (app: ReturnType<typeof buildServer>, payload: unknown) =>
  app.inject({ method: "POST", url: "/adp/v1/decide", payload: payload as object });

describe("POST /adp/v1/decide (ПИ-1)", () => {
  it("агентская по действующему мандату — 200 APPROVE с согласованной парой", async () => {
    const { c, app } = server();
    const m = await mk(c);
    await decide(c, m);
    // Агентский токен — только по CART (РП49 (б)).
    const cart = await cartUnder(c, m.id, 50_000);
    const res = await post(app, auth({ aoi: { indicator: true, agent_code: A, mandate_id: cart } }));
    expect(res.statusCode).toBe(200);
    expect(parseDecision(res.json(), "adp").decision).toBe("APPROVE");
  });

  it("неагентская — 200 BYPASS даже без точки решения (хранилищ нет)", async () => {
    const app = buildServer({ env: "dev", adp: {} });
    const res = await post(app, plain());
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ decision: "BYPASS", reason: null, decided_in_ms: 0 });
  });

  it("CARD_TOKEN с aoi.indicator: false без кода и мандата — 200 BYPASS без точки решения (РП49 (в))", async () => {
    const app = buildServer({ env: "dev", adp: {} });
    const res = await post(app, { ...plain(), aoi: { indicator: false } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ decision: "BYPASS", reason: null, decided_in_ms: 0 });
  });

  it("неагентская с некорректной суммой и без msg_type — BYPASS: остальное тело не разбирается (доп. РП43 п. 20)", async () => {
    const app = buildServer({ env: "dev", adp: {} });
    const res = await post(app, { instrument: { kind: "CARD_TOKEN" }, amount: -5 });
    expect(res.json().decision).toBe("BYPASS");
  });

  it("агентская без точки решения — 503 без решения (у процессинга ADP_UNAVAILABLE)", async () => {
    const app = buildServer({ env: "dev", adp: {} });
    const res = await post(app, auth());
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({});
  });

  it.each([
    ["тело не объект", [1, 2]],
    ["без instrument", { op_ref: "x", aoi: { indicator: true } }],
    ["msg_type не AUTH_REQUEST", auth({ msg_type: "REVERSAL" })],
    ["сумма не целое ≥ 1", auth({ amount: 0 })],
    ["валюта не ISO 4217", auth({ currency: "rub" })],
  ])("%s — 400 без решения", async (_n, body) => {
    const { app } = server();
    const res = await post(app, body);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({});
  });

  it.each([
    ["тело не JSON", "application/json", "{не json"],
    ["Content-Type не application/json", "application/xml", "<auth/>"],
  ])("%s — 400 с телом {}, без текста Fastify (/audit PS-10 № 6)", async (_n, type, payload) => {
    const { app } = server();
    const res = await app.inject({ method: "POST", url: "/adp/v1/decide", headers: { "content-type": type }, payload });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({});
  });

  it("сбой точки решения (исключение) — 503, не BYPASS", async () => {
    const { adp, app } = server();
    adp.decide = () => Promise.reject(new Error("неожиданно"));
    expect((await post(app, auth())).statusCode).toBe(503);
  });

  it("несогласованная пара не уходит процессингу — 503 (РП19 п. 3)", async () => {
    const { adp, app } = server();
    adp.decide = async () => ({ decision: "APPROVE", reason: "LIMIT_EXCEEDED", decided_in_ms: 1 });
    expect((await post(app, auth())).statusCode).toBe(503);
  });
});

describe("стенд и main.ts (доп. РП43 п. 21)", () => {
  it("createStand отдаёт POST /adp/v1/decide: неагентская — BYPASS; CARD_TOKEN с признаком и токен не из П5 — DECLINE CREDENTIAL_INVALID", async () => {
    const stand = createStand();
    try {
      const b = await post(stand.app, plain());
      expect(b.json().decision).toBe("BYPASS");
      const card = await post(stand.app, raw({ aoi: { indicator: true, agent_code: "nspk:agent:nobody:v1", mandate_id: "mnd_x" } }));
      expect(parseDecision(card.json(), "adp")).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
      // Токен, которого П5 стенда не выдавал (домен неизвестен), — тоже до реестра (РП47 п. 6).
      const d = await post(stand.app, auth({ op_ref: "OPKC-ROUTE-2", aoi: { indicator: true, agent_code: "nspk:agent:nobody:v1", mandate_id: "mnd_x" } }));
      expect(parseDecision(d.json(), "adp")).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    } finally {
      await stand.close();
    }
  });

  it("main.ts не подключает ADP до SEC-1: открытого порта с правом создавать резервы нет", () => {
    const main = readFileSync(new URL("../../src/main.ts", import.meta.url), "utf8");
    expect(main).not.toMatch(/\badp\s*:/);
    expect(main).not.toMatch(/adp\/|adpRoutes|new Adp\b/);
  });
});
