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
import { A, decide, mk, setup } from "../support/state.js";

const auth = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => ({
  op_ref: "OPKC-ROUTE-1",
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount: 10_000,
  currency: "RUB",
  merchant: { id: "MER-1042" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: A, mandate_id: "mnd_x" },
  ...over,
});
const plain = (): CanonicalMessage => {
  const m = auth();
  delete m.aoi;
  return m;
};

function server() {
  const c = setup();
  const adp = new Adp({
    agents: { get: (code) => (code === A ? { status: "ACTIVE", level: 1 } : undefined) },
    mandates: c.consent,
    state: c.state,
    operations: new MemoryOperationStore(),
    params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000 },
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
    const res = await post(app, auth({ aoi: { indicator: true, agent_code: A, mandate_id: m.id } }));
    expect(res.statusCode).toBe(200);
    expect(parseDecision(res.json(), "adp").decision).toBe("APPROVE");
  });

  it("неагентская — 200 BYPASS даже без точки решения (хранилищ нет)", async () => {
    const app = buildServer({ env: "dev", adp: {} });
    const res = await post(app, plain());
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
  it("createStand отдаёт POST /adp/v1/decide: неагентская — BYPASS, неизвестный агент — DECLINE AGENT_UNKNOWN", async () => {
    const stand = createStand();
    try {
      const b = await post(stand.app, plain());
      expect(b.json().decision).toBe("BYPASS");
      const d = await post(stand.app, auth({ aoi: { indicator: true, agent_code: "nspk:agent:nobody:v1", mandate_id: "mnd_x" } }));
      expect(parseDecision(d.json(), "adp")).toEqual({ decision: "DECLINE", reason: "AGENT_UNKNOWN" });
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
