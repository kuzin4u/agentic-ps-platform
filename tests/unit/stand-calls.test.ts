// Журнал обращений стенда и выданные реквизиты (РП25 дополнение STAND-69, передача агента #69): source ставит стенд по
// типу сокета; kid, x-nonce, Idempotency-Key, code при 4xx / 5xx; тел нет — token_ref и cryptogram в журнале не встречаются
// (инвариант 1); журнал полон с первого обращения без хука в stand.app после createStand.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:stand-calls:v1";

describe("stand.calls() и stand.issuedCredentials() (STAND-69)", () => {
  let stand: Stand;
  let side: AgentSide;
  let base: string;
  beforeAll(async () => {
    stand = createStand();
    // Часы — после начальной подачи знаков: она подписана часами на момент createStand.
    base = await stand.listen();
    stand.setClock(new Date("2026-10-20T09:00:00Z"));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const call = (method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = {}) =>
    signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers,
      now: stand.now(),
    });

  it("журнал полон с первого обращения: подача знаков при старте — inject, без хука после createStand", async () => {
    const seeded = stand.calls().filter((c) => c.path.startsWith("/participants/v1/merchants/") && c.method === "POST");
    expect(seeded.length).toBeGreaterThan(0);
    expect(seeded.every((c) => c.source === "inject" && c.status === 200 && c.code === undefined)).toBe(true);
    expect(base).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it("по сети — network, app.inject — inject; путь без строки запроса", async () => {
    const before = stand.calls().length;
    expect((await fetch(`${base}/.well-known/pao-configuration?x=1`)).status).toBe(200);
    await stand.app.inject({ method: "GET", url: "/.well-known/pao-configuration?y=2" });
    const [net, inj] = stand.calls().slice(before);
    expect(net).toEqual({ method: "GET", path: "/.well-known/pao-configuration", status: 200, source: "network" });
    expect(inj).toEqual({ method: "GET", path: "/.well-known/pao-configuration", status: 200, source: "inject" });
  });

  it("подписанное обращение — kid, nonce, idempotency_key; 4xx — code; отказ транспорта 404 — в журнале", async () => {
    const before = stand.calls().length;
    const ok = await call("GET", "/pao/v1/agent");
    expect(ok.statusCode).toBe(200);
    const key = randomUUID();
    const bad = await call("POST", "/pao/v1/mandates", { type: "НЕТ" }, { "idempotency-key": key });
    expect(bad.statusCode).toBeGreaterThanOrEqual(400);
    const unknown = await stand.app.inject({ method: "GET", url: "/pao/v1/nope" });
    expect(unknown.statusCode).toBe(404);
    const [a, b, c] = stand.calls().slice(before);
    expect(a).toMatchObject({ method: "GET", path: "/pao/v1/agent", status: 200, kid: side.kid, source: "inject" });
    expect(a?.nonce).toMatch(/^[0-9a-f-]{36}$/);
    expect(a && "code" in a).toBe(false);
    expect(b).toMatchObject({ method: "POST", path: "/pao/v1/mandates", status: bad.statusCode, code: (bad.json() as { code: string }).code, idempotency_key: key });
    expect(c).toMatchObject({ method: "GET", path: "/pao/v1/nope", status: 404, code: (unknown.json() as { code: string }).code });
  });

  it("реквизит: пара token_ref и cryptogram — в issuedCredentials, повтор — без новой пары; в журнале их нет (инвариант 1)", async () => {
    const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
      const req: MandateRequest = {
        type: "INTENT",
        subject: "s",
        amount_limit: 1,
        currency: "RUB",
        valid_to: "2026-10-26T00:00:00Z",
        merchant_scope: ["MER-1042"],
        principal_ref: "prn_stand_calls",
        mode: "IMMEDIATE",
        ...over,
      };
      const res = await call("POST", "/pao/v1/mandates", req, { "idempotency-key": randomUUID() });
      expect(res.statusCode).toBe(201);
      const id = (res.json() as { id: string }).id;
      expect((await stand.issuer.sign(id)).statusCode).toBe(200);
      return id;
    };
    const intent = await mandate({ type: "INTENT", amount_limit: 300_000, subject: "продукты" });
    const cart = await mandate({
      type: "CART",
      parent_id: intent,
      amount_limit: 189_000,
      subject: "корзина",
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 189_000 }], total: 189_000 },
    });
    const req = { mandate_id: cart, order_ref: "ORD-calls", merchant_id: "MER-1042", amount_max: 189_000, currency: "RUB", kind: "CARD" };
    const key = randomUUID();
    const first = await call("POST", "/pao/v1/credentials", req, { "idempotency-key": key });
    expect(first.statusCode).toBe(201);
    const { token_ref, cryptogram } = (first.json() as { payload: { token_ref: string; cryptogram: string } }).payload;
    expect(stand.issuedCredentials()).toEqual([{ token_ref, cryptogram }]);
    expect((await call("POST", "/pao/v1/credentials", req, { "idempotency-key": key })).statusCode).toBe(201);
    expect((await call("POST", "/pao/v1/credentials", req, { "idempotency-key": randomUUID() })).statusCode).toBe(201);
    expect(stand.issuedCredentials()).toEqual([{ token_ref, cryptogram }]);
    const journal = JSON.stringify(stand.calls());
    expect(journal).toContain("/pao/v1/credentials");
    expect(journal).not.toContain(token_ref);
    expect(journal).not.toContain(cryptogram);
  });
});
