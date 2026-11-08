// Путь операции на стенде для тестов режима сбоев (РП75): агент, INTENT и CART подписаны банком стенда, реквизит на заказ,
// решение ADP по сообщению ОПКЦ и ответ эмитента (ПИ-3) — как сборка демо-стенда приложения. Сообщения процессинга —
// прямо в ADP стенда (путь через ОПКЦ — PS-11).
import { randomUUID } from "node:crypto";
import { expect } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import type { Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "./agent.js";
import { signedInject } from "./signed-inject.js";

export interface FeedEvent {
  readonly event_id: string;
  readonly type: string;
  readonly data: Record<string, unknown>;
}

export interface DemoFlow {
  /** Лента агента после курсора. */
  feed(after?: string): Promise<FeedEvent[]>;
  /** Реквизит и решение ADP на заказ суммой amount; решение — как есть. */
  decide(order_ref: string, amount: number): Promise<{ decision: Decision; op_ref: string }>;
  /** Заказ ниже порога подтверждения: APPROVE и ответ эмитента — событие operation.authorized в ленте. */
  approve(order_ref: string): Promise<string>;
}

/** Ниже рыночного порога подтверждения (confirm_above_kop стенда — 300 000). */
const SMALL = 100_000;

export async function demoFlow(s: Stand, code: string, principal_ref = "prn_demo_flow"): Promise<DemoFlow> {
  const side = newAgentSide();
  expect((await s.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
  const call = (method: "GET" | "POST", path: string, body?: unknown, query?: string) =>
    signedInject(s.app, side, code, {
      method,
      path,
      ...(query === undefined ? {} : { query }),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: s.now(),
    });
  const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: new Date(s.now().getTime() + 3 * 86_400_000).toISOString(),
      merchant_scope: ["MER-1042"],
      principal_ref,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await call("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await s.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
  const cartId = await mandate({
    type: "CART",
    parent_id: intentId,
    amount_limit: 2_000_000,
    subject: "корзина SHOP-1042",
    cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: 340_000 }], total: 340_000 },
  });
  const decide = async (order_ref: string, amount: number) => {
    const cr = await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref, merchant_id: "MER-1042", amount_max: amount, currency: "RUB", kind: "CARD" });
    expect(cr.statusCode).toBe(201);
    const cred = cr.json() as Credential;
    const op_ref = `OPKC-${order_ref}-1`;
    const msg: CanonicalMessage = {
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
      order_ref,
    };
    const decision = (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
    return { decision, op_ref };
  };
  return {
    feed: async (after) => {
      const r = await call("GET", "/pao/v1/events", undefined, after === undefined ? undefined : `after=${after}`);
      expect(r.statusCode).toBe(200);
      return r.json() as FeedEvent[];
    },
    decide,
    async approve(order_ref) {
      const { decision, op_ref } = await decide(order_ref, SMALL);
      expect(decision.decision).toBe("APPROVE");
      const ev = await s.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved: true } });
      expect(ev.statusCode).toBe(202);
      return op_ref;
    },
  };
}
