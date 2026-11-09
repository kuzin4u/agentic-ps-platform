// Отзыв мандата и запросы подтверждения П6 (узел У5, нюанс (g) по #112; Р-1351, Р-1354, Р-1356). К1.1 — поведение до
// правки: ADP отказывает по отозванному CART и со ссылкой (первый барьер); ожидающий запрос отзыв не трогает. Путь
// «витрина → ADP → подтверждение» — без подмены, как tests/unit/stand-demo-actions.test.ts.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:confirm-revoke:v1";
const T0 = new Date("2026-11-09T12:00:00Z");
const SKU = "BRD-1042-02"; // 1 890 ₽
const QTY = 2;
const TOTAL = 378_000; // выше порога подтверждения стенда (300 000) — CONFIRMATION_REQUIRED

let st: Stand | undefined;
let mm: MerchantsStand | undefined;
afterEach(async () => {
  await mm?.close();
  await st?.close();
  mm = undefined;
  st = undefined;
});

async function setup() {
  const s = createStand();
  st = s;
  s.setClock(T0);
  const side = newAgentSide();
  expect((await s.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  const m = createMerchants(s, {
    decide: async (msg: CanonicalMessage) => {
      const d = (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
      if (d.decision !== "APPROVE") return { approved: false, reason: d.reason ?? null };
      const r = await s.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref: msg.op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved: true } });
      expect(r.statusCode).toBe(202);
      return { approved: true, reason: null };
    },
  });
  mm = m;
  const pao = (method: "GET" | "POST", path: string, body?: unknown) =>
    signedInject(s.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: s.now(),
    });
  const shop = (path: string, body?: unknown) => merchantCall(m.app, { side, agentCode: CODE, now: s.now(), path, ...(body === undefined ? {} : { body }) });
  const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-11-12T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: "prn_confirm_revoke",
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await pao("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await s.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "хлеб" });
  type Feed = { readonly type: string; readonly data: Record<string, unknown> }[];
  const feed = async (): Promise<Feed> => (await pao("GET", "/pao/v1/events")).json() as Feed;
  /** CART, заказ, реквизит, оплата: витрина ждёт подтверждения, П6 — запрос PENDING. */
  const awaiting = async () => {
    const cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: TOTAL,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: SKU, qty: QTY, price: TOTAL / QTY }], total: TOTAL },
    });
    const o = (await shop("/v1/shops/SHOP-1042/orders", { items: [{ sku: SKU, qty: QTY }], cart_mandate_id: cartId })).json() as { id: string };
    const res = await pao("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: o.id, merchant_id: "MER-1042", amount_max: TOTAL, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const paid = await shop(`/v1/shops/SHOP-1042/orders/${o.id}/payment`, {
      credential_ref: cred.credential_ref,
      kind: cred.kind,
      payload: cred.payload,
      aoi: cred.aoi,
      cart_mandate_id: cartId,
      order_ref: o.id,
    });
    expect(paid.json()).toMatchObject({ status: "AWAITING_CONFIRMATION" });
    const id = (await feed()).filter((e) => e.type === "confirmation.required").at(-1)!.data.confirmation_id as string;
    return { cartId, order_id: o.id, cred, confirmation_id: id };
  };
  /** Новая авторизация по реквизиту CART прямо в ADP стенда, со ссылкой подтверждения или без — решение как есть. */
  const authorize = async (cred: Credential, order_ref: string, op_ref: string, confirmation_ref?: string): Promise<Decision> => {
    const msg: CanonicalMessage = {
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: TOTAL,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
      order_ref,
      ...(confirmation_ref === undefined ? {} : { confirmation_ref }),
    };
    return (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
  };
  return { s, pao, feed, intentId, awaiting, authorize };
}

describe("К1.1: поведение до правки — первый барьер ADP и запрос PENDING после отзыва", () => {
  it("ссылка выдана до отзыва CART → авторизация со ссылкой — ADP DECLINE MANDATE_REVOKED, ссылка не погашена", async () => {
    const t = await setup();
    const a = await t.awaiting();
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    const { confirmation_ref } = (await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json() as { confirmation_ref: string };
    expect(confirmation_ref).toMatch(/^cr_/);
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    const d = await t.authorize(a.cred, a.order_id, `OPKC-${a.order_id}-ref`, confirmation_ref);
    expect(d).toMatchObject({ decision: "DECLINE", reason: "MANDATE_REVOKED" });
    expect((await t.s.confirmations.get(a.confirmation_id))).toMatchObject({ status: "APPROVED", confirmation_ref, op_ref: null });
  });

  it("запрос PENDING → отзыв CART → запрос остаётся PENDING, confirmation.rejected нет; банк одобряет — APPROVED (нюанс (g))", async () => {
    const t = await setup();
    const a = await t.awaiting();
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    expect((await t.s.confirmations.get(a.confirmation_id))?.status).toBe("PENDING");
    expect((await t.feed()).filter((e) => e.type === "confirmation.rejected")).toEqual([]);
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    expect((await t.s.confirmations.get(a.confirmation_id))?.status).toBe("APPROVED");
  });
});
