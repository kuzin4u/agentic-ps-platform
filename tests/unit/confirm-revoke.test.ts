// Отзыв мандата и запросы подтверждения П6 (узел У5, нюанс (g) по #112; РП76; Р-1351, Р-1354, Р-1356, Р-1362). К1.1 —
// первый барьер ADP: по отозванному CART отказ и со ссылкой. К2.2 — отзыв закрывает ожидающие запросы: ПИ-8 revoke (и
// повтор), revoke-all, ПАО relinquish; INTENT — и запросы его CART; не PENDING не трогается; сбой П6 — 503, повтор
// доотклоняет; п. 10 — отзыв между чтением мандата ADP и записью запроса. Путь «витрина → ADP → подтверждение» — без
// подмены, как tests/unit/stand-demo-actions.test.ts.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryConfirmationStore } from "../../src/confirm/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:confirm-revoke:v1";
const PRINCIPAL = "prn_confirm_revoke";
const T0 = new Date("2026-11-09T12:00:00Z");
const SKU = "BRD-1042-02"; // 1 890 ₽
const QTY = 2;
const TOTAL = 378_000; // выше порога подтверждения стенда (300 000) — CONFIRMATION_REQUIRED

let st: Stand | undefined;
let mm: MerchantsStand | undefined;
afterEach(async () => {
  vi.restoreAllMocks();
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
  const pao = (method: "GET" | "POST", path: string, body?: unknown, key: string = randomUUID()) =>
    signedInject(s.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": key },
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
      principal_ref: PRINCIPAL,
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
  /** CART под INTENT, заказ и реквизит — до оплаты. */
  const cart = async (parent = intentId) => {
    const cartId = await mandate({
      type: "CART",
      parent_id: parent,
      amount_limit: TOTAL,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: SKU, qty: QTY, price: TOTAL / QTY }], total: TOTAL },
    });
    const o = (await shop("/v1/shops/SHOP-1042/orders", { items: [{ sku: SKU, qty: QTY }], cart_mandate_id: cartId })).json() as { id: string };
    const res = await pao("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: o.id, merchant_id: "MER-1042", amount_max: TOTAL, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    return { cartId, order_id: o.id, cred: res.json() as Credential };
  };
  /** Оплата у витрины: ADP — CONFIRMATION_REQUIRED, П6 — запрос; ответ витрины как есть. */
  const pay = async (c: Awaited<ReturnType<typeof cart>>) =>
    shop(`/v1/shops/SHOP-1042/orders/${c.order_id}/payment`, {
      credential_ref: c.cred.credential_ref,
      kind: c.cred.kind,
      payload: c.cred.payload,
      aoi: c.cred.aoi,
      cart_mandate_id: c.cartId,
      order_ref: c.order_id,
    });
  const lastRequired = async () => (await feed()).filter((e) => e.type === "confirmation.required").at(-1)!.data.confirmation_id as string;
  /** CART, заказ, реквизит, оплата: витрина ждёт подтверждения, П6 — запрос PENDING. */
  const awaiting = async (parent = intentId) => {
    const c = await cart(parent);
    expect((await pay(c)).json()).toMatchObject({ status: "AWAITING_CONFIRMATION" });
    return { ...c, confirmation_id: await lastRequired() };
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
  const record = async (id: string) => s.confirmations.get(id);
  const rejectedEvents = async (id: string) => (await feed()).filter((e) => e.type === "confirmation.rejected" && e.data.confirmation_id === id);
  /** Закрыт отзывом (РП76 п. 3): REJECTED, closed по часам стенда, без решения банка и ссылки; событие — одно. */
  const expectClosed = async (id: string) => {
    expect(await record(id)).toMatchObject({ status: "REJECTED", decision: null, confirmation_ref: null, closed: { reason: "MANDATE_REVOKED", at: s.now().toISOString() } });
    expect(await rejectedEvents(id)).toHaveLength(1);
  };
  return { s, pao, feed, intentId, cart, pay, awaiting, lastRequired, authorize, record, rejectedEvents, expectClosed };
}

describe("К1.1: первый барьер ADP — ссылка по отозванному CART", () => {
  it("ссылка выдана до отзыва CART → авторизация со ссылкой — ADP DECLINE MANDATE_REVOKED, ссылка не погашена", async () => {
    const t = await setup();
    const a = await t.awaiting();
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    const { confirmation_ref } = (await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json() as { confirmation_ref: string };
    expect(confirmation_ref).toMatch(/^cr_/);
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    const d = await t.authorize(a.cred, a.order_id, `OPKC-${a.order_id}-ref`, confirmation_ref);
    expect(d).toMatchObject({ decision: "DECLINE", reason: "MANDATE_REVOKED" });
    expect(await t.record(a.confirmation_id)).toMatchObject({ status: "APPROVED", confirmation_ref, op_ref: null });
  });
});

describe("РП76: отзыв закрывает ожидающие запросы подтверждения", () => {
  it("К1.1 (б) перевёрнут: PENDING → отзыв CART → REJECTED с closed, confirmation.rejected; банк после — 409 со статусом REJECTED", async () => {
    const t = await setup();
    const a = await t.awaiting();
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    await t.expectClosed(a.confirmation_id);
    expect((await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json()).toMatchObject({ status: "REJECTED", confirmation_ref: null });
    const late = await t.s.issuer.confirm(a.confirmation_id);
    expect(late).toMatchObject({ statusCode: 409, body: { code: "CONFIRMATION_NOT_PENDING", status: "REJECTED" } });
    expect(await t.rejectedEvents(a.confirmation_id), "второго события нет").toHaveLength(1);
  });

  it("INTENT с двумя CART: отзыв INTENT закрывает оба запроса; повтор отзыва — без второго события", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const b = await t.awaiting();
    expect((await t.s.issuer.revoke(t.intentId)).statusCode).toBe(200);
    await t.expectClosed(a.confirmation_id);
    await t.expectClosed(b.confirmation_id);
    expect((await t.s.issuer.revoke(t.intentId)).statusCode).toBe(200);
    expect(await t.rejectedEvents(a.confirmation_id)).toHaveLength(1);
    expect(await t.rejectedEvents(b.confirmation_id)).toHaveLength(1);
  });

  it("не PENDING и запрос по другому CART не трогаются: APPROVED остаётся, PENDING другого CART остаётся", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const other = await t.awaiting();
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    const approved = await t.record(a.confirmation_id);
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    expect(await t.record(a.confirmation_id)).toEqual(approved);
    expect((await t.record(other.confirmation_id))?.status).toBe("PENDING");
    expect((await t.feed()).filter((e) => e.type === "confirmation.rejected")).toEqual([]);
  });

  it("revoke-all закрывает запросы по мандатам клиента", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const r = await t.s.issuer.revokeAll(PRINCIPAL, "rvk_confirm_revoke_1");
    expect(r.statusCode).toBe(200);
    await t.expectClosed(a.confirmation_id);
  });

  it("relinquish агента закрывает запрос по CART", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const r = await t.pao("POST", `/pao/v1/mandates/${a.cartId}/relinquish`);
    expect(r.statusCode).toBe(200);
    await t.expectClosed(a.confirmation_id);
  });

  it("сбой П6 после записи отзыва — 503 STATE_UNAVAILABLE, мандат отозван, запрос PENDING; повтор отзыва доотклоняет", async () => {
    const t = await setup();
    const a = await t.awaiting();
    vi.spyOn(MemoryConfirmationStore.prototype, "pendingByAgent").mockRejectedValueOnce(new Error("ECONNRESET"));
    expect(await t.s.issuer.revoke(a.cartId)).toMatchObject({ statusCode: 503, body: { code: "STATE_UNAVAILABLE" } });
    expect((await t.pao("GET", `/pao/v1/mandates/${a.cartId}`)).json()).toMatchObject({ status: "REVOKED" });
    expect((await t.record(a.confirmation_id))?.status).toBe("PENDING");
    expect((await t.s.issuer.revoke(a.cartId)).statusCode).toBe(200);
    await t.expectClosed(a.confirmation_id);
  });

  it("relinquish: сбой П6 — 503 не сохраняется под ключом, повтор тем же ключом доотклоняет", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const key = randomUUID();
    vi.spyOn(MemoryConfirmationStore.prototype, "pendingByAgent").mockRejectedValueOnce(new Error("ECONNRESET"));
    const first = await t.pao("POST", `/pao/v1/mandates/${a.cartId}/relinquish`, undefined, key);
    expect(first.statusCode).toBe(503);
    expect(first.json()).toMatchObject({ code: "STATE_UNAVAILABLE" });
    expect((await t.record(a.confirmation_id))?.status).toBe("PENDING");
    const again = await t.pao("POST", `/pao/v1/mandates/${a.cartId}/relinquish`, undefined, key);
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ status: "REVOKED" });
    await t.expectClosed(a.confirmation_id);
  });

  it("п. 10: отзыв между чтением мандата ADP и записью запроса — запрос закрыт сразу после записи", async () => {
    const t = await setup();
    const c = await t.cart();
    const create = MemoryConfirmationStore.prototype.create;
    // Отзыв — внутри записи запроса ADP, до вставки: проход отзыва запроса ещё не видит.
    const spy = vi.spyOn(MemoryConfirmationStore.prototype, "create").mockImplementationOnce(async function (this: MemoryConfirmationStore, rec) {
      expect((await t.s.issuer.revoke(c.cartId)).statusCode).toBe(200);
      return create.call(this, rec);
    });
    await t.pay(c);
    expect(spy).toHaveBeenCalledTimes(1);
    await t.expectClosed(await t.lastRequired());
  });
});
