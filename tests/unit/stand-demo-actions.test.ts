// РП75 п. 6 (#112): действия кнопок реакции демо-стенда — stopPurchase, remindClient, revokeMandate, sendToReview. На
// каждое — ответ, событие (лента агента, П6, витрина) и запись stand.demo.log(). Путь «витрина → ADP → подтверждение» —
// без подмены, как tests/env/merchants-confirmation-stand.test.ts: решение ОПКЦ стенда — ADP стенда.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:demo-actions:v1";
const T0 = new Date("2026-11-08T12:00:00Z");
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

const at = (sec: number): Date => new Date(T0.getTime() + sec * 1000);

async function setup(demo: NonNullable<Parameters<typeof createStand>[0]>["demo"] = { faults: true }) {
  const s = createStand({ demo });
  st = s;
  s.setClock(T0);
  const side = newAgentSide();
  expect((await s.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  const decisions: Decision[] = [];
  const m = createMerchants(s, {
    decide: async (msg: CanonicalMessage) => {
      const d = (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
      decisions.push(d);
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
      principal_ref: "prn_demo_actions",
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
  /** Новая авторизация по реквизиту CART прямо в ADP стенда — решение как есть. */
  const authorize = async (cred: Credential, order_ref: string, op_ref: string): Promise<Decision> => {
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
    };
    return (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
  };
  const order = async (id: string) => (await shop(`/v1/shops/SHOP-1042/orders/${id}`)).json() as { status: string };
  const actions = () => s.demo!.log().filter((e) => e.kind === "action");
  return { s, m, pao, shop, feed, mandate, intentId, awaiting, authorize, order, actions, decisions };
}

describe("stopPurchase (В5): отзыв CART через банк стенда и отказ ожидающего запроса", () => {
  it("ответ 200 и rejected; mandate.revoked и confirmation.rejected агенту; ADP отклоняет CART; записи по одной", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const r = await t.s.demo!.stopPurchase(a.cartId);
    expect(r.statusCode).toBe(200);
    expect(r.rejected).toEqual([a.confirmation_id]);
    const events = await t.feed();
    expect(events.filter((e) => e.type === "mandate.revoked" && e.data.mandate_id === a.cartId)).toHaveLength(1);
    expect(events.filter((e) => e.type === "confirmation.rejected" && e.data.confirmation_id === a.confirmation_id)).toHaveLength(1);
    // Закрыл сам отзыв (РП76 п. 8): без решения банка, с closed — своего отказа у stopPurchase нет.
    expect(await t.s.confirmations.get(a.confirmation_id)).toMatchObject({ status: "REJECTED", decision: null, closed: { reason: "MANDATE_REVOKED" } });
    const d = await t.authorize(a.cred, a.order_id, `OPKC-${a.order_id}-stop`);
    expect(d).toMatchObject({ decision: "DECLINE", reason: "MANDATE_REVOKED" });
    expect(t.actions().map((e) => [e.what, e.ids])).toEqual([
      ["PURCHASE_STOPPED", { mandate_id: a.cartId }],
      ["CONFIRMATION_REJECTED", { mandate_id: a.cartId, confirmation_id: a.confirmation_id }],
    ]);
    expect(t.actions()[0]!.at).toBe(T0.toISOString());
  });

  it("не CART или неизвестный мандат — исключение, отзыва и записи нет", async () => {
    const t = await setup();
    await expect(t.s.demo!.stopPurchase(t.intentId)).rejects.toThrow(/только CART/);
    await expect(t.s.demo!.stopPurchase("mnd_unknown")).rejects.toThrow(/не найден/);
    expect((await t.feed()).filter((e) => e.type === "mandate.revoked")).toEqual([]);
    expect(t.actions()).toEqual([]);
  });
});

describe("remindClient (В6): один раз +confirmation_remind_extend_sec запросу и удержанию заказа", () => {
  it("без напоминания: на 50-й секунде запрос истёк, заказ у витрины DECLINED (контроль срока 45 с)", async () => {
    const t = await setup();
    const a = await t.awaiting();
    t.s.setClock(at(50));
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(409);
    expect((await t.order(a.order_id)).status).toBe("DECLINED");
  });

  it("срок +15 с, confirmation_ref и итоги прежние; на 50-й секунде подтверждение проходит, заказ PAID; повтор — без продления", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const before = (await t.s.confirmations.get(a.confirmation_id))!;
    expect(before.expires_at).toBe(at(45).toISOString());
    t.s.setClock(at(10));
    const r = await t.s.demo!.remindClient(a.confirmation_id);
    expect(r).toEqual({ confirmation_id: a.confirmation_id, expires_at: at(60).toISOString(), extended: true });
    const after = (await t.s.confirmations.get(a.confirmation_id))!;
    expect(after).toEqual({ ...before, expires_at: at(60).toISOString() });
    // Агент видит новый срок в GET; события в ПАО нет.
    expect((await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json()).toMatchObject({ status: "PENDING", expires_at: at(60).toISOString(), confirmation_ref: null });
    expect((await t.feed()).filter((e) => e.type.startsWith("confirmation.")).map((e) => e.type)).toEqual(["confirmation.required"]);

    const again = await t.s.demo!.remindClient(a.confirmation_id);
    expect(again).toEqual({ confirmation_id: a.confirmation_id, expires_at: at(60).toISOString(), extended: false });
    const ids = { confirmation_id: a.confirmation_id, mandate_id: a.cartId, merchant_id: "MER-1042", order_ref: a.order_id };
    expect(t.actions().map((e) => [e.what, e.ids, e.at])).toEqual([
      ["CLIENT_REMINDED", ids, at(10).toISOString()],
      ["REMIND_REPEATED", ids, at(10).toISOString()],
    ]);

    // После 45 с, до 60 с: витрина ещё держит заказ, банк подтверждает, ссылка продавцу — PAID.
    t.s.setClock(at(50));
    expect((await t.order(a.order_id)).status).toBe("AWAITING_CONFIRMATION");
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    const { confirmation_ref } = (await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json() as { confirmation_ref: string };
    const done = await t.shop(`/v1/shops/SHOP-1042/orders/${a.order_id}/confirmation`, { confirmation_ref });
    expect(done.json()).toMatchObject({ status: "PAID" });
  });

  it("запрос не PENDING или неизвестен — исключение, записи нет", async () => {
    const t = await setup();
    const a = await t.awaiting();
    expect((await t.s.issuer.confirm(a.confirmation_id, { decision: "REJECT" })).statusCode).toBe(200);
    await expect(t.s.demo!.remindClient(a.confirmation_id)).rejects.toThrow(/не ожидает решения/);
    await expect(t.s.demo!.remindClient("cnf_unknown")).rejects.toThrow(/не найден/);
    expect(t.actions()).toEqual([]);
  });
});

describe("РП75 дополнение #115: «только действия» — demo: { actions: true }, срок order_hold_sec, сбоев нет", () => {
  const ONLY = { actions: true } as const;

  it("срок запроса и удержания — 900 с; на 50-й секунде заказ ждёт; arm / disarm / mark — исключение без записи", async () => {
    const t = await setup(ONLY);
    expect(t.s.params.order_hold_sec).toBe(900);
    const a = await t.awaiting();
    expect((await t.s.confirmations.get(a.confirmation_id))!.expires_at).toBe(at(900).toISOString());
    t.s.setClock(at(50));
    expect((await t.order(a.order_id)).status).toBe("AWAITING_CONFIRMATION");
    const d = t.s.demo!;
    expect(() => d.arm("Н-12")).toThrow(/сбои выключены/);
    expect(() => d.disarm("Н-12")).toThrow(/сбои выключены/);
    expect(() => d.mark("Н-01", { order_id: a.order_id })).toThrow(/сбои выключены/);
    expect(d.log()).toEqual([]);
    // Сбои не подключены: обращений с пометкой сбоя нет (РП75 п. 5 — поле только при faults).
    expect(t.s.calls().filter((c) => "fault" in c)).toEqual([]);
  });

  it("stopPurchase: отзыв закрывает запрос (РП76), одно confirmation.rejected; (d) заказ ждёт до конца удержания, затем DECLINED", async () => {
    const t = await setup(ONLY);
    const a = await t.awaiting();
    const r = await t.s.demo!.stopPurchase(a.cartId);
    expect(r.statusCode).toBe(200);
    expect(r.rejected).toEqual([a.confirmation_id]);
    expect((await t.feed()).filter((e) => e.type === "confirmation.rejected" && e.data.confirmation_id === a.confirmation_id)).toHaveLength(1);
    expect(await t.s.confirmations.get(a.confirmation_id)).toMatchObject({ status: "REJECTED", decision: null, closed: { reason: "MANDATE_REVOKED" } });
    expect(t.s.demo!.log().map((e) => [e.kind, e.what])).toEqual([
      ["action", "PURCHASE_STOPPED"],
      ["action", "CONFIRMATION_REJECTED"],
    ]);
    t.s.setClock(at(899));
    expect((await t.order(a.order_id)).status).toBe("AWAITING_CONFIRMATION");
    t.s.setClock(at(901));
    expect((await t.order(a.order_id)).status).toBe("DECLINED");
  });

  it("remindClient: +confirmation_remind_extend_sec к 900 с у запроса и у витрины; после 900 с подтверждение проходит, заказ PAID", async () => {
    const t = await setup(ONLY);
    const ext = t.s.params.confirmation_remind_extend_sec;
    const a = await t.awaiting();
    t.s.setClock(at(10));
    expect(await t.s.demo!.remindClient(a.confirmation_id)).toEqual({ confirmation_id: a.confirmation_id, expires_at: at(900 + ext).toISOString(), extended: true });
    t.s.setClock(at(900 + ext - 1));
    expect((await t.order(a.order_id)).status).toBe("AWAITING_CONFIRMATION");
    expect((await t.s.issuer.confirm(a.confirmation_id)).statusCode).toBe(200);
    const { confirmation_ref } = (await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json() as { confirmation_ref: string };
    expect((await t.shop(`/v1/shops/SHOP-1042/orders/${a.order_id}/confirmation`, { confirmation_ref })).json()).toMatchObject({ status: "PAID" });
    expect(t.actions().map((e) => e.what)).toEqual(["CLIENT_REMINDED"]);
  });
});

describe("revokeMandate: отзыв клиентом через банк стенда (РП38)", () => {
  it("ответ 200, mandate.revoked агенту, запись MANDATE_REVOKED; неизвестный — исключение без записи", async () => {
    const t = await setup();
    const r = await t.s.demo!.revokeMandate(t.intentId);
    expect(r.statusCode).toBe(200);
    expect((await t.feed()).filter((e) => e.type === "mandate.revoked" && e.data.mandate_id === t.intentId)).toHaveLength(1);
    await expect(t.s.demo!.revokeMandate("mnd_unknown")).rejects.toThrow(/не найден/);
    expect(t.actions().map((e) => [e.what, e.ids])).toEqual([["MANDATE_REVOKED", { mandate_id: t.intentId }]]);
  });
});

describe("sendToReview: только запись журнала", () => {
  it("запись с tx, условием и нарушителем — та же, что в журнале; ничего больше", async () => {
    const t = await setup();
    const calls = t.s.calls().length;
    const e = t.s.demo!.sendToReview({ tx: { op_ref: "OPKC-1", order_id: "ORD-1" }, condition: "R46", violator: "AGENT" });
    expect(e).toEqual({ seq: 1, at: T0.toISOString(), kind: "action", what: "SENT_TO_REVIEW", ids: { op_ref: "OPKC-1", order_id: "ORD-1" }, review: { condition: "R46", violator: "AGENT" } });
    expect(t.s.demo!.log()).toEqual([e]);
    expect(t.s.calls()).toHaveLength(calls);
  });

  it("пустой tx, поле вне перечня, условие не вида R46, нарушитель вне перечня — исключение, записи нет", async () => {
    const t = await setup();
    const d = t.s.demo!;
    expect(() => d.sendToReview({ tx: {}, condition: "R46", violator: "AGENT" })).toThrow(/хотя бы один/);
    expect(() => d.sendToReview({ tx: { credential_ref: "CRD-1" } as never, condition: "R46", violator: "AGENT" })).toThrow(/вне перечня/);
    expect(() => d.sendToReview({ tx: { op_ref: "OPKC-1" }, condition: "46", violator: "AGENT" })).toThrow(/R46/);
    expect(() => d.sendToReview({ tx: { op_ref: "OPKC-1" }, condition: "R46", violator: "CLIENT" as never })).toThrow(/violator/);
    expect(d.log()).toEqual([]);
  });
});
