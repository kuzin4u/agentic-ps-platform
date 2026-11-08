// РП75 п. 3, п. 8 (#112, К3.2): строки «ПР» — нарушение агента разыгрывает приложение ключом своего агента, Платформа и
// витрины отвечают настоящей защитой. По тесту на строку: запрос ключом агента и точный код ответа. Коды — в ответ по #112.
// Режим сбоев не включается (arm нет): защита — та же, что вне демо-режима; стенд — демо, как у приложения.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:demo-guards:v1";
const T0 = new Date("2026-11-08T13:00:00Z");
const SKU = "BRD-1042-01"; // 390 ₽ — ниже порога подтверждения
const PRICE = 39_000;
const QTY = 2;
const TOTAL = PRICE * QTY;

let st: Stand | undefined;
let mm: MerchantsStand | undefined;
afterEach(async () => {
  await mm?.close();
  await st?.close();
  mm = undefined;
  st = undefined;
});

async function setup() {
  const s = createStand({ demo: { faults: true } });
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
  const mandate = async (over: Partial<MandateRequest>, sign = true): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-11-12T00:00:00Z",
      merchant_scope: ["MER-1042", "MER-4401"],
      principal_ref: "prn_demo_guards",
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await pao("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    if (sign) expect((await s.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "хлеб" });
  const cart = (sign = true) =>
    mandate(
      {
        type: "CART",
        parent_id: intentId,
        amount_limit: TOTAL,
        subject: "корзина SHOP-1042",
        merchant_scope: ["MER-1042"],
        cart: { merchant_id: "MER-1042", items: [{ sku: SKU, qty: QTY, price: PRICE }], total: TOTAL },
      },
      sign,
    );
  const order = async (cartId: string, shopId = "SHOP-1042", sku = SKU, qty = QTY) => {
    const r = await shop(`/v1/shops/${shopId}/orders`, { items: [{ sku, qty }], cart_mandate_id: cartId });
    expect(r.statusCode).toBe(201);
    return r.json() as { id: string; total: number };
  };
  const credential = (cartId: string, order_ref: string, amount = TOTAL, merchant_id = "MER-1042") =>
    pao("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref, merchant_id, amount_max: amount, currency: "RUB", kind: "CARD" });
  const pkgOf = (cred: Credential, cartId: string, order_ref: string) => ({
    credential_ref: cred.credential_ref,
    kind: cred.kind,
    payload: cred.payload,
    aoi: cred.aoi,
    cart_mandate_id: cartId,
    order_ref,
  });
  const pay = (shopId: string, order_id: string, pkg: unknown) => shop(`/v1/shops/${shopId}/orders/${order_id}/payment`, pkg);
  /** Оплаченный заказ по CART: реквизит, пакет, PAID. */
  const paid = async () => {
    const cartId = await cart();
    const o = await order(cartId);
    const c = await credential(cartId, o.id);
    expect(c.statusCode).toBe(201);
    const cred = c.json() as Credential;
    const r = await pay("SHOP-1042", o.id, pkgOf(cred, cartId, o.id));
    expect(r.json()).toMatchObject({ status: "PAID" });
    return { cartId, o, cred };
  };
  return { s, m, pao, shop, cart, order, credential, pkgOf, pay, paid, decisions };
}

const codeOf = (r: { statusCode: number; json(): unknown }) => [r.statusCode, (r.json() as { code?: string }).code];

describe("РП75 п. 3, строки «ПР»: точный код защиты на запрос ключом агента", () => {
  it("Н-01 (R46): повторная оплата оплаченного заказа — витрина 409 ORDER_NOT_PAYABLE, второй авторизации нет", async () => {
    const t = await setup();
    const { cartId, o, cred } = await t.paid();
    const before = t.decisions.length;
    const r = await t.pay("SHOP-1042", o.id, t.pkgOf(cred, cartId, o.id));
    expect(codeOf(r)).toEqual([409, "ORDER_NOT_PAYABLE"]);
    expect(t.decisions.length).toBe(before);
  });

  it("Н-06 (R37, R09, R18): после отзыва CART — реквизит 409 MANDATE_REVOKED, авторизация — DECLINE MANDATE_REVOKED", async () => {
    const t = await setup();
    const cartId = await t.cart();
    const o = await t.order(cartId);
    const c = await t.credential(cartId, o.id);
    expect(c.statusCode).toBe(201);
    expect((await t.s.issuer.revoke(cartId)).statusCode).toBe(200);
    expect(codeOf(await t.credential(cartId, `${o.id}-2`))).toEqual([409, "MANDATE_REVOKED"]);
    const r = await t.pay("SHOP-1042", o.id, t.pkgOf(c.json() as Credential, cartId, o.id));
    expect(r.json()).toMatchObject({ status: "DECLINED", payment: { approved: false } });
    expect(t.decisions.at(-1)).toMatchObject({ decision: "DECLINE", reason: "MANDATE_REVOKED" });
  });

  it("Н-07 (R18): реквизит по неподписанному CART — 409 PRINCIPAL_SIGNATURE_PENDING", async () => {
    const t = await setup();
    const cartId = await t.cart(false);
    const o = await t.order(cartId);
    expect(codeOf(await t.credential(cartId, o.id))).toEqual([409, "PRINCIPAL_SIGNATURE_PENDING"]);
  });

  it("Н-08: пакет не того заказа (корзина другая) — витрина 409 PACKAGE_MISMATCH", async () => {
    const t = await setup();
    const { cartId, cred } = await t.paid();
    const other = await t.order(await t.cart());
    const r = await t.pay("SHOP-1042", other.id, t.pkgOf(cred, cartId, other.id));
    expect(codeOf(r)).toEqual([409, "PACKAGE_MISMATCH"]);
  });

  it("Н-08: заказ больше корзины — реквизит на сумму заказа 409 MANDATE_SCOPE; реквизит в пределе — авторизация на сумму заказа отклонена ADP", async () => {
    const t = await setup();
    const cartId = await t.cart();
    const o = await t.order(cartId, "SHOP-1042", SKU, 5);
    expect(o.total).toBeGreaterThan(TOTAL);
    expect(codeOf(await t.credential(cartId, o.id, o.total))).toEqual([409, "MANDATE_SCOPE"]);
    const c = await t.credential(cartId, o.id, TOTAL);
    expect(c.statusCode).toBe(201);
    const r = await t.pay("SHOP-1042", o.id, t.pkgOf(c.json() as Credential, cartId, o.id));
    expect(r.json()).toMatchObject({ status: "DECLINED", payment: { approved: false } });
    expect(t.decisions.at(-1)).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
  });

  it("Н-09: пакет CART продавца А у продавца Б — витрина 409 PACKAGE_MISMATCH; реквизит на продавца Б — отказ Платформы", async () => {
    const t = await setup();
    const cartId = await t.cart();
    const oa = await t.order(cartId);
    const c = await t.credential(cartId, oa.id);
    const cred = c.json() as Credential;
    const ob = await t.order(cartId, "SHOP-4401", "BRD-4401-01", 1);
    // Пакет как есть — заказ А у витрины Б.
    expect(codeOf(await t.pay("SHOP-4401", ob.id, t.pkgOf(cred, cartId, oa.id)))).toEqual([409, "PACKAGE_MISMATCH"]);
    // Пакет переписан на заказ Б — витрина пропускает, ADP: реквизит выдан продавцу А.
    const r = await t.pay("SHOP-4401", ob.id, t.pkgOf(cred, cartId, ob.id));
    expect(r.json()).toMatchObject({ status: "DECLINED", payment: { approved: false } });
    expect(t.decisions.at(-1)).toMatchObject({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    // Новый реквизит по CART А на продавца Б.
    expect(codeOf(await t.credential(cartId, ob.id, ob.total, "MER-4401"))).toEqual([409, "MANDATE_SCOPE"]);
  });
});
