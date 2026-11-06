// РП25 дополнение #106 (передача #106 от agentic-buyer-app): набор витрин стенда параметром — createStand({ shops }).
// Один источник: справочник продавцов (реквизит по merchant_id), эквайрер, знаки готовности и витрины createMerchants.
// Две витрины вне фикстуры: агент находит обе, получает реквизит по merchant_id новой, оплата проходит, знак ACTIVE.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { SHOPS, type Shop } from "../../src/fixtures/index.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:shops-106:v1";
const PRINCIPAL = "prn_shops_106";
const RUB = "RUB";

/** Витрина вне фикстуры: ИНН — вымышленный, код региона 00, контрольная цифра верна (как у фикстуры, РП58 п. 5). */
const bakery = (n: string, inn: string, readiness_mark: boolean): Shop => ({
  id: `SHOP-${n}`,
  merchant_id: `MER-${n}`,
  name: `Пекарня ${n}`,
  inn,
  mcc: "5462",
  category: "bakery",
  payment_methods: ["card", "sbp"],
  delivery_regions: ["RU-MOW"],
  returns: { days: 0, text: "Продовольственные товары надлежащего качества возврату не подлежат" },
  readiness_mark,
  behaviour: "NORMAL",
  items: [
    {
      sku: `BRD-${n}-01`,
      title: "Хлеб на закваске",
      price: 45_000,
      currency: RUB,
      in_stock: true,
      category: "bakery",
      delivery_options: [{ method: "PICKUP", min_days: 0, max_days: 0, cost: 0, currency: RUB }],
      gtin: null,
      brand: null,
      model: null,
    },
  ],
});
const OWN: readonly Shop[] = [bakery("9001", "0000900107", true), bakery("9002", "0000900202", false)];

const open: { stand: Stand; m?: MerchantsStand }[] = [];
afterEach(async () => {
  for (const { stand, m } of open.splice(0)) {
    await m?.close();
    await stand.close();
  }
});

function start(shops?: readonly Shop[], opts?: Parameters<typeof createMerchants>[1]) {
  const stand = createStand(shops ? { shops } : {});
  const m = createMerchants(stand, opts);
  open.push({ stand, m });
  return { stand, m };
}

async function agent(stand: Stand, side: AgentSide) {
  expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  const pao = (path: string, body: unknown) =>
    signedInject(stand.app, side, CODE, { method: "POST", path, body: JSON.stringify(body), headers: { "idempotency-key": randomUUID() }, now: stand.now() });
  // Один срок на все мандаты агента: CART не позже INTENT (A7 п. 5).
  const valid_to = new Date(stand.now().getTime() + 86_400_000).toISOString();
  const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "хлеб",
      amount_limit: 1_000_000,
      currency: RUB,
      valid_to,
      merchant_scope: ["MER-9001"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await pao("/pao/v1/mandates", req);
    expect(res.statusCode, res.body).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  return { pao, mandate };
}

describe("#106: createStand({ shops }) — один набор витрин стенда", () => {
  it("две витрины вне фикстуры: список, реквизит по merchant_id, оплата PAID, знак ACTIVE у витрины с readiness_mark", async () => {
    const { stand, m } = start(OWN);
    const side = newAgentSide();
    const { pao, mandate } = await agent(stand, side);

    // Список витрин — ровно набор стенда, фикстуры нет (н1).
    const list = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops as { id: string; zone: string }[];
    expect(list.map((s) => [s.id, s.zone])).toEqual([
      ["SHOP-9001", "CONTOUR"],
      ["SHOP-9002", "OUTSIDE"],
    ]);

    // Знаки: ACTIVE — витрине с readiness_mark, у второй — нет знака (подача эквайрера стенда при старте).
    expect((await stand.acquirerParticipant.getReadiness("MER-9001")).body).toMatchObject({ merchant_id: "MER-9001", status: "ACTIVE" });
    expect((await stand.acquirerParticipant.getReadiness("MER-9002")).body).toMatchObject({ merchant_id: "MER-9002", status: "NONE" });

    // Заказ, мандат корзины, реквизит по merchant_id новой витрины (справочник продавцов — из набора), оплата пакетом.
    const intent = await mandate({});
    const shop = (path: string, body: unknown) => merchantCall(m.app, { side, agentCode: CODE, now: stand.now(), path, body });
    const cart = await mandate({
      type: "CART",
      parent_id: intent,
      amount_limit: 90_000,
      subject: "корзина SHOP-9001",
      cart: { merchant_id: "MER-9001", items: [{ sku: "BRD-9001-01", qty: 2, price: 45_000 }], total: 90_000 },
    });
    const o = (await shop("/v1/shops/SHOP-9001/orders", { items: [{ sku: "BRD-9001-01", qty: 2 }], cart_mandate_id: cart })).json() as { id: string; total: number };
    expect(o.total).toBe(90_000);
    const res = await pao("/pao/v1/credentials", { mandate_id: cart, order_ref: o.id, merchant_id: "MER-9001", amount_max: o.total, currency: RUB, kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const paid = await shop(`/v1/shops/SHOP-9001/orders/${o.id}/payment`, {
      credential_ref: cred.credential_ref,
      kind: cred.kind,
      payload: cred.payload,
      aoi: cred.aoi,
      cart_mandate_id: cart,
      order_ref: o.id,
    });
    expect(paid.statusCode).toBe(200);
    expect(paid.json()).toMatchObject({ status: "PAID", payment: { approved: true } });
  });

  it("набор заменяет фикстуру: продавец фикстуры MER-1042 стенду со своим набором неизвестен (н1)", async () => {
    const { stand } = start(OWN);
    const { mandate, pao } = await agent(stand, newAgentSide());
    const intent = await mandate({ merchant_scope: ["MER-1042"] });
    const cart = await mandate({
      type: "CART",
      parent_id: intent,
      merchant_scope: ["MER-1042"],
      amount_limit: 10_000,
      subject: "корзина",
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 10_000 }], total: 10_000 },
    });
    // Продавца нет в справочнике стенда (набор — OWN): П5 отказывает MANDATE_SCOPE (РП49 (д) п. 2, A7 п. 5).
    const res = await pao("/pao/v1/credentials", { mandate_id: cart, order_ref: `ORD-${randomUUID()}`, merchant_id: "MER-1042", amount_max: 10_000, currency: RUB, kind: "CARD" });
    expect([res.statusCode, res.json().code]).toEqual([409, "MANDATE_SCOPE"]);
    // Эквайрер стенда обслуживает только продавцов набора: MER-1042 ему не принадлежит.
    const mark = await stand.acquirerParticipant.getReadiness("MER-1042");
    expect([mark.statusCode, mark.body]).toEqual([404, { code: "MERCHANT_NOT_FOUND" }]);
  });

  it("stand.shops — копия, глубоко замороженная: изменение массива и витрины вызывающим стенд не меняет", async () => {
    const mine = OWN.map((s) => structuredClone(s)) as Shop[];
    const { stand, m } = start(mine);
    mine.push(bakery("9003", "0000900107", true));
    (mine[0] as { name: string }).name = "подмена";
    expect(stand.shops.map((s) => s.id)).toEqual(["SHOP-9001", "SHOP-9002"]);
    expect(stand.shops[0]!.name).toBe("Пекарня 9001");
    expect(Object.isFrozen(stand.shops)).toBe(true);
    expect(Object.isFrozen(stand.shops[0]!.items[0])).toBe(true);
    const list = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops as { id: string; name: string }[];
    expect(list.map((s) => s.name)).toEqual(["Пекарня 9001", "Пекарня 9002"]);
  });

  it("paymentMethods (#86) — поверх набора стенда; merchant_id фикстуры при своём наборе — исключение", async () => {
    const { m } = start(OWN, { paymentMethods: { "MER-9002": ["cash"] } });
    const list = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops as { id: string; payment_methods: string[] }[];
    expect(Object.fromEntries(list.map((s) => [s.id, s.payment_methods]))).toEqual({ "SHOP-9001": ["card", "sbp"], "SHOP-9002": ["cash"] });
    const stand = createStand({ shops: OWN });
    open.push({ stand });
    expect(() => createMerchants(stand, { paymentMethods: { "MER-1042": ["cash"] } })).toThrow(/MER-1042/);
  });

  it("без shops — набор фикстуры: stand.shops равен SHOPS по значению, но это копия", async () => {
    const { stand, m } = start();
    expect(stand.shops).toEqual(SHOPS);
    expect(stand.shops).not.toBe(SHOPS);
    const list = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops as { id: string }[];
    expect(list.map((s) => s.id)).toEqual([...SHOPS].map((s) => s.id).sort());
    expect((await stand.acquirerParticipant.getReadiness("MER-1042")).body).toMatchObject({ status: "ACTIVE" });
  });
});
