// РП75 п. 3 (#112): сбои витрин демо-стенда — Н-03 «оплачено» без ожидания решения и при отказе, Н-04 исполнение до
// решения, Н-05 инструкция агенту в описании товара. Со сбоем — нарушение и запись журнала; без arm и без режима —
// поведение прежнее.
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEMO_AGENT_INSTRUCTION } from "../../src/env/merchants/server.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";

const A = "nspk:agent:shop-faults:v1";
const T0 = new Date("2026-11-08T10:00:00Z");

let m: MerchantsStand | undefined;
let st: Stand | undefined;
afterEach(async () => {
  await m?.close();
  await st?.close();
  m = undefined;
  st = undefined;
});

/** Решение ОПКЦ, которое держится до open(): ответ витрины до решения виден по порядку. */
function gate(result: { approved: boolean; reason: string | null }) {
  let open!: () => void;
  const opened = new Promise<void>((r) => (open = r));
  return { open, decide: async () => (await opened, result) };
}

async function setup(demo: boolean, opts: Parameters<typeof createMerchants>[1] = {}) {
  const s = createStand(demo ? { demo: { faults: true } } : {});
  st = s;
  s.setClock(T0);
  const side = newAgentSide();
  expect((await s.admit(buyerApplication(A, side), "op")).admitted).toBe(true);
  m = createMerchants(s, opts);
  const who = { side, agentCode: A, now: s.now() };
  const app = m.app;
  const order = async (shop = "SHOP-1042", sku = "BRD-1042-01") =>
    (await merchantCall(app, { ...who, path: `/v1/shops/${shop}/orders`, body: { items: [{ sku, qty: 1 }], cart_mandate_id: "MND-cart-1" } })).json() as { id: string };
  const pay = (shop: string, id: string) =>
    merchantCall(app, {
      ...who,
      path: `/v1/shops/${shop}/orders/${id}/payment`,
      body: {
        credential_ref: "CRD-test-1",
        kind: "CARD",
        payload: { token_ref: "tok_ag_test", cryptogram: "Y3J5cHRvZ3JhbQ==", valid_to: "2026-11-08T10:15:00Z" },
        aoi: { indicator: true, agent_code: A, mandate_id: "MND-cart-1" },
        cart_mandate_id: "MND-cart-1",
        order_ref: id,
      },
    });
  const get = async (shop: string, id: string) => (await merchantCall(app, { ...who, path: `/v1/shops/${shop}/orders/${id}` })).json() as Record<string, unknown>;
  const catalog = async (shop = "SHOP-1042") =>
    (await merchantCall(app, { ...who, path: `/v1/shops/${shop}/catalog` })).json() as { items: { sku: string; description?: string }[] };
  const log = () => s.demo?.log().filter((e) => e.what !== "ARMED" && e.what !== "DISARMED") ?? [];
  return { s, m, order, pay, get, catalog, log };
}

describe("РП75 п. 3: без arm и без режима сбоев витрины ведут себя как прежде", () => {
  it.each([false, true])("demo = %s: отказ ОПКЦ — DECLINED, fulfilled_at нет, описание без инструкции, сбойных записей нет", async (demo) => {
    const t = await setup(demo, { decide: () => ({ approved: false, reason: "LIMIT_EXCEEDED" }) });
    const o = await t.order();
    const r = await t.pay("SHOP-1042", o.id);
    expect(r.json()).toMatchObject({ status: "DECLINED", payment: { approved: false, confirmation_required: false } });
    expect("fulfilled_at" in r.json()).toBe(false);
    expect(JSON.stringify(await t.catalog())).not.toContain(DEMO_AGENT_INSTRUCTION);
    expect(t.log()).toEqual([]);
  });
});

describe("Н-03 (R27, R28, R30): «оплачено» без ожидания решения ADP и при отказе", () => {
  it("ответ PAID приходит, пока ОПКЦ не решила; отказ к заказу не применяется; запись PAID_BEFORE_OUTCOME", async () => {
    const g = gate({ approved: false, reason: "LIMIT_EXCEEDED" });
    const t = await setup(true, { decide: g.decide });
    t.s.demo!.arm("Н-03");
    const o = await t.order();
    const r = await t.pay("SHOP-1042", o.id);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ status: "PAID", payment: { approved: true, confirmation_required: false } });
    // Авторизация ушла и ждёт решения — ответ витрины был раньше.
    expect(t.m.opkc.messages).toHaveLength(1);
    expect(t.log()).toEqual([
      { seq: 2, at: T0.toISOString(), kind: "fault", test: "Н-03", what: "PAID_BEFORE_OUTCOME", ids: { shop_id: "SHOP-1042", merchant_id: "MER-1042", order_id: o.id } },
    ]);
    g.open();
    await vi.waitFor(() => expect(t.m.reconciliationReplies).toHaveLength(1));
    expect((await t.get("SHOP-1042", o.id)).status).toBe("PAID");
  });

  it("выбор витрины: Н-03 у SHOP-3301 — у SHOP-1042 отказ остаётся DECLINED, записи нет", async () => {
    const t = await setup(true, { decide: () => ({ approved: false, reason: "LIMIT_EXCEEDED" }) });
    t.s.demo!.arm("Н-03", { shop_id: "SHOP-3301" });
    const o = await t.order();
    expect((await t.pay("SHOP-1042", o.id)).json().status).toBe("DECLINED");
    expect(t.log()).toEqual([]);
  });
});

describe("Н-04 (R32): исполнение заказа до решения", () => {
  it("при PAYING у заказа уже fulfilled_at; после решения отметка остаётся; запись FULFILLED_BEFORE_OUTCOME — одна", async () => {
    const g = gate({ approved: true, reason: null });
    const t = await setup(true, { decide: g.decide });
    t.s.demo!.arm("Н-04", { merchant_id: "MER-1042" });
    const o = await t.order();
    const paying = t.pay("SHOP-1042", o.id);
    await vi.waitFor(() => expect(t.m.opkc.messages).toHaveLength(1));
    expect(await t.get("SHOP-1042", o.id)).toMatchObject({ status: "PAYING", fulfilled_at: T0.toISOString() });
    g.open();
    expect((await paying).json()).toMatchObject({ status: "PAID", fulfilled_at: T0.toISOString() });
    expect(t.log().map((e) => [e.test, e.what, e.ids.order_id])).toEqual([["Н-04", "FULFILLED_BEFORE_OUTCOME", o.id]]);
  });
});

describe("Н-05 (R47): инструкция агенту в описании товара", () => {
  it("в описании первой карточки выбранной витрины — инструкция; прочие карточки и витрины без неё; disarm — снова чисто", async () => {
    const t = await setup(true);
    const before = await t.catalog();
    t.s.demo!.arm("Н-05", { shop_id: "SHOP-1042" });
    const after = await t.catalog();
    expect(after.items[0]!.description).toContain(DEMO_AGENT_INSTRUCTION);
    expect(after.items.slice(1)).toEqual(before.items.slice(1));
    expect(JSON.stringify(await t.catalog("SHOP-3301"))).not.toContain(DEMO_AGENT_INSTRUCTION);
    expect(t.log().map((e) => [e.test, e.what, e.ids])).toEqual([["Н-05", "INSTRUCTION_SERVED", { shop_id: "SHOP-1042", merchant_id: "MER-1042" }]]);
    t.s.demo!.disarm("Н-05");
    expect(await t.catalog()).toEqual(before);
  });
});

describe("РП75 п. 2: настройки сбоев витрин проверяются при arm", () => {
  it("чужая настройка, неизвестная витрина или продавец — исключение, записи нет", async () => {
    const t = await setup(true);
    const d = t.s.demo!;
    expect(() => d.arm("Н-03", { delay_ms: 1 })).toThrow(/у Н-03 нет настройки delay_ms/);
    expect(() => d.arm("Н-04", { shop_id: "SHOP-0000" })).toThrow(/не витрина стенда/);
    expect(() => d.arm("Н-05", { merchant_id: "MER-0000" })).toThrow(/не продавец витрин стенда/);
    expect(() => d.arm("Н-12", { shop_id: "SHOP-1042" })).toThrow(/у Н-12 нет настройки shop_id/);
    expect(() => d.arm("Н-02", { reorder: true })).toThrow(/у Н-02 нет настройки reorder/);
    expect(d.log()).toEqual([]);
  });
});
