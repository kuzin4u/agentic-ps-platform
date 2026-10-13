// PS-12: эмулятор эквайрера — перенос aoi, режим без поддержки aoi (РП22 п. 6), неагентская операция (инвариант 2).
import { describe, expect, it } from "vitest";
import { Acquirer, OpkcStub, parsePaymentPackage, type PaymentPackage } from "../../src/env/acquirer/index.js";
import { MerchantAgentVerifier, buildMerchantsServer } from "../../src/env/merchants/index.js";
import { createMerchants, createStand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";

const CODE = "nspk:agent:acq-a:v1";
const merchant = { id: "MER-1042", mcc: "5462", name: "Масса Мадре" };

const card = (): PaymentPackage =>
  parsePaymentPackage({
    credential_ref: "CRD-1",
    kind: "CARD",
    payload: { token_ref: "tok_ag_1", cryptogram: "Y3J5cHRv" },
    aoi: { indicator: true, agent_code: CODE, mandate_id: "MND-1", fulfilment_ref: null },
    cart_mandate_id: "MND-1",
    order_ref: "ORD-1",
  })!;

const acq = (aoiSupport: boolean) => {
  const opkc = new OpkcStub();
  return { opkc, acquirer: new Acquirer({ acquirer_id: "ACQ-01", aoiSupport, opkc }) };
};

describe("ПИ-2: перенос признака", () => {
  it("aoi переносится без изменений; инструмент AGENT_TOKEN; сумма — из заказа", async () => {
    const { opkc, acquirer } = acq(true);
    const p = card();
    const r = await acquirer.authorize({ merchant, amount: 189000, currency: "RUB", order_ref: "ORD-1", package: p });
    expect(r.approved).toBe(true);
    const [msg] = opkc.messages;
    expect(msg).toMatchObject({
      op_ref: r.op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: 189000,
      merchant: { id: "MER-1042", acquirer_id: "ACQ-01" },
      instrument: { kind: "AGENT_TOKEN", token_ref: "tok_ag_1", cryptogram: "Y3J5cHRv" },
      order_ref: "ORD-1",
    });
    expect(msg!.aoi).toEqual(p.aoi);
    expect(msg!.aoi).not.toBe(p.aoi);
  });

  it("СБП: ACCOUNT_LINK, канал SBP", async () => {
    const { opkc, acquirer } = acq(true);
    const p = parsePaymentPackage({ ...card(), kind: "SBP", payload: { account_link_ref: "alk_1" } })!;
    await acquirer.authorize({ merchant, amount: 5000, currency: "RUB", order_ref: "ORD-1", package: p });
    expect(opkc.messages[0]).toMatchObject({ channel: "SBP", instrument: { kind: "ACCOUNT_LINK", account_link_ref: "alk_1" } });
  });

  it("реверсал — с тем же признаком и инструментом (A1 п. 5.1)", async () => {
    const { opkc, acquirer } = acq(true);
    const r = await acquirer.authorize({ merchant, amount: 100, currency: "RUB", order_ref: "ORD-1", package: card() });
    await acquirer.reverse(r.op_ref);
    const [auth, rev] = opkc.messages;
    expect(rev).toMatchObject({ msg_type: "REVERSAL", op_ref: r.op_ref });
    expect(rev!.aoi).toEqual(auth!.aoi);
    expect(rev!.instrument).toEqual(auth!.instrument);
  });

  it("сумма — только целые копейки > 0", async () => {
    const { acquirer } = acq(true);
    for (const amount of [0, -1, 1.5]) {
      await expect(acquirer.authorize({ merchant, amount, currency: "RUB", order_ref: "ORD-1", package: card() })).rejects.toThrow();
    }
  });
});

describe("РП22 п. 6: эквайрер без поддержки aoi", () => {
  it("aoi в сообщение не попадает, инструмент остаётся агентским (BYPASS невозможен)", async () => {
    const { opkc, acquirer } = acq(false);
    await acquirer.authorize({ merchant, amount: 100, currency: "RUB", order_ref: "ORD-1", package: card() });
    expect(opkc.messages[0]).not.toHaveProperty("aoi");
    expect(opkc.messages[0]!.instrument.kind).toBe("AGENT_TOKEN");
  });

  it("продавец передаёт метаданные пакета для сверки по credential_ref", async () => {
    const s = createStand();
    const side = newAgentSide();
    expect(s.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    const m = createMerchants(s, { aoiSupport: false });
    try {
      const who = { side, agentCode: CODE };
      const o = (await merchantCall(m.app, { ...who, path: "/v1/shops/SHOP-1042/orders", body: { items: [{ sku: "BRD-1042-01", qty: 1 }], cart_mandate_id: "MND-1" } })).json();
      const p = { ...card(), order_ref: o.id };
      const r = await merchantCall(m.app, { ...who, path: `/v1/shops/SHOP-1042/orders/${o.id}/payment`, body: p });
      expect(r.json().status).toBe("PAID");
      expect(m.reconciliation).toEqual([{ merchant_id: "MER-1042", credential_ref: "CRD-1", order_ref: o.id, aoi: p.aoi }]);
      expect(m.opkc.messages[0]).not.toHaveProperty("aoi");
    } finally {
      await m.close();
    }
  });

  it("сбой порта сверки авторизацию не останавливает: метаданные решение ADP не определяют", async () => {
    const s = createStand();
    const side = newAgentSide();
    expect(s.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    const opkc = new OpkcStub();
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: false, opkc });
    const verifier = new MerchantAgentVerifier(() => s.keys.jwks(), { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60 });
    const reconciliation = {
      submit: async () => {
        throw new Error("API для продавцов недоступен");
      },
    };
    const app = buildMerchantsServer({ verifier, acquirer, reconciliation });
    const who = { side, agentCode: CODE };
    const o = (await merchantCall(app, { ...who, path: "/v1/shops/SHOP-1042/orders", body: { items: [{ sku: "BRD-1042-01", qty: 1 }], cart_mandate_id: "MND-1" } })).json();
    const r = await merchantCall(app, { ...who, path: `/v1/shops/SHOP-1042/orders/${o.id}/payment`, body: { ...card(), order_ref: o.id } });
    expect(r.json().status).toBe("PAID");
    expect(opkc.messages).toHaveLength(1);
  });

  it("эквайрер без aoi без порта сверки — ошибка сборки витрин", () => {
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: false, opkc: new OpkcStub() });
    const verifier = new MerchantAgentVerifier(() => ({ keys: [] }), { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60 });
    expect(() => buildMerchantsServer({ verifier, acquirer })).toThrow(/порт сверки/);
  });

  it("с поддержкой aoi метаданные не передаются", async () => {
    const s = createStand();
    const side = newAgentSide();
    expect(s.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    const m = createMerchants(s);
    try {
      const who = { side, agentCode: CODE };
      const o = (await merchantCall(m.app, { ...who, path: "/v1/shops/SHOP-1042/orders", body: { items: [{ sku: "BRD-1042-01", qty: 1 }], cart_mandate_id: "MND-1" } })).json();
      const r = await merchantCall(m.app, { ...who, path: `/v1/shops/SHOP-1042/orders/${o.id}/payment`, body: { ...card(), order_ref: o.id } });
      expect(r.json().status).toBe("PAID");
      expect(m.opkc.messages[0]).toHaveProperty("aoi");
      expect(m.reconciliation).toEqual([]);
    } finally {
      await m.close();
    }
  });
});

describe("Инвариант 2: неагентская операция", () => {
  it("CARD_TOKEN без пакета — обычная авторизация без aoi", async () => {
    for (const aoiSupport of [true, false]) {
      const { opkc, acquirer } = acq(aoiSupport);
      await acquirer.authorize({ merchant, amount: 100, currency: "RUB", order_ref: "ORD-2", instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" } });
      expect(opkc.messages[0]).not.toHaveProperty("aoi");
      expect(opkc.messages[0]!.instrument).toEqual({ kind: "CARD_TOKEN", token_ref: "tok_card_1" });
    }
  });
});

describe("Разбор пакета (РП22 п. 5): только поля PaymentPackage, fail-closed", () => {
  const base = { ...card() } as Record<string, unknown>;
  it("лишние поля, в том числе сумма, не переносятся", () => {
    expect(parsePaymentPackage({ ...base, amount: 1, note: "x" })).toEqual(card());
  });
  it.each([
    ["нет credential_ref", { credential_ref: undefined }],
    ["вид вне перечня", { kind: "CASH" }],
    ["CARD без криптограммы", { payload: { token_ref: "t" } }],
    ["CARD с привязкой счёта", { payload: { token_ref: "t", cryptogram: "c", account_link_ref: "a" } }],
    ["SBP с токеном", { kind: "SBP", payload: { token_ref: "t", account_link_ref: "a" } }],
    ["indicator ≠ true", { aoi: { indicator: false, agent_code: CODE, mandate_id: "M" } }],
    ["aoi без кода агента", { aoi: { indicator: true, mandate_id: "M" } }],
    ["нет order_ref", { order_ref: "" }],
    ["payload не объект", { payload: "x" }],
  ])("%s — null", (_n, over) => {
    expect(parsePaymentPackage({ ...base, ...over })).toBeNull();
  });
  it("не объект — null", () => {
    expect(parsePaymentPackage(null)).toBeNull();
    expect(parsePaymentPackage([base])).toBeNull();
  });
});
