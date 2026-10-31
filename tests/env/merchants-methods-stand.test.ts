// #86 (AG-09 ч. 2д агента): замена payment_methods витрин эмулятора по merchant_id в createMerchants стенда — витрина
// с знаком ACTIVE и способами без card / sbp или пустым списком проверяется агентом без подмен ответов.
import { afterEach, describe, expect, it } from "vitest";
import { SHOPS } from "../../src/env/merchants/index.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { merchantCall } from "../support/merchant-call.js";

const open: { stand: Stand; m: MerchantsStand }[] = [];
afterEach(async () => {
  for (const { stand, m } of open.splice(0)) {
    await m.close();
    await stand.close();
  }
});

function start(opts?: Parameters<typeof createMerchants>[1]) {
  const stand = createStand();
  const m = createMerchants(stand, opts);
  open.push({ stand, m });
  return { stand, m };
}

async function methodsOf(m: MerchantsStand): Promise<Record<string, readonly string[]>> {
  const shops = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops as { id: string; payment_methods: string[] }[];
  return Object.fromEntries(shops.map((s) => [s.id, s.payment_methods]));
}

const CARD_SBP = ["card", "sbp"];

describe("#86: paymentMethods витрин стенда по merchant_id", () => {
  it("(а) [\"cash\"] у MER-1042 — у SHOP-1042 только cash, знак ACTIVE; остальные витрины без изменений", async () => {
    const { stand, m } = start({ paymentMethods: { "MER-1042": ["cash"] } });
    const methods = await methodsOf(m);
    expect(methods["SHOP-1042"]).toEqual(["cash"]);
    for (const s of SHOPS.filter((x) => x.id !== "SHOP-1042")) expect(methods[s.id], s.id).toEqual(CARD_SBP);
    const r = await stand.acquirerParticipant.getReadiness("MER-1042");
    expect(r.statusCode).toBe(200);
    expect(r.body).toMatchObject({ merchant_id: "MER-1042", status: "ACTIVE" });
  });

  it("(б) [] у MER-1042 — у SHOP-1042 пустой список как есть, знак ACTIVE (Р-1005 агента)", async () => {
    const { stand, m } = start({ paymentMethods: { "MER-1042": [] } });
    expect((await methodsOf(m))["SHOP-1042"]).toEqual([]);
    const r = await stand.acquirerParticipant.getReadiness("MER-1042");
    expect(r.body).toMatchObject({ merchant_id: "MER-1042", status: "ACTIVE" });
  });

  it("(в) неизвестный merchant_id — исключение при создании (fail-closed)", () => {
    const stand = createStand();
    try {
      expect(() => createMerchants(stand, { paymentMethods: { "MER-0000": ["cash"] } })).toThrow(/MER-0000/);
      expect(() => createMerchants(stand, { paymentMethods: { "MER-1042": ["cash"], "SHOP-1042": ["cash"] } })).toThrow(/SHOP-1042/);
    } finally {
      void stand.close();
    }
  });

  it("(г) фикстура не меняется: после замены SHOPS и следующий createMerchants без опции — card, sbp", async () => {
    const { m: first } = start({ paymentMethods: { "MER-1042": ["cash"] } });
    expect((await methodsOf(first))["SHOP-1042"]).toEqual(["cash"]);
    expect(SHOPS.find((s) => s.merchant_id === "MER-1042")!.payment_methods).toEqual(CARD_SBP);
    const { m: second } = start();
    expect((await methodsOf(second))["SHOP-1042"]).toEqual(CARD_SBP);
  });

  it("(д) без опции — все витрины фикстуры как прежде", async () => {
    const { m } = start();
    expect(await methodsOf(m)).toEqual(Object.fromEntries(SHOPS.map((s) => [s.id, [...s.payment_methods]])));
  });
});
