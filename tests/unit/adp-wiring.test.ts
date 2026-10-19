// ADP на настоящем журнале согласий и П3 в памяти ядра (PS-10 К1.4, РП43 п. 5–6): INTENT — один резерв, CART — два
// («CART → родитель», откат первого при отказе второго), verify.amount_left у CART — меньшее из CART и родителя.
import { describe, expect, it } from "vitest";
import { Adp, MemoryOperationStore } from "../../src/adp/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId } from "../../src/state/index.js";
import { A, decide, intent, mk, setup, type Ctx } from "../support/state.js";

let seq = 0;
const auth = (mandate_id: string, amount: number): CanonicalMessage => ({
  op_ref: `OPKC-WIRING-${++seq}`,
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount,
  currency: "RUB",
  merchant: { id: "MER-1042" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: A, mandate_id },
});

function adpFor(c: Ctx): Adp {
  return new Adp({
    agents: { get: (code) => (code === A ? { status: "ACTIVE", level: 2 } : undefined) },
    mandates: c.consent,
    state: c.state,
    operations: new MemoryOperationStore(),
    params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
  });
}

async function cartUnder(c: Ctx, parent: string, amount: number): Promise<string> {
  const cart = await mk(
    c,
    intent({
      type: "CART",
      parent_id: parent,
      subject: "корзина SHOP-1042",
      amount_limit: amount,
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: amount }], total: amount },
    }),
  );
  await decide(c, cart);
  return cart.id;
}

const left = async (c: Ctx, id: string) => (await c.ledger.available(accountId(id))).amount;

describe("ADP ← журнал согласий и П3 (РП43 п. 5–6)", () => {
  it("INTENT: APPROVE, один резерв, verify.amount_left уменьшился", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const d = await adpFor(c).decide(auth(p.id, 20_000));
    expect(parseDecision(d, "adp").decision).toBe("APPROVE");
    expect(d.agent_level).toBe(2);
    expect(await left(c, p.id)).toBe(30_000);
    expect((await c.consent.verify(p.id, A))?.amount_left).toBe(30_000);
  });

  it("CART: два резерва — CART и родитель; reservation_id — удержание CART; mandate_left_after — меньшее", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const cart = await cartUnder(c, p.id, 12_900);
    const d = await adpFor(c).decide(auth(cart, 10_000));
    expect(parseDecision(d, "adp").decision).toBe("APPROVE");
    expect((await c.ledger.get(d.reservation_id!)).account).toBe(accountId(cart));
    expect([await left(c, cart), await left(c, p.id)]).toEqual([2_900, 40_000]);
    expect(d.mandate_left_after).toBe(2_900);
  });

  it("несколько CART в сумме больше родителя — второй LIMIT_EXCEEDED по родителю, резерв CART освобождён (инвариант 4)", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const c1 = await cartUnder(c, p.id, 30_000);
    const c2 = await cartUnder(c, p.id, 30_000);
    const adp = adpFor(c);
    expect(parseDecision(await adp.decide(auth(c1, 30_000)), "adp").decision).toBe("APPROVE");
    expect(parseDecision(await adp.decide(auth(c2, 30_000)), "adp")).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect([await left(c, c2), await left(c, p.id)]).toEqual([30_000, 20_000]);
  });

  it("verify.amount_left у CART — меньшее из остатков CART и родителя", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const cart = await cartUnder(c, p.id, 12_900);
    expect((await c.consent.verify(cart, A))?.amount_left).toBe(12_900);
    expect(parseDecision(await adpFor(c).decide(auth(p.id, 45_000)), "adp").decision).toBe("APPROVE");
    expect((await c.consent.verify(cart, A))?.amount_left).toBe(5_000);
  });
});
