// П3 → П2 (PS-09 К1.5, РП41 п. 10–11): verify.amount_left из П3 и STATE_UNKNOWN; MANDATE_EXHAUSTED и mandate.exhausted —
// по закреплению всего предела, не по резерву; дописывание при отказе в резерве (доп. 1) и при повторе закрепления;
// свёртка (дубль, отзыв после исчерпания), CART при EXHAUSTED родителе, отзыв EXHAUSTED — без записи.
import { AsyncHashChainJournal, AsyncMemoryHoldLedger, type AsyncHoldLedger } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { MemoryConsentStore } from "../../src/consent/store.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { A, decide, intent, mk, revoke, setup, T0, type Ctx } from "../support/state.js";

const RUB = (amount: number) => ({ amount, currency: "RUB" });

async function active(c: Ctx, req: MandateRequest = intent()) {
  const m = await mk(c, req);
  await decide(c, m);
  return m;
}

async function kinds(store: MemoryConsentStore, id: string): Promise<string[]> {
  const row = (await store.getMandate(id))!;
  return (await store.journal(row.chain).all()).filter((e) => e.ref === id).map((e) => e.kind);
}

async function exhaustedEvents(c: Ctx, id: string) {
  return (await c.consent.events(A, undefined, 100)).filter((e) => e.type === "mandate.exhausted" && e.data.mandate_id === id);
}

/** Удержания, у которых можно уронить чтение: сбой П3 → verify STATE_UNKNOWN. */
function breakable(): { ledger: AsyncHoldLedger; down: { on: boolean } } {
  const inner = new AsyncMemoryHoldLedger();
  const down = { on: false };
  const ledger = new Proxy(inner, {
    get(t, p, r) {
      const v = Reflect.get(t, p, r) as unknown;
      if (typeof v !== "function") return v;
      return (...a: unknown[]) => (down.on ? Promise.reject(new Error("ECONNRESET")) : (v as (...x: unknown[]) => unknown).apply(t, a));
    },
  });
  return { ledger, down };
}

describe("verify.amount_left из П3 (РП41 п. 10)", () => {
  it("уменьшается резервом, восстанавливается освобождением; исход CONFIRMED", async () => {
    const c = setup();
    const m = await active(c);
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "CONFIRMED", amount_left: 50_000 });
    const r = await c.state.reserve(m.id, RUB(20_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "CONFIRMED", amount_left: 30_000 });
    await c.state.release(r.hold.id);
    expect((await c.consent.verify(m.id, A))?.amount_left).toBe(50_000);
  });

  it("резерв на весь предел — CONFIRMED с amount_left 0, статус ACTIVE, записи исчерпания нет (по резерву не исчерпан)", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    expect((await c.state.reserve(m.id, RUB(50_000), "auth-1")).ok).toBe(true);
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "CONFIRMED", amount_left: 0 });
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    expect(await c.state.reserve(m.id, RUB(1), "auth-2")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await kinds(store, m.id)).not.toContain("MANDATE_EXHAUSTED");
  });

  it("счёта ещё нет — предел; чтение счёт не открывает", async () => {
    const { ledger } = breakable();
    const c = setup({ ledger });
    const m = await mk(c);
    expect(await c.state.amountLeft(m.id, 50_000)).toBe(50_000);
    await expect(ledger.account(`mandate:${m.id}`)).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
  });

  it("сбой П3 при целом журнале — 200 STATE_UNKNOWN, amount_left 0 (A7 п. 8.6); чтение не пишет", async () => {
    const { ledger, down } = breakable();
    const store = new MemoryConsentStore();
    const c = setup({ ledger, store });
    const m = await active(c);
    down.on = true;
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "STATE_UNKNOWN", amount_left: 0 });
    expect(await kinds(store, m.id)).toEqual(["MANDATE_REQUESTED", "MANDATE_SIGNED"]);
  });
});

describe("MANDATE_EXHAUSTED и mandate.exhausted (РП41 п. 11)", () => {
  it("закрепление всего предела — запись, статус EXHAUSTED, одно событие {mandate_id}; verify OUT_OF_SCOPE 0; резерв — LIMIT_EXCEEDED", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    const a = await c.state.reserve(m.id, RUB(30_000), "a");
    const b = await c.state.reserve(m.id, RUB(20_000), "b");
    if (!a.ok || !b.ok) throw new Error("резерв");
    await c.state.commit(a.hold.id, RUB(30_000));
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    await c.state.commit(b.hold.id, RUB(20_000));
    expect(await kinds(store, m.id)).toEqual(["MANDATE_REQUESTED", "MANDATE_SIGNED", "MANDATE_EXHAUSTED"]);
    const row = (await store.getMandate(m.id))!;
    const rec = (await store.journal(row.chain).all()).find((e) => e.kind === "MANDATE_EXHAUSTED")!;
    expect(rec.payload).toEqual({ committed: 50_000, currency: "RUB" });
    expect((await c.consent.get(m.id, A))?.status).toBe("EXHAUSTED");
    const ev = await exhaustedEvents(c, m.id);
    expect(ev).toHaveLength(1);
    expect(ev[0]!.data).toEqual({ mandate_id: m.id });
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "OUT_OF_SCOPE", amount_left: 0 });
    expect(await c.state.reserve(m.id, RUB(1), "c")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await exhaustedEvents(c, m.id)).toHaveLength(1);
  });

  it("частичное представление освобождает остаток — предел не закреплён, исчерпания нет", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    await c.state.commit(r.hold.id, RUB(49_999));
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    expect(await c.consent.verify(m.id, A)).toMatchObject({ outcome: "CONFIRMED", amount_left: 1 });
  });

  it("доп. 1: сбой записи после commit — следующий отказ в резерве дописывает запись; событие одно, ответ LIMIT_EXCEEDED", async () => {
    const store = new MemoryConsentStore();
    let failOnce = true;
    const logs: string[] = [];
    const c: Ctx = setup({
      store,
      exhausted: async (id, p) => {
        if (failOnce) {
          failOnce = false;
          throw new Error("журнал недоступен");
        }
        return c.consent.exhausted(id, p);
      },
      log: (msg) => logs.push(msg),
    });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    expect((await c.state.commit(r.hold.id, RUB(50_000))).ok).toBe(true);
    expect(logs).toContain("П3: запись MANDATE_EXHAUSTED не выполнена");
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    expect(await exhaustedEvents(c, m.id)).toHaveLength(0);
    expect(await c.state.reserve(m.id, RUB(1), "b")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect((await c.consent.get(m.id, A))?.status).toBe("EXHAUSTED");
    expect(await exhaustedEvents(c, m.id)).toHaveLength(1);
    expect(await c.state.reserve(m.id, RUB(1), "c")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await kinds(store, m.id)).toEqual(["MANDATE_REQUESTED", "MANDATE_SIGNED", "MANDATE_EXHAUSTED"]);
  });

  it("сбой записи после commit — повтор закрепления дописывает запись (РП41 п. 7, 11)", async () => {
    let failOnce = true;
    const c: Ctx = setup({
      exhausted: async (id, p) => {
        if (failOnce) {
          failOnce = false;
          throw new Error("журнал недоступен");
        }
        return c.consent.exhausted(id, p);
      },
    });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    await c.state.commit(r.hold.id, RUB(50_000));
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    expect((await c.state.commit(r.hold.id, RUB(50_000))).ok).toBe(true);
    expect((await c.consent.get(m.id, A))?.status).toBe("EXHAUSTED");
  });

  it("10 одновременных повторов закрепления и отказов в резерве — одна запись, одно событие (лок записи по мандату)", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    await Promise.all([
      ...Array.from({ length: 5 }, () => c.state.commit(r.hold.id, RUB(50_000))),
      ...Array.from({ length: 5 }, (_, i) => c.state.reserve(m.id, RUB(1), `x-${i}`)),
    ]);
    expect((await kinds(store, m.id)).filter((k) => k === "MANDATE_EXHAUSTED")).toHaveLength(1);
    expect(await exhaustedEvents(c, m.id)).toHaveLength(1);
  });

  it("отзыв и отказ агента при EXHAUSTED — 200 с текущим статусом, без записи (как EXPIRED, РП38)", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    await c.state.commit(r.hold.id, RUB(50_000));
    expect(await revoke(c, m)).toBe(200);
    expect((await c.consent.relinquish(m.id, A, "kid"))?.status).toBe("EXHAUSTED");
    expect(await kinds(store, m.id)).toEqual(["MANDATE_REQUESTED", "MANDATE_SIGNED", "MANDATE_EXHAUSTED"]);
  });

  it("свёртка: дубль MANDATE_EXHAUSTED пропускается; отзыв после исчерпания (два экземпляра) — REVOKED; срок на EXHAUSTED не действует", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const m = await active(c);
    const r = await c.state.reserve(m.id, RUB(50_000), "a");
    if (!r.ok) throw new Error(r.code);
    await c.state.commit(r.hold.id, RUB(50_000));
    const row = (await store.getMandate(m.id))!;
    const j = new AsyncHashChainJournal(store.journal(row.chain), () => T0.toISOString());
    await j.append("MANDATE_EXHAUSTED", m.id, { committed: 50_000, currency: "RUB" }, m.id);
    expect((await c.consent.get(m.id, A))?.status).toBe("EXHAUSTED");
    await j.append("MANDATE_REVOKED", m.id, {}, m.id);
    expect((await c.consent.get(m.id, A))?.status).toBe("REVOKED");
  });

  it("CART: родитель EXHAUSTED → CART EXHAUSTED, резерв по CART — LIMIT_EXCEEDED; свой предел CART исчерпывается своим закреплением", async () => {
    const c = setup();
    const cartReq = (parent_id: string): MandateRequest =>
      intent({
        type: "CART",
        parent_id,
        subject: "корзина SHOP-1042",
        amount_limit: 12_900,
        cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
      });
    const p = await active(c);
    const cart = await active(c, cartReq(p.id));
    const r = await c.state.reserve(p.id, RUB(50_000), "p");
    if (!r.ok) throw new Error(r.code);
    await c.state.commit(r.hold.id, RUB(50_000));
    expect((await c.consent.get(cart.id, A))?.status).toBe("EXHAUSTED");
    expect(await c.state.reserve(cart.id, RUB(1), "c")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await c.consent.verify(cart.id, A)).toMatchObject({ outcome: "OUT_OF_SCOPE", amount_left: 0 });

    const p2 = await active(c);
    const cart2 = await active(c, cartReq(p2.id));
    const h = await c.state.reserve(cart2.id, RUB(12_900), "c2");
    if (!h.ok) throw new Error(h.code);
    await c.state.commit(h.hold.id, RUB(12_900));
    expect((await c.consent.get(cart2.id, A))?.status).toBe("EXHAUSTED");
    expect((await c.consent.get(p2.id, A))?.status).toBe("ACTIVE");
    expect(await exhaustedEvents(c, cart2.id)).toHaveLength(1);
  });
});
