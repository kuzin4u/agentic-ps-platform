// П3 подключение (PS-09 К1.3, РП41 п. 3–4, 6): бюджет из журнала согласий (свёртка, у CART — с родителем), счёт
// открывается после MANDATE_SIGNED (сбой — первым резервом), отзыв закрывает новые резервы, таймер прохода expire.
import { AsyncMemoryHoldLedger } from "@kuzin4u/agentic-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { accountId, startReservationExpiry, StateService } from "../../src/state/index.js";
import { A, decide, intent, mk, revoke, setup, T0 } from "../support/state.js";

describe("П3 ← журнал согласий (РП41 п. 3–4)", () => {
  it("подпись SIGN открывает счёт мандата с пределом и валютой из записи; повтор подписи — тот же счёт", async () => {
    const c = setup();
    const m = await mk(c);
    expect(await decide(c, m)).toBe(200);
    expect(await c.ledger.account(accountId(m.id))).toMatchObject({ limit: 50_000, currency: "RUB", committed: 0, reserved: 0 });
    expect(await decide(c, m)).toBe(200);
    expect((await c.ledger.account(accountId(m.id))).limit).toBe(50_000);
  });

  it("REJECT — счёта нет, резерв — MANDATE_REVOKED (доп. РП41 п. 5: «отозван или отклонён», агенту — стоп)", async () => {
    const c = setup();
    const m = await mk(c);
    expect(await decide(c, m, "REJECT")).toBe(200);
    await expect(c.ledger.account(accountId(m.id))).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
    expect(await c.state.reserve(m.id, { amount: 1, currency: "RUB" }, "a")).toEqual({ ok: false, code: "MANDATE_REVOKED" });
  });

  it("сбой открытия счёта не меняет ответ банку (200 ACTIVE); первый резерв открывает счёт", async () => {
    const inner = new AsyncMemoryHoldLedger();
    let down = true;
    const ledger = new Proxy(inner, {
      get(t, p, r) {
        const v = Reflect.get(t, p, r) as unknown;
        if (p === "openAccount" && down) return () => Promise.reject(new Error("ECONNRESET"));
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const c = setup({ ledger });
    const m = await mk(c);
    expect(await decide(c, m)).toBe(200);
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    await expect(inner.account(accountId(m.id))).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
    down = false;
    expect((await c.state.reserve(m.id, { amount: 20_000, currency: "RUB" }, "auth-1")).ok).toBe(true);
    expect(await inner.available(accountId(m.id))).toEqual({ amount: 30_000, currency: "RUB" });
  });

  it("до подписи — PRINCIPAL_SIGNATURE_PENDING; после отзыва — MANDATE_REVOKED, а закрепление резерва до отзыва проходит (ПС16 в П3)", async () => {
    const c = setup();
    const m = await mk(c);
    expect(await c.state.reserve(m.id, { amount: 1, currency: "RUB" }, "a")).toEqual({ ok: false, code: "PRINCIPAL_SIGNATURE_PENDING" });
    await decide(c, m);
    const r = await c.state.reserve(m.id, { amount: 10_000, currency: "RUB" }, "auth-1");
    if (!r.ok) throw new Error(r.code);
    expect(await revoke(c, m)).toBe(200);
    expect(await c.state.reserve(m.id, { amount: 1, currency: "RUB" }, "auth-2")).toEqual({ ok: false, code: "MANDATE_REVOKED" });
    expect((await c.state.commit(r.hold.id, { amount: 10_000, currency: "RUB" })).ok).toBe(true);
  });

  it("CART: статус вместе с родителем — родитель отозван, резерв по CART — MANDATE_REVOKED (РП35 п. 2)", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const cart = await mk(
      c,
      intent({
        type: "CART",
        parent_id: p.id,
        subject: "корзина SHOP-1042",
        amount_limit: 12_900,
        cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
      }),
    );
    await decide(c, cart);
    expect((await c.ledger.account(accountId(cart.id))).limit).toBe(12_900);
    await revoke(c, p);
    expect(await c.consent.budget(cart.id)).toMatchObject({ status: "REVOKED" });
    expect(await c.state.reserve(cart.id, { amount: 1, currency: "RUB" }, "a")).toEqual({ ok: false, code: "MANDATE_REVOKED" });
  });

  it("budget: неизвестный и не по маске — undefined (MANDATE_NOT_FOUND); сбой хранилища — исключение → STATE_UNAVAILABLE", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    expect(await c.consent.budget("mnd_00000000-0000-4000-8000-00000000dead")).toBeUndefined();
    expect(await c.consent.budget("../x")).toBeUndefined();
    const m = await mk(c);
    await decide(c, m);
    vi.spyOn(store, "getMandate").mockRejectedValueOnce(new Error("ECONNRESET"));
    expect(await c.state.reserve(m.id, { amount: 1, currency: "RUB" }, "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
  });
});

describe("П3 таймер прохода expire (РП41 п. 6)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("проход по таймеру освобождает истёкшие резервы; остановка ждёт текущий проход", async () => {
    const ledger = new AsyncMemoryHoldLedger();
    let now = T0.getTime();
    const budgets = { budget: async () => ({ status: "ACTIVE" as const, amount_limit: 1_000, currency: "RUB" }) };
    const state = new StateService(ledger, budgets, { reservationTtlSec: 60, now: () => new Date(now) });
    const M = "mnd_00000000-0000-4000-8000-000000000001";
    expect((await state.reserve(M, { amount: 1_000, currency: "RUB" }, "a")).ok).toBe(true);
    const stop = startReservationExpiry(state, 1_000);
    now += 61_000;
    await vi.advanceTimersByTimeAsync(1_000);
    await stop();
    expect(await ledger.available(accountId(M))).toEqual({ amount: 1_000, currency: "RUB" });
  });
});
