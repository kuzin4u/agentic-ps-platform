// П3 бюджет мандата на удержаниях ядра в памяти (PS-09 К1.2, РП41): коды П3, повтор резерва и закрепления, срок,
// отзыв (A3 п. 6.3), fail-closed (A3 п. 4.5). Та же логика на PostgreSQL — state-pg.test.ts (К1.4).
import { AsyncMemoryHoldLedger, HoldError, type AsyncHoldLedger, type Money } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import type { MandateStatus } from "../../src/consent/model.js";
import {
  accountId,
  holdRef,
  StateService,
  type ClientLimitCheck,
  type MandateBudget,
  type MandateBudgetSource,
} from "../../src/state/index.js";

const M = "mnd_00000000-0000-4000-8000-000000000001";
const RUB = (amount: number): Money => ({ amount, currency: "RUB" });
const TTL = 600;

class Budgets implements MandateBudgetSource {
  readonly map = new Map<string, MandateBudget>();
  failing = false;
  set(id: string, status: MandateStatus, amount_limit = 300_000, currency = "RUB"): this {
    this.map.set(id, { status, amount_limit, currency });
    return this;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    if (this.failing) throw new Error("журнал недоступен");
    return this.map.get(id);
  }
}

/** Ядро с отказом хранилища по выбору: сбой не HoldError — STATE_UNAVAILABLE, без догадки. */
function flaky(inner: AsyncHoldLedger, broken: Set<keyof AsyncHoldLedger>): AsyncHoldLedger {
  return new Proxy(inner, {
    get(t, p, r) {
      const v = Reflect.get(t, p, r) as unknown;
      if (typeof v !== "function") return v;
      return (...a: unknown[]) => {
        if (broken.has(p as keyof AsyncHoldLedger)) return Promise.reject(new Error("ECONNRESET"));
        return (v as (...x: unknown[]) => unknown).apply(t, a);
      };
    },
  });
}

function setup(opts: { clientLimit?: ClientLimitCheck; status?: MandateStatus } = {}) {
  let now = Date.parse("2026-10-19T10:00:00Z");
  const budgets = new Budgets().set(M, opts.status ?? "ACTIVE");
  const ledger = new AsyncMemoryHoldLedger();
  const broken = new Set<keyof AsyncHoldLedger>();
  const logs: string[] = [];
  const state = new StateService(flaky(ledger, broken), budgets, {
    reservationTtlSec: TTL,
    now: () => new Date(now),
    ...(opts.clientLimit ? { clientLimit: opts.clientLimit } : {}),
    log: (_l, _f, msg) => logs.push(msg),
  });
  return { state, ledger, budgets, broken, logs, tick: (sec: number) => (now += sec * 1000), at: () => now };
}

describe("П3 резерв (РП41 п. 4–5)", () => {
  it("счёт = мандат, ref = мандат + ключ операции, срок = now + reservation_ttl_sec", async () => {
    const s = setup();
    expect(await s.state.open(M)).toBe(true);
    const r = await s.state.reserve(M, RUB(100_000), "auth-1");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.hold.account).toBe(accountId(M));
    expect(r.hold.ref).toBe(holdRef(M, "auth-1"));
    expect(r.hold.expires_at).toBe(s.at() + TTL * 1000);
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(200_000));
  });

  it("повтор с тем же ключом, суммой и валютой — прежнее удержание, остаток не уменьшается второй раз", async () => {
    const s = setup();
    const a = await s.state.reserve(M, RUB(100_000), "auth-1");
    const b = await s.state.reserve(M, RUB(100_000), "auth-1");
    expect(a.ok && b.ok && a.hold.id === b.hold.id).toBe(true);
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(200_000));
  });

  it("тот же ключ с другой суммой — IDEMPOTENCY_CONFLICT (REF_CONFLICT ядра)", async () => {
    const s = setup();
    await s.state.reserve(M, RUB(100_000), "auth-1");
    expect(await s.state.reserve(M, RUB(100_001), "auth-1")).toEqual({ ok: false, code: "IDEMPOTENCY_CONFLICT" });
  });

  it("сверх остатка — LIMIT_EXCEEDED (INSUFFICIENT ядра); ровно остаток — принят", async () => {
    const s = setup();
    expect((await s.state.reserve(M, RUB(200_000), "a")).ok).toBe(true);
    expect(await s.state.reserve(M, RUB(100_001), "b")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect((await s.state.reserve(M, RUB(100_000), "c")).ok).toBe(true);
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(0));
  });

  it("20 одновременных по 1 000 ₽ при пределе 3 000 ₽ — принято ровно 3 (ПС10 на памяти ядра)", async () => {
    const s = setup();
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => s.state.reserve(M, RUB(100_000), `op-${i}`)));
    expect(rs.filter((r) => r.ok)).toHaveLength(3);
    expect(rs.filter((r) => !r.ok && r.code === "LIMIT_EXCEEDED")).toHaveLength(17);
    expect((await s.ledger.account(accountId(M))).reserved).toBe(300_000);
  });

  it("валюта операции ≠ валюте мандата — MANDATE_SCOPE, до ядра", async () => {
    const s = setup();
    expect(await s.state.reserve(M, { amount: 100, currency: "USD" }, "a")).toEqual({ ok: false, code: "MANDATE_SCOPE" });
  });

  it.each([0, -1, 1.5, Number.NaN, 2 ** 53])("сумма %s — REQUEST_INVALID: только целые минимальные единицы ≥ 1", async (amount) => {
    const s = setup();
    expect(await s.state.reserve(M, RUB(amount), "a")).toEqual({ ok: false, code: "REQUEST_INVALID" });
  });

  it("пустой ключ операции — REQUEST_INVALID", async () => {
    expect(await setup().state.reserve(M, RUB(1), "")).toEqual({ ok: false, code: "REQUEST_INVALID" });
  });

  it("неизвестный мандат — MANDATE_NOT_FOUND", async () => {
    expect(await setup().state.reserve("mnd_нет", RUB(1), "a")).toEqual({ ok: false, code: "MANDATE_NOT_FOUND" });
  });

  it.each([
    ["PENDING_SIGNATURE", "PRINCIPAL_SIGNATURE_PENDING"],
    ["REVOKED", "MANDATE_REVOKED"],
    ["EXPIRED", "MANDATE_EXPIRED"],
    ["EXHAUSTED", "LIMIT_EXCEEDED"],
    ["REJECTED", "MANDATE_REVOKED"],
  ] as const)("мандат %s — %s, резерва нет", async (status, code) => {
    const s = setup({ status });
    expect(await s.state.reserve(M, RUB(1), "a")).toEqual({ ok: false, code });
    await expect(s.ledger.account(accountId(M))).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
  });

  it("счёт не открыт после подписи — первый резерв открывает его из записи мандата", async () => {
    const s = setup();
    const r = await s.state.reserve(M, RUB(1_000), "a");
    expect(r.ok).toBe(true);
    expect((await s.ledger.account(accountId(M))).limit).toBe(300_000);
  });

  it("счёт с другим пределом (ACCOUNT_CONFLICT) — открытие не удаётся; та же ошибка в резерве — STATE_UNAVAILABLE", async () => {
    const s = setup();
    await s.ledger.openAccount(accountId(M), RUB(999));
    expect(await s.state.open(M)).toBe(false);
    const conflict = new StateService(
      { ...s.ledger, reserve: () => Promise.reject(new HoldError("ACCOUNT_CONFLICT")) } as unknown as AsyncHoldLedger,
      s.budgets,
      { reservationTtlSec: TTL },
    );
    expect(await conflict.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
  });

  it("лимит клиента запрещает — LIMIT_EXCEEDED, резерва нет; сбой лимита — STATE_UNAVAILABLE (меньшее из пределов, A3 п. 7.2)", async () => {
    const deny = setup({ clientLimit: { allows: async () => false } });
    expect(await deny.state.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    const down = setup({ clientLimit: { allows: async () => Promise.reject(new Error("нет связи")) } });
    expect(await down.state.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    await expect(down.ledger.account(accountId(M))).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
  });

  it("журнал не прочитан — STATE_UNAVAILABLE, резерва нет (fail-closed, A3 п. 4.5)", async () => {
    const s = setup();
    s.budgets.failing = true;
    expect(await s.state.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    await expect(s.ledger.account(accountId(M))).rejects.toMatchObject({ code: "UNKNOWN_ACCOUNT" });
  });

  it("сбой хранилища удержаний — STATE_UNAVAILABLE, не LIMIT_EXCEEDED и не догадка", async () => {
    const s = setup();
    await s.state.open(M);
    s.broken.add("reserve");
    expect(await s.state.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    expect(s.logs).toContain("П3: резерв не выполнен");
  });
});

describe("П3 закрепление и освобождение (РП41 п. 6–8)", () => {
  async function reserved(amount = 100_000) {
    const s = setup();
    const r = await s.state.reserve(M, RUB(amount), "auth-1");
    if (!r.ok) throw new Error(r.code);
    return { ...s, hold: r.hold };
  }

  it("полное закрепление: COMMITTED, закреплено растёт, резерв уменьшается", async () => {
    const s = await reserved();
    const c = await s.state.commit(s.hold.id, RUB(100_000));
    expect(c.ok && c.hold.state).toBe("COMMITTED");
    expect(await s.ledger.account(accountId(M))).toMatchObject({ committed: 100_000, reserved: 0 });
  });

  it("частичное представление закрепляет свою сумму, остаток освобождается (A1 п. 6.3)", async () => {
    const s = await reserved();
    const c = await s.state.commit(s.hold.id, RUB(30_000));
    expect(c.ok && c.hold).toMatchObject({ state: "PARTIAL", committed: 30_000, released: 70_000 });
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(270_000));
  });

  it("повтор закрепления той же суммой — прежний результат, закреплено не удваивается", async () => {
    const s = await reserved();
    await s.state.commit(s.hold.id, RUB(30_000));
    const again = await s.state.commit(s.hold.id, RUB(30_000));
    expect(again.ok && again.hold.committed).toBe(30_000);
    expect((await s.ledger.account(accountId(M))).committed).toBe(30_000);
  });

  it("повтор закрепления другой суммой — COMMIT_CONFLICT", async () => {
    const s = await reserved();
    await s.state.commit(s.hold.id, RUB(30_000));
    expect(await s.state.commit(s.hold.id, RUB(40_000))).toEqual({ ok: false, code: "COMMIT_CONFLICT" });
  });

  it("сумма больше резерва или другая валюта — REQUEST_INVALID", async () => {
    const s = await reserved();
    expect(await s.state.commit(s.hold.id, RUB(100_001))).toEqual({ ok: false, code: "REQUEST_INVALID" });
    expect(await s.state.commit(s.hold.id, { amount: 1, currency: "USD" })).toEqual({ ok: false, code: "REQUEST_INVALID" });
  });

  it("освобождение (реверсал) восстанавливает остаток; повтор не меняет состояние (ПС13 на уровне П3)", async () => {
    const s = await reserved();
    const a = await s.state.release(s.hold.id);
    const b = await s.state.release(s.hold.id);
    expect(a.ok && b.ok && b.hold.state).toBe("RELEASED");
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(300_000));
  });

  it("закрепление после освобождения — RESERVATION_RELEASED и инцидент, нового резерва нет", async () => {
    const s = await reserved();
    await s.state.release(s.hold.id);
    expect(await s.state.commit(s.hold.id, RUB(100_000))).toEqual({ ok: false, code: "RESERVATION_RELEASED" });
    expect(s.logs).toContain("П3: поздний клиринг — удержание уже освобождено");
    expect(await s.ledger.account(accountId(M))).toMatchObject({ committed: 0, reserved: 0 });
  });

  it("срок: до прохода expire закрепление проходит; после прохода — RESERVATION_RELEASED", async () => {
    const early = await reserved();
    early.tick(TTL + 1);
    expect((await early.state.commit(early.hold.id, RUB(100_000))).ok).toBe(true);

    const late = await reserved();
    late.tick(TTL - 1);
    expect(await late.state.expire()).toHaveLength(0);
    late.tick(1);
    expect(await late.state.expire()).toHaveLength(1);
    expect(await late.state.commit(late.hold.id, RUB(100_000))).toEqual({ ok: false, code: "RESERVATION_RELEASED" });
    expect(await late.ledger.available(accountId(M))).toEqual(RUB(300_000));
  });

  it("сбой прохода expire — в журнал процесса, без исключения", async () => {
    const s = await reserved();
    s.broken.add("expire");
    expect(await s.state.expire()).toEqual([]);
    expect(s.logs).toContain("П3: проход expire не выполнен");
  });

  it("отзыв: нового резерва нет (MANDATE_REVOKED), закрепление резерва до отзыва — есть (A3 п. 6.3, ПС16)", async () => {
    const s = await reserved();
    s.budgets.set(M, "REVOKED");
    expect(await s.state.reserve(M, RUB(1_000), "auth-2")).toEqual({ ok: false, code: "MANDATE_REVOKED" });
    expect((await s.state.commit(s.hold.id, RUB(100_000))).ok).toBe(true);
  });

  it("сбой хранилища при закреплении и освобождении — STATE_UNAVAILABLE; неизвестное удержание — тоже", async () => {
    const s = await reserved();
    s.broken.add("commit");
    expect(await s.state.commit(s.hold.id, RUB(1))).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    s.broken.add("release");
    expect(await s.state.release(s.hold.id)).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    s.broken.clear();
    expect(await s.state.release("HLD-нет")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
  });

  it("HoldError ядра — тот же класс, что импортирует П3 (иначе коды молча ушли бы в STATE_UNAVAILABLE)", async () => {
    const s = setup();
    await expect(s.ledger.account("нет")).rejects.toBeInstanceOf(HoldError);
  });
});
