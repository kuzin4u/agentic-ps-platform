// П3 бюджет мандата на удержаниях ядра в памяти (PS-09 К1.2, РП41): коды П3, повтор резерва и закрепления, срок,
// отзыв (A3 п. 6.3), fail-closed (A3 п. 4.5). Та же логика на PostgreSQL — state-pg.test.ts (К1.4).
import { AsyncMemoryHoldLedger, HoldError, type AsyncHoldLedger, type Money } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import type { MandateStatus } from "../../src/consent/model.js";
import {
  accountId,
  clientAccountId,
  clientHoldRef,
  holdRef,
  StateService,
  type ClientAccount,
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

/**
 * Ядро с отказом хранилища по выбору: сбой не HoldError — STATE_UNAVAILABLE, без догадки. calls — имена вызовов StateService
 * (обычный путь резерва клиента — account и reserve, РП46 (г)); hooks.beforeSetLimit — вмешательство другого экземпляра
 * между чтением счёта и setLimit (гонка сужения с резервом).
 */
function flaky(
  inner: AsyncHoldLedger,
  broken: Set<keyof AsyncHoldLedger>,
  calls: string[],
  hooks: { beforeSetLimit?: () => Promise<void> },
): AsyncHoldLedger {
  return new Proxy(inner, {
    get(t, p, r) {
      const v = Reflect.get(t, p, r) as unknown;
      if (typeof v !== "function") return v;
      return async (...a: unknown[]) => {
        calls.push(String(p));
        if (broken.has(p as keyof AsyncHoldLedger)) throw new Error("ECONNRESET");
        if (p === "setLimit") await hooks.beforeSetLimit?.();
        return (v as (...x: unknown[]) => unknown).apply(t, a);
      };
    },
  });
}

function setup(opts: { status?: MandateStatus } = {}) {
  let now = Date.parse("2026-10-19T10:00:00Z");
  const budgets = new Budgets().set(M, opts.status ?? "ACTIVE");
  const ledger = new AsyncMemoryHoldLedger();
  const broken = new Set<keyof AsyncHoldLedger>();
  const logs: string[] = [];
  const calls: string[] = [];
  const hooks: { beforeSetLimit?: () => Promise<void> } = {};
  const state = new StateService(flaky(ledger, broken, calls, hooks), budgets, {
    reservationTtlSec: TTL,
    now: () => new Date(now),
    log: (_l, _f, msg) => logs.push(msg),
  });
  return {
    state,
    ledger,
    budgets,
    broken,
    logs,
    calls,
    set beforeSetLimit(f: (() => Promise<void>) | undefined) {
      hooks.beforeSetLimit = f;
    },
    tick: (sec: number) => (now += sec * 1000),
    at: () => now,
  };
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

  it("повтор ключа после освобождения или прохода expire — RESERVATION_RELEASED, не ok: бюджет не удержан (/audit № 1)", async () => {
    const s = setup();
    const r = await s.state.reserve(M, RUB(100_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    await s.state.release(r.hold.id);
    expect(await s.state.reserve(M, RUB(100_000), "auth-1")).toEqual({ ok: false, code: "RESERVATION_RELEASED" });
    const e = await s.state.reserve(M, RUB(100_000), "auth-2");
    s.tick(TTL);
    await s.state.expire();
    expect(e.ok).toBe(true);
    expect(await s.state.reserve(M, RUB(100_000), "auth-2")).toEqual({ ok: false, code: "RESERVATION_RELEASED" });
    expect(await s.ledger.available(accountId(M))).toEqual(RUB(300_000));
  });

  it("повтор ключа после закрепления — прежнее удержание (операция уже исполнена, бюджет израсходован)", async () => {
    const s = setup();
    const r = await s.state.reserve(M, RUB(100_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    await s.state.commit(r.hold.id, RUB(40_000));
    const again = await s.state.reserve(M, RUB(100_000), "auth-1");
    expect(again.ok && again.hold).toMatchObject({ id: r.hold.id, state: "PARTIAL", committed: 40_000 });
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

  it("валюта не по форме ISO 4217 — REQUEST_INVALID, а не MANDATE_SCOPE (/audit № 12)", async () => {
    expect(await setup().state.reserve(M, { amount: 1, currency: "rub" }, "a")).toEqual({ ok: false, code: "REQUEST_INVALID" });
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
    expect(s.logs).toContain("П3: инцидент — счёт мандата с другим пределом");
    const conflict = new StateService(
      { ...s.ledger, reserve: () => Promise.reject(new HoldError("ACCOUNT_CONFLICT")) } as unknown as AsyncHoldLedger,
      s.budgets,
      { reservationTtlSec: TTL },
    );
    expect(await conflict.reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
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

describe("П3 лимит клиента вторым счётом удержаний (РП45 п. 1)", () => {
  const CLIENT = (limit: number, over: Partial<ClientAccount> = {}): ClientAccount => ({
    participant_code: "bank:a",
    principal_ref: "prn_7f3c9a",
    period: "DAY",
    period_start: "2026-10-19",
    limit: RUB(limit),
    ...over,
  });

  it("счёт клиента за период, ref — клиент + ключ операции; повтор — то же удержание; сверх предела — LIMIT_EXCEEDED", async () => {
    const s = setup();
    const r = await s.state.reserveClient(CLIENT(3_000), RUB(1_000), "auth-1");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.hold.account).toBe(clientAccountId(CLIENT(3_000)));
    expect(r.hold.account).toBe("client:bank:a:prn_7f3c9a:DAY:2026-10-19");
    expect(r.hold.ref).toBe(clientHoldRef(CLIENT(3_000), "auth-1"));
    expect(r.hold.expires_at).toBe(s.at() + TTL * 1000);
    const again = await s.state.reserveClient(CLIENT(3_000), RUB(1_000), "auth-1");
    expect(again.ok && again.hold.id).toBe(r.hold.id);
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(2_000), "auth-2")).ok).toBe(true);
    expect(await s.state.reserveClient(CLIENT(3_000), RUB(1), "auth-3")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await s.state.clientLeft(CLIENT(3_000))).toBe(0);
    // Тот же op_key с другой суммой — инцидент повтора, а не второй резерв.
    expect(await s.state.reserveClient(CLIENT(3_000), RUB(5), "auth-1")).toEqual({ ok: false, code: "IDEMPOTENCY_CONFLICT" });
  });

  it("одновременные резервы по одному клиенту — одобрений не больше предела (неделимость ядра, инвариант 4)", async () => {
    const s = setup();
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => s.state.reserveClient(CLIENT(3_000), RUB(1_000), `burst-${i}`)));
    expect(rs.filter((r) => r.ok)).toHaveLength(3);
    expect(rs.filter((r) => !r.ok && r.code === "LIMIT_EXCEEDED")).toHaveLength(17);
  });

  it("новый период — новый счёт; предел 0 — LIMIT_EXCEEDED без счёта", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(1_000), RUB(1_000), "d1")).ok).toBe(true);
    expect((await s.state.reserveClient(CLIENT(1_000, { period_start: "2026-10-20" }), RUB(1_000), "d2")).ok).toBe(true);
    expect(await s.state.reserveClient(CLIENT(0), RUB(1), "z")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await s.state.clientLeft(CLIENT(500, { period_start: "2026-10-21" }))).toBe(500);
  });

  it("расширение в периоде — сразу: предел счёта = запись (setLimit, РП46 (г))", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(2_000), RUB(1_500), "w1")).ok).toBe(true);
    // Банк расширил до 5 000 (после подтверждения клиентом, ПИ-8): действует сразу, не со следующего периода.
    expect((await s.state.reserveClient(CLIENT(5_000), RUB(3_500), "w2")).ok).toBe(true);
    expect(await s.ledger.account(clientAccountId(CLIENT(5_000)))).toMatchObject({ limit: 5_000, reserved: 5_000 });
    expect(await s.state.reserveClient(CLIENT(5_000), RUB(1), "w3")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
  });

  it("сужение выше удержанного — сразу: остаток по новому пределу", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(1_000), "n1")).ok).toBe(true);
    expect(await s.state.clientLeft(CLIENT(1_500))).toBe(500);
    expect(await s.state.reserveClient(CLIENT(1_500), RUB(600), "n2")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await s.ledger.account(clientAccountId(CLIENT(1_500)))).toMatchObject({ limit: 1_500, reserved: 1_000 });
    expect((await s.state.reserveClient(CLIENT(1_500), RUB(500), "n3")).ok).toBe(true);
  });

  it("сужение ниже удержанного — предел = committed + reserved, остаток 0; после освобождения — снова по записи", async () => {
    const s = setup();
    const r1 = await s.state.reserveClient(CLIENT(3_000), RUB(2_000), "b1");
    expect(r1.ok).toBe(true);
    // Банк сузил до 1 000 при удержанных 2 000: прошлое не отменяется (A3 п. 6.3), новых резервов нет.
    expect(await s.state.reserveClient(CLIENT(1_000), RUB(1), "b2")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(await s.ledger.account(clientAccountId(CLIENT(1_000)))).toMatchObject({ limit: 2_000, reserved: 2_000 });
    expect(await s.state.clientLeft(CLIENT(1_000))).toBe(0);
    // Уже суженный до использованного счёт setLimit не вызывает (РП46 (г) п. 1, З3).
    const calls = s.calls.length;
    expect(await s.state.reserveClient(CLIENT(1_000), RUB(1), "b3")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(s.calls.slice(calls)).not.toContain("setLimit");
    // Удержание освобождено — предел снова приводится к записи: освобождённое запись не превышает.
    if (r1.ok) await s.ledger.release(r1.hold.id);
    expect(await s.state.clientLeft(CLIENT(1_000))).toBe(1_000);
    expect((await s.state.reserveClient(CLIENT(1_000), RUB(1_000), "b4")).ok).toBe(true);
    expect(await s.ledger.account(clientAccountId(CLIENT(1_000)))).toMatchObject({ limit: 1_000, reserved: 1_000 });
    expect(await s.state.reserveClient(CLIENT(1_000), RUB(1), "b5")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
  });

  it("обычный путь — account и reserve, без setLimit; расхождение — один setLimit", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(100), "p1")).ok).toBe(true);
    let from = s.calls.length;
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(100), "p2")).ok).toBe(true);
    expect(s.calls.slice(from)).toEqual(["account", "reserve"]);
    from = s.calls.length;
    expect((await s.state.reserveClient(CLIENT(2_000), RUB(100), "p3")).ok).toBe(true);
    expect(s.calls.slice(from)).toEqual(["account", "setLimit", "reserve"]);
  });

  it("гонка сужения с резервом: LIMIT_BELOW_USED — перечитать и повторить; одобрений не больше суженного предела", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(500), "g0")).ok).toBe(true);
    // Между чтением счёта и setLimit другой экземпляр резервирует по старой записи (3 000) — setLimit(1 000) ниже
    // использованного (LIMIT_BELOW_USED): перечитать, сузить до использованного.
    s.beforeSetLimit = async () => {
      s.beforeSetLimit = undefined;
      await s.ledger.reserve(clientAccountId(CLIENT(3_000)), RUB(1_000), "client:bank:a:prn_7f3c9a:op:g1", null);
    };
    expect(await s.state.reserveClient(CLIENT(1_000), RUB(1), "g2")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    expect(s.calls.filter((c) => c === "setLimit")).toHaveLength(2);
    expect(await s.ledger.account(clientAccountId(CLIENT(1_000)))).toMatchObject({ limit: 1_500, reserved: 1_500 });
  });

  it("гонка с резервом три раза подряд — STATE_UNAVAILABLE без резерва (fail-closed)", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(9_000), RUB(500), "h0")).ok).toBe(true);
    let n = 0;
    s.beforeSetLimit = async () => {
      await s.ledger.reserve(clientAccountId(CLIENT(9_000)), RUB(1_000), `client:bank:a:prn_7f3c9a:op:race-${++n}`, null);
    };
    expect(await s.state.reserveClient(CLIENT(1_000), RUB(1), "h1")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    expect(s.logs).toContain("П3: предел счёта клиента не приведён к записи за три попытки — резерва нет");
  });

  it("одновременные резервы и сужение — сумма одобрений после сужения не выше нового предела (инвариант 4)", async () => {
    const s = setup();
    expect((await s.state.reserveClient(CLIENT(3_000), RUB(100), "c0")).ok).toBe(true);
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => s.state.reserveClient(CLIENT(1_000), RUB(100), `cc-${i}`)));
    expect(rs.filter((r) => r.ok)).toHaveLength(9);
    expect(await s.ledger.account(clientAccountId(CLIENT(1_000)))).toMatchObject({ limit: 1_000, reserved: 1_000 });
  });

  it("валюта лимита ≠ валюте операции, сбой хранилища — STATE_UNAVAILABLE без резерва (A3 п. 4.5)", async () => {
    const s = setup();
    expect(await s.state.reserveClient(CLIENT(3_000), { amount: 100, currency: "USD" }, "c1")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    s.broken.add("openAccount");
    expect(await s.state.reserveClient(CLIENT(3_000), RUB(100), "c2")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    s.broken.clear();
    s.broken.add("reserve");
    expect(await s.state.reserveClient(CLIENT(3_000), RUB(100), "c3")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
    s.broken.add("account");
    expect(await s.state.clientLeft(CLIENT(3_000))).toBeUndefined();
  });
});
