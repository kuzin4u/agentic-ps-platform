// П3 на PostgreSQL (PS-09 К1.4, РП41 п. 2, 12; инвариант 4, A3 п. 4.4): путь Платформы — StateService на PgHoldLedger
// ядра. ПС10 на уровне П3: одновременные резервы сверх предела — принято ровно столько, сколько помещается, перерасхода
// нет ни на копейку, в том числе с двух экземпляров (два пула). Два одновременных прохода expire — без ошибки и без
// двойного освобождения. В CI (РП30 п. 7); локально без базы — пропуск.
import { PgHoldLedger, type Money } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgConsentStore } from "../../src/consent/store.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { A, decide, mk, setup } from "../support/state.js";

const RUB = (amount: number): Money => ({ amount, currency: "RUB" });
const TTL = 600;
let seq = 0;
const mandate = (): string => `mnd_00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

/** Бюджет из записи мандата: здесь проверяется атомарность удержаний, журнал согласий — в state-wiring.test.ts. */
class Budgets implements MandateBudgetSource {
  readonly map = new Map<string, MandateBudget>();
  add(limit: number): string {
    const id = mandate();
    this.map.set(id, { status: "ACTIVE", amount_limit: limit, currency: "RUB" });
    return id;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    return this.map.get(id);
  }
}

describe.skipIf(!DATABASE_URL)("П3 на PostgreSQL: StateService + PgHoldLedger (РП41, ПС10)", () => {
  let db: TestDb;
  let now = Date.parse("2026-10-19T10:00:00Z");
  const budgets = new Budgets();
  const warns: string[] = [];
  const service = (pool: TestDb["pool"]): StateService =>
    new StateService(new PgHoldLedger(pool), budgets, {
      reservationTtlSec: TTL,
      now: () => new Date(now),
      log: (level, _f, msg) => level === "warn" && warns.push(msg),
    });
  let s1: StateService;
  let s2: StateService;
  let ledger: PgHoldLedger;

  beforeAll(async () => {
    db = await openTestDb("state");
    s1 = service(db.pool);
    s2 = service(db.reopen());
    ledger = new PgHoldLedger(db.pool);
  });
  afterAll(async () => {
    await db?.close();
  });

  it("20 одновременных резервов по 1 000 ₽ при пределе 3 000 ₽ — принято ровно 3, reserved = 300 000 коп.", async () => {
    const M = budgets.add(300_000);
    expect(await s1.open(M)).toBe(true);
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => s1.reserve(M, RUB(100_000), `op-${i}`)));
    const accepted = rs.filter((r) => r.ok).length;
    expect(accepted, `перерасход бюджета: принято ${accepted} резервов при месте для 3 (инвариант 4)`).toBe(3);
    expect(rs.filter((r) => !r.ok && r.code === "LIMIT_EXCEEDED")).toHaveLength(17);
    const a = await ledger.account(accountId(M));
    expect(a.reserved + a.committed, "перерасход бюджета: закреплено + зарезервировано > предела").toBeLessThanOrEqual(a.limit);
    expect(a.reserved).toBe(300_000);
  });

  it("два экземпляра (два пула), по 10 резервов на 70 000 коп. при пределе 300 000 — принято ровно 4, без открытого заранее счёта", async () => {
    const M = budgets.add(300_000);
    const rs = await Promise.all(
      Array.from({ length: 20 }, (_, i) => (i % 2 === 0 ? s1 : s2).reserve(M, RUB(70_000), `op-${i}`)),
    );
    const accepted = rs.filter((r) => r.ok).length;
    expect(accepted, `перерасход бюджета с двух экземпляров: принято ${accepted} при месте для 4`).toBe(4);
    expect(rs.every((r) => r.ok || r.code === "LIMIT_EXCEEDED")).toBe(true);
    expect((await ledger.account(accountId(M))).reserved).toBe(280_000);
  });

  it("20 одновременных повторов одного ключа операции — одно удержание (идемпотентность по ref на PG)", async () => {
    const M = budgets.add(300_000);
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? s1 : s2).reserve(M, RUB(100_000), "auth-1")));
    expect(new Set(rs.map((r) => (r.ok ? r.hold.id : r.code))).size).toBe(1);
    expect((await ledger.account(accountId(M))).reserved).toBe(100_000);
  });

  it("закрепление на PG: частичное с освобождением остатка, повтор — без удвоения, другая сумма — COMMIT_CONFLICT", async () => {
    const M = budgets.add(300_000);
    const r = await s1.reserve(M, RUB(100_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    const all = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? s1 : s2).commit(r.hold.id, RUB(30_000))));
    expect(all.every((x) => x.ok && x.hold.committed === 30_000)).toBe(true);
    expect(await ledger.account(accountId(M))).toMatchObject({ committed: 30_000, reserved: 0 });
    expect(await s2.commit(r.hold.id, RUB(40_000))).toEqual({ ok: false, code: "COMMIT_CONFLICT" });
  });

  it("освобождение на PG: остаток восстановлен, повтор не меняет; закрепление после — RESERVATION_RELEASED", async () => {
    const M = budgets.add(300_000);
    const r = await s1.reserve(M, RUB(100_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    await Promise.all([s1.release(r.hold.id), s2.release(r.hold.id)]);
    expect(await ledger.available(accountId(M))).toEqual(RUB(300_000));
    expect(await s1.commit(r.hold.id, RUB(100_000))).toEqual({ ok: false, code: "RESERVATION_RELEASED" });
    expect(await ledger.account(accountId(M))).toMatchObject({ committed: 0, reserved: 0 });
  });

  it("два одновременных прохода expire — без ошибки, каждое удержание освобождено один раз (ревью из чата к РП41)", async () => {
    const M = budgets.add(500_000);
    const holds = await Promise.all(Array.from({ length: 5 }, (_, i) => s1.reserve(M, RUB(100_000), `exp-${i}`)));
    expect(holds.every((h) => h.ok)).toBe(true);
    now += TTL * 1000 + 1;
    warns.length = 0;
    const [a, b] = await Promise.all([s1.expire(), s2.expire()]);
    expect(warns, "проход expire упал").toEqual([]);
    const ours = [...a, ...b].filter((h) => h.account === accountId(M));
    expect(ours).toHaveLength(5);
    expect(new Set(ours.map((h) => h.id)).size).toBe(5);
    for (const h of holds) if (h.ok) expect(await ledger.get(h.hold.id)).toMatchObject({ state: "RELEASED", released: 100_000 });
    expect(await ledger.account(accountId(M))).toMatchObject({ committed: 0, reserved: 0 });
    expect(await s1.expire()).toEqual([]);
  });

  it("сбой базы — STATE_UNAVAILABLE, не LIMIT_EXCEEDED (fail-closed, A3 п. 4.5)", async () => {
    const M = budgets.add(300_000);
    const dead = db.reopen();
    await dead.end();
    expect(await service(dead).reserve(M, RUB(1), "a")).toEqual({ ok: false, code: "STATE_UNAVAILABLE" });
  });
});

describe.skipIf(!DATABASE_URL)("П3 → П2 на PostgreSQL: MANDATE_EXHAUSTED и mandate.exhausted в одной транзакции (РП41 п. 11, РП39 п. 1)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("exhaust");
  });
  afterAll(async () => {
    await db?.close();
  });

  it("закрепление всего предела с двух экземпляров — одна запись в цепочке, одно событие в pao_events, статус EXHAUSTED", async () => {
    const store = new PgConsentStore(db.pool);
    const c1 = setup({ store, ledger: new PgHoldLedger(db.pool) });
    const c2 = setup({ store: new PgConsentStore(db.reopen()), ledger: new PgHoldLedger(db.reopen()) });
    const m = await mk(c1);
    expect(await decide(c1, m)).toBe(200);
    const r = await c1.state.reserve(m.id, RUB(50_000), "auth-1");
    if (!r.ok) throw new Error(r.code);
    await Promise.all([c1.state.commit(r.hold.id, RUB(50_000)), c1.state.commit(r.hold.id, RUB(50_000))]);
    expect((await c1.consent.get(m.id, A))?.status).toBe("EXHAUSTED");
    expect(await c2.state.reserve(m.id, RUB(1), "auth-2")).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    const row = (await store.getMandate(m.id))!;
    const recs = (await store.journal(row.chain).all()).filter((e) => e.kind === "MANDATE_EXHAUSTED");
    expect(recs).toHaveLength(1);
    expect(recs[0]!.payload).toEqual({ committed: 50_000, currency: "RUB" });
    const ev = (await c1.consent.events(A, undefined, 100)).filter((e) => e.type === "mandate.exhausted");
    expect(ev.map((e) => e.data)).toEqual([{ mandate_id: m.id }]);
    expect(await c1.consent.verify(m.id, A)).toMatchObject({ outcome: "OUT_OF_SCOPE", amount_left: 0 });
  });
});
