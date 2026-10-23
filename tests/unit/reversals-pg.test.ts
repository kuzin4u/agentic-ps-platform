// Реверсал и истечение авторизации на PostgreSQL (PS-16 ч. 3, РП55 п. 1, 6; sql/117): только вставка, одна запись на
// op_ref; ПИ-3 REVERSAL по записям ADP и итогам на базе; одновременные реверсалы с двух экземпляров — одна запись; GET —
// REVERSED. П3 здесь — подмена (освобождение удержаний ядра на PG проверяют тесты П3). В CI (РП30 п. 7); без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { PgOpLock } from "../../src/fulfilment/oplock.js";
import { PgOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { acceptOperationEvent, PgFulfilmentStore } from "../../src/fulfilment/records.js";
import { acceptReversal, PgReversalStore, type ReversalRecord } from "../../src/fulfilment/reversals.js";
import { operationFor } from "../../src/fulfilment/view.js";
import { accountId, holdRef, StateService, type StateResult } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:reversal-pg:v1";
const AT = "2026-10-23T12:00:00.000Z";
const HASH = "c".repeat(64);

const facts: OperationFacts = {
  agent_code: AGENT,
  order_ref: "ORD-rev-1",
  channel: "CARD",
  merchant_id: "MER-1042",
  amount: 60_000,
  currency: "RUB",
  aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_r" },
};

const record = (op_ref: string, over: Partial<ReversalRecord> = {}): ReversalRecord => ({
  op_ref,
  kind: "REVERSAL",
  agent_code: AGENT,
  mandate_id: "mnd_r",
  at: AT,
  ...over,
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

/** П3-подмена: освобождение — успех без закреплённого. */
const fakeState = () => {
  const released: string[] = [];
  return {
    released,
    state: {
      hold: async (hold_id: string): Promise<StateResult> =>
        ({ ok: true, hold: { id: hold_id, account: "a", ref: "r", currency: "RUB", amount: 60_000, committed: 0, released: 0, state: "RESERVED", expires_at: null } }) as StateResult,
      release: async (hold_id: string): Promise<StateResult> => {
        released.push(hold_id);
        return { ok: true, hold: { id: hold_id, account: "a", ref: "r", currency: "RUB", amount: 60_000, committed: 0, released: 60_000, state: "RELEASED", expires_at: null } } as StateResult;
      },
    },
  };
};

describe.skipIf(!DATABASE_URL)("реверсал на PostgreSQL (РП55, sql/117)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("reversals");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const approved = async (op_ref: string) => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin(op_ref, HASH, AT)).toBeUndefined();
    await ops.finish({
      op_ref,
      msg_hash: HASH,
      decision: { decision: "APPROVE", reason: null, reservation_id: "h-cart", decided_in_ms: 1 },
      mandate_id: "mnd_r",
      holds: ["h-cart", "h-intent"],
      at: AT,
      facts,
    });
  };
  const instance = (pool: pg.Pool, state: ReturnType<typeof fakeState>["state"]) => ({
    operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
    outcomes: new PgOutcomeStore(pool),
    fulfilments: new PgFulfilmentStore(pool),
    reversals: new PgReversalStore(pool),
    state,
    now: () => new Date(AT),
  });

  it("запись одна на op_ref: повтор — прежняя; только вставка (23001); kind вне перечня — CHECK (23514)", async () => {
    const store = new PgReversalStore(db.pool);
    expect(await store.record(record("OP-rev-once"))).toBeUndefined();
    expect(await store.record(record("OP-rev-once", { kind: "AUTH_EXPIRED" }))).toEqual(record("OP-rev-once"));
    expect(await store.get("OP-rev-once")).toEqual(record("OP-rev-once"));
    expect(await code(db.pool.query("UPDATE operation_reversals SET kind = 'AUTH_EXPIRED' WHERE op_ref = 'OP-rev-once'"))).toBe("23001");
    expect(await code(db.pool.query("DELETE FROM operation_reversals WHERE op_ref = 'OP-rev-once'"))).toBe("23001");
    expect(await code(db.pool.query("TRUNCATE operation_reversals"))).toBe("23001");
    expect(await code(store.record(record("OP-rev-bad", { kind: "REFUND" as ReversalRecord["kind"] })))).toBe("23514");
  });

  it("ПИ-3 REVERSAL до ответа эмитента по записи на базе: оба удержания освобождены, запись; GET — REVERSED / REVERSAL", async () => {
    await approved("OP-rev-pi3");
    const { state, released } = fakeState();
    expect(await acceptReversal(instance(db.pool, state), { op_ref: "OP-rev-pi3", msg_type: "REVERSAL" })).toBe(202);
    expect(released).toEqual(["h-cart", "h-intent"]);
    const deps = { operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }), outcomes: new PgOutcomeStore(db.pool), reversals: new PgReversalStore(db.pool) };
    expect(await operationFor(deps, AGENT, "OP-rev-pi3")).toMatchObject({ status: "REVERSED", reason: "REVERSAL", amount: 60_000 });
  });

  it("два экземпляра одновременно — одна запись, обоим 202", async () => {
    await approved("OP-rev-race");
    const a = fakeState();
    const b = fakeState();
    const msg = { op_ref: "OP-rev-race", msg_type: "AUTH_EXPIRED" };
    expect(await Promise.all([acceptReversal(instance(db.pool, a.state), msg), acceptReversal(instance(pool2, b.state), msg)])).toEqual([202, 202]);
    const rows = (await db.pool.query<{ kind: string }>("SELECT kind FROM operation_reversals WHERE op_ref = 'OP-rev-race'")).rows;
    expect(rows).toEqual([{ kind: "AUTH_EXPIRED" }]);
  });

  it("блокировка по op_ref: второй ждёт первого; ожидание дольше предела — исключение (→ 503), соединение не возвращается с lock_timeout", async () => {
    const a = new PgOpLock(db.pool, { timeoutMs: 5_000 });
    const b = new PgOpLock(pool2, { timeoutMs: 100 });
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    let held!: () => void;
    const holding = new Promise<void>((r) => (held = r));
    const pa = a.run("OP-lock-1", async () => {
      held();
      await gate;
      return "a";
    });
    await holding;
    await expect(b.run("OP-lock-1", async () => "b")).rejects.toMatchObject({ code: "55P03" });
    // Другой op_ref не ждёт.
    expect(await b.run("OP-lock-2", async () => "other")).toBe("other");
    open();
    expect(await pa).toBe("a");
    expect(await b.run("OP-lock-1", async () => "b")).toBe("b");
    const t = await pool2.query<{ lock_timeout: string }>("SHOW lock_timeout");
    expect(t.rows[0]!.lock_timeout).toBe("0");
  });

  it("сквозной, с барьерами: реверсал проверил удержания и ждёт, клиринг закрепил CART и ждёт — под очередью смешанного состояния нет (КТ1 п. 1)", async () => {
    const op_ref = "OP-rev-barrier";
    const cart = "mnd_rbar_cart";
    const root = "mnd_rbar_root";
    const ledger = new PgHoldLedger(db.pool);
    const rub = (amount: number) => ({ amount, currency: "RUB" });
    await ledger.openAccount(accountId(cart), rub(100_000));
    await ledger.openAccount(accountId(root), rub(1_000_000));
    const expires = Date.parse(AT) + 600_000;
    const hc = await ledger.reserve(accountId(cart), rub(60_000), holdRef(cart, op_ref), expires);
    const hr = await ledger.reserve(accountId(root), rub(60_000), holdRef(root, op_ref), expires);
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin(op_ref, HASH, AT)).toBeUndefined();
    await ops.finish({ op_ref, msg_hash: HASH, decision: { decision: "APPROVE", reason: null, reservation_id: hc.id, decided_in_ms: 1 }, mandate_id: cart, holds: [hc.id, hr.id], at: AT, facts });
    await new PgOutcomeStore(db.pool).record({ op_ref, agent_code: AGENT, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    const budgets = { budget: async () => ({ status: "ACTIVE" as const, amount_limit: 100_000, currency: "RUB" }) };
    // Барьер с пределом: под очередью второй обработчик стоит на блокировке и сигнала не даст — ждущий идёт дальше по сроку.
    const signal = () => {
      let fire!: () => void;
      const p = new Promise<void>((r) => (fire = r));
      return { fire, wait: () => Promise.race([p, new Promise<void>((r) => setTimeout(r, 400))]) };
    };
    const checked = signal(); // реверсал проверил удержания
    const cartCommitted = signal(); // клиринг закрепил CART
    const released = signal(); // реверсал освободил
    const base = (pool: pg.Pool) => ({
      operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
      store: new PgOutcomeStore(pool),
      fulfilments: new PgFulfilmentStore(pool),
      lock: new PgOpLock(pool, { timeoutMs: 5_000 }),
      now: () => new Date(AT),
    });
    const s1 = new StateService(new PgHoldLedger(db.pool), budgets, { reservationTtlSec: 600 });
    const presenting = {
      ...base(db.pool),
      reversals: new PgReversalStore(db.pool),
      state: {
        hold: (id: string) => s1.hold(id),
        release: (id: string) => s1.release(id),
        committed: (m: string) => s1.committed(m),
        commit: async (id: string, money: { amount: number; currency: string }) => {
          const r = await s1.commit(id, money);
          if (id === hc.id) {
            cartCommitted.fire();
            await released.wait();
          }
          return r;
        },
      },
    };
    const s2 = new StateService(new PgHoldLedger(pool2), budgets, { reservationTtlSec: 600 });
    const store2 = new PgReversalStore(pool2);
    const reversing = {
      ...base(pool2),
      reversals: {
        get: (o: string) => store2.get(o),
        record: async (r: ReversalRecord) => {
          checked.fire();
          await cartCommitted.wait();
          return store2.record(r);
        },
      },
      state: {
        hold: (id: string) => s2.hold(id),
        commit: (id: string, money: { amount: number; currency: string }) => s2.commit(id, money),
        committed: (m: string) => s2.committed(m),
        release: async (id: string) => {
          const r = await s2.release(id);
          if (id === hr.id) released.fire();
          return r;
        },
      },
    };
    const pr = acceptOperationEvent(reversing, { op_ref, msg_type: "REVERSAL" });
    await checked.wait();
    const pp = acceptOperationEvent(presenting, { op_ref, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" });
    expect(await Promise.all([pr, pp])).toEqual([202, 202]);
    const got = [await ledger.get(hc.id), await ledger.get(hr.id)];
    // Без очереди: реверсал проверил (всё открыто) → клиринг закрепил CART → реверсал освободил INTENT → клиринг по INTENT —
    // RESERVATION_RELEASED: CART закреплён, INTENT освобождён, бюджет INTENT вернулся при списанных деньгах (инвариант 4).
    expect(got.map((h) => h.committed > 0), "закреплены оба или ни одного").toSatisfy((c: boolean[]) => c.every((x) => x === c[0]));
  });

  it("сквозной: настоящий П3 на PgHoldLedger, клиринг и реверсал по одному op_ref одновременно с двух экземпляров — ни одно закреплённое удержание не освобождено (КТ1 п. 1)", async () => {
    for (let round = 0; round < 6; round++) {
      const op_ref = `OP-rev-e2e-${round}`;
      const cart = `mnd_re2e_cart_${round}`;
      const root = `mnd_re2e_root_${round}`;
      const ledger = new PgHoldLedger(db.pool);
      const rub = (amount: number) => ({ amount, currency: "RUB" });
      await ledger.openAccount(accountId(cart), rub(100_000));
      await ledger.openAccount(accountId(root), rub(1_000_000));
      const expires = Date.parse(AT) + 600_000;
      const hc = await ledger.reserve(accountId(cart), rub(60_000), holdRef(cart, op_ref), expires);
      const hr = await ledger.reserve(accountId(root), rub(60_000), holdRef(root, op_ref), expires);
      const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
      expect(await ops.begin(op_ref, HASH, AT)).toBeUndefined();
      await ops.finish({
        op_ref,
        msg_hash: HASH,
        decision: { decision: "APPROVE", reason: null, reservation_id: hc.id, decided_in_ms: 1 },
        mandate_id: cart,
        holds: [hc.id, hr.id],
        at: AT,
        facts,
      });
      await new PgOutcomeStore(db.pool).record({ op_ref, agent_code: AGENT, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
      const budgets = { budget: async () => ({ status: "ACTIVE" as const, amount_limit: 100_000, currency: "RUB" }) };
      const instance = (pool: pg.Pool) => ({
        operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
        store: new PgOutcomeStore(pool),
        fulfilments: new PgFulfilmentStore(pool),
        reversals: new PgReversalStore(pool),
        state: new StateService(new PgHoldLedger(pool), budgets, { reservationTtlSec: 600 }),
        lock: new PgOpLock(pool, { timeoutMs: 5_000 }),
        now: () => new Date(AT),
      });
      const present = { op_ref, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" };
      const reverse = { op_ref, msg_type: "REVERSAL" };
      const pair = round % 2 === 0 ? [present, reverse] : [reverse, present];
      expect(await Promise.all([acceptOperationEvent(instance(db.pool), pair[0]), acceptOperationEvent(instance(pool2), pair[1])])).toEqual([202, 202]);
      const got = [await ledger.get(hc.id), await ledger.get(hr.id)];
      const committed = got.filter((h) => h.committed > 0).length;
      // Либо клиринг первым — закреплены оба, реверсал ничего не освободил; либо реверсал первым — оба освобождены,
      // клиринг — NOT_RESERVED. Смешанного «CART закреплён, INTENT освобождён» быть не может (инвариант 4).
      expect([0, 2], `раунд ${round}: закреплено ${committed} из 2`).toContain(committed);
      if (committed === 2) for (const h of got) expect(h.committed + h.released).toBe(60_000);
    }
  });

  it("записи операций по мандату (К2.1): только этот mandate_id, по времени, не больше предела; факты — как у get", async () => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    const put = async (op_ref: string, mandate_id: string, at: string) => {
      expect(await ops.begin(op_ref, HASH, at)).toBeUndefined();
      await ops.finish({ op_ref, msg_hash: HASH, decision: { decision: "APPROVE", reason: null, reservation_id: "h", decided_in_ms: 1 }, mandate_id, holds: ["h"], at, facts });
    };
    await put("OP-bym-2", "mnd_bym", "2026-10-23T12:00:02.000Z");
    await put("OP-bym-1", "mnd_bym", "2026-10-23T12:00:01.000Z");
    await put("OP-bym-3", "mnd_bym", "2026-10-23T12:00:03.000Z");
    await put("OP-bym-x", "mnd_bym_other", "2026-10-23T12:00:00.000Z");
    expect((await ops.byMandate("mnd_bym", 10)).map((r) => r.op_ref)).toEqual(["OP-bym-1", "OP-bym-2", "OP-bym-3"]);
    expect((await ops.byMandate("mnd_bym", 2)).map((r) => r.op_ref)).toEqual(["OP-bym-1", "OP-bym-2"]);
    expect((await ops.byMandate("mnd_bym", 1))[0]).toEqual(await ops.get("OP-bym-1"));
    expect(await ops.byMandate("mnd_bym_none", 10)).toEqual([]);
  });

  it("индекс записей операций по мандату (РП55 п. 6)", async () => {
    const r = await db.pool.query<{ indexname: string }>("SELECT indexname FROM pg_indexes WHERE tablename = 'adp_operations' AND indexname = 'adp_operations_mandate'");
    expect(r.rows).toHaveLength(1);
  });
});
