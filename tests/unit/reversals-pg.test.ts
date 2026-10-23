// Реверсал и истечение авторизации на PostgreSQL (PS-16 ч. 3, РП55 п. 1, 6; sql/117): только вставка, одна запись на
// op_ref; ПИ-3 REVERSAL по записям ADP и итогам на базе; одновременные реверсалы с двух экземпляров — одна запись; GET —
// REVERSED. П3 здесь — подмена (освобождение удержаний ядра на PG проверяют тесты П3). В CI (РП30 п. 7); без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { PgOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { PgFulfilmentStore } from "../../src/fulfilment/records.js";
import { acceptReversal, PgReversalStore, type ReversalRecord } from "../../src/fulfilment/reversals.js";
import { operationFor } from "../../src/fulfilment/view.js";
import type { StateResult } from "../../src/state/index.js";
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

  it("индекс записей операций по мандату (РП55 п. 6)", async () => {
    const r = await db.pool.query<{ indexname: string }>("SELECT indexname FROM pg_indexes WHERE tablename = 'adp_operations' AND indexname = 'adp_operations_mandate'");
    expect(r.rows).toHaveLength(1);
  });
});
