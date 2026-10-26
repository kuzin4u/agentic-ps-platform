// Возврат и operation.refunded на PostgreSQL (PS-16 ч. 3, РП55 п. 3; sql/117): только вставка, одна запись на op_ref;
// событие — в транзакции записи; одновременные возвраты с двух экземпляров — одна запись и одно событие; GET — REFUNDED.
// В CI (РП30 п. 7); без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { PgOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { fulfilmentRefFor, PgFulfilmentStore } from "../../src/fulfilment/records.js";
import { acceptRefund, PgRefundStore, refundedEventFor, type RefundRecord } from "../../src/fulfilment/refunds.js";
import { operationFor } from "../../src/fulfilment/view.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:refund-pg:v1";
const AT = "2026-10-23T13:00:00.000Z";
const HASH = "e".repeat(64);

const facts: OperationFacts = {
  agent_code: AGENT,
  order_ref: "ORD-ref-1",
  channel: "CARD",
  merchant_id: "MER-1042",
  amount: 60_000,
  currency: "RUB",
  aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_rf" },
};

const record = (op_ref: string, over: Partial<RefundRecord> = {}): RefundRecord => ({
  op_ref,
  agent_code: AGENT,
  mandate_id: "mnd_rf",
  amount: 60_000,
  currency: "RUB",
  at: AT,
  ...over,
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

describe.skipIf(!DATABASE_URL)("возврат и operation.refunded на PostgreSQL (РП55, sql/117)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("refunds");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const events = async (op_ref: string) =>
    (await db.pool.query<{ type: string; data: string; event_id: string }>("SELECT type, data, event_id FROM pao_events WHERE op_ref = $1 ORDER BY type", [op_ref])).rows;
  const settled = async (op_ref: string) => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin(op_ref, HASH, AT)).toBeUndefined();
    await ops.finish({
      op_ref,
      msg_hash: HASH,
      decision: { decision: "APPROVE", reason: null, reservation_id: "h-cart", decided_in_ms: 1 },
      mandate_id: "mnd_rf",
      holds: ["h-cart"],
      at: AT,
      facts,
    });
    expect(await new PgOutcomeStore(db.pool).record({ op_ref, agent_code: AGENT, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined)).toBeUndefined();
    const f = {
      op_ref,
      fulfilment_ref: fulfilmentRefFor(op_ref),
      agent_code: AGENT,
      mandate_id: "mnd_rf",
      order_ref: "ORD-ref-1",
      merchant_id: "MER-1042",
      authorized_amount: 60_000,
      final_amount: 60_000,
      currency: "RUB",
      scope_check: "WITHIN_LIMITS" as const,
      spent_position: 60_000,
      at: AT,
    };
    expect(await new PgFulfilmentStore(db.pool).record(f, undefined)).toBeUndefined();
  };
  const instance = (pool: pg.Pool) => ({
    operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
    outcomes: new PgOutcomeStore(pool),
    fulfilments: new PgFulfilmentStore(pool),
    refunds: new PgRefundStore(pool),
    now: () => new Date(AT),
  });

  it("запись и событие — одной транзакцией; повтор — прежняя запись без второго события; сумма — число; только вставка (23001)", async () => {
    const store = new PgRefundStore(db.pool);
    const r = record("OP-ref-once");
    expect(await store.record(r, await refundedEventFor(r))).toBeUndefined();
    expect(await store.get("OP-ref-once")).toEqual(r);
    expect(await store.record(record("OP-ref-once", { amount: 1_000 }), await refundedEventFor(r))).toEqual(r);
    expect(await events("OP-ref-once")).toEqual([
      { type: "operation.refunded", data: JSON.stringify({ op_ref: "OP-ref-once" }), event_id: operationEventIdFor("OP-ref-once", "operation.refunded") },
    ]);
    expect(await code(db.pool.query("UPDATE operation_refunds SET amount = 1 WHERE op_ref = 'OP-ref-once'"))).toBe("23001");
    expect(await code(db.pool.query("DELETE FROM operation_refunds WHERE op_ref = 'OP-ref-once'"))).toBe("23001");
    expect(await code(db.pool.query("TRUNCATE operation_refunds"))).toBe("23001");
    expect(await code(store.record(record("OP-ref-bad", { currency: "rub" }), undefined))).toBe("23514");
  });

  it("ПИ-3 REFUND по записям на базе, два экземпляра одновременно — одна запись, одно событие; GET — REFUNDED с fulfilment", async () => {
    await settled("OP-ref-pi3");
    const msg = { op_ref: "OP-ref-pi3", msg_type: "REFUND", amount: 60_000, currency: "RUB" };
    expect(await Promise.all([acceptRefund(instance(db.pool), msg), acceptRefund(instance(pool2), msg)])).toEqual([202, 202]);
    expect((await events("OP-ref-pi3")).map((e) => e.type)).toEqual(["operation.refunded"]);
    const deps = { operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }), outcomes: new PgOutcomeStore(db.pool), fulfilments: new PgFulfilmentStore(db.pool), refunds: new PgRefundStore(db.pool) };
    expect(await operationFor(deps, AGENT, "OP-ref-pi3")).toMatchObject({ status: "REFUNDED", reason: null, fulfilment: { final_amount: 60_000 } });
  });
});
