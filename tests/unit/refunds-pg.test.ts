// Возврат и operation.refunded на PostgreSQL (PS-16 ч. 3, РП55 п. 3; sql/117; PS-23 ч. 1, РП71, sql/122): только вставка;
// без refund_ref — одна запись на op_ref, с ним — на пару (op_ref, refund_ref); смешение форм — без записи; событие — одно,
// в транзакции первой записи; одновременные возвраты с двух соединений — под блокировкой по op_ref (нюанс 2); миграция
// сохраняет прежние записи; GET — REFUNDED. В CI (РП30 п. 7); без базы — пропуск.
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyMigrations, migrationsDir } from "@kuzin4u/agentic-core";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { PgOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { fulfilmentRefFor, PgFulfilmentStore } from "../../src/fulfilment/records.js";
import { acceptRefund, PgRefundStore, refundedEventFor, refundLockKey, type RefundOutcome, type RefundRecord } from "../../src/fulfilment/refunds.js";
import { platformMigrationsDir } from "../../src/shared/migrations.js";
import { operationFor } from "../../src/fulfilment/view.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:refund-pg:v1";
const AT = "2026-10-23T13:00:00.000Z";
const HASH = "e".repeat(64);
/** lockTimeoutMs — adp_timeout_ms (РП71 нюанс 2); в тестах — с запасом на нагрузку CI. */
const LOCK = { lockTimeoutMs: 5_000 } as const;

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
  refund_ref: null,
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
    refunds: new PgRefundStore(pool, LOCK),
    now: () => new Date(AT),
  });

  it("запись и событие — одной транзакцией; повтор — прежняя запись без второго события; сумма — число; только вставка (23001)", async () => {
    const store = new PgRefundStore(db.pool, LOCK);
    const r = record("OP-ref-once");
    expect(await store.record(r, await refundedEventFor(r))).toEqual({ kind: "inserted", all: [r] });
    expect(await store.get("OP-ref-once")).toEqual(r);
    expect(await store.record(record("OP-ref-once", { amount: 1_000 }), await refundedEventFor(r))).toEqual({ kind: "conflict", prior: r });
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
    const deps = { operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }), outcomes: new PgOutcomeStore(db.pool), fulfilments: new PgFulfilmentStore(db.pool), refunds: new PgRefundStore(db.pool, LOCK) };
    expect(await operationFor(deps, AGENT, "OP-ref-pi3")).toMatchObject({ status: "REFUNDED", reason: null, fulfilment: { final_amount: 60_000 } });
  });

  const rows = async (op_ref: string) =>
    (await db.pool.query<{ refund_ref: string | null; amount: string }>("SELECT refund_ref, amount FROM operation_refunds WHERE op_ref = $1 ORDER BY refund_ref NULLS FIRST", [op_ref])).rows.map((x) => [
      x.refund_ref,
      Number(x.amount),
    ]);

  it("РП71: две ссылки — две записи, одно событие; повтор, конфликт, смешение форм в обе стороны; индекс — второй барьер (23505)", async () => {
    const store = new PgRefundStore(db.pool, LOCK);
    const r1 = record("OP-ref-multi", { refund_ref: "R1", amount: 20_000 });
    const r2 = record("OP-ref-multi", { refund_ref: "R2", amount: 15_000 });
    expect(await store.record(r1, await refundedEventFor(r1))).toEqual({ kind: "inserted", all: [r1] });
    expect(await store.record(r2, await refundedEventFor(r2))).toEqual({ kind: "inserted", all: [r1, r2] });
    expect(await store.record(r1, await refundedEventFor(r1))).toEqual({ kind: "duplicate", prior: r1 });
    expect(await store.record({ ...r1, amount: 1 }, undefined)).toEqual({ kind: "conflict", prior: r1 });
    expect(await store.record(record("OP-ref-multi"), undefined)).toEqual({ kind: "mixed", first: r1 });
    expect(await rows("OP-ref-multi")).toEqual([
      ["R1", 20_000],
      ["R2", 15_000],
    ]);
    expect((await events("OP-ref-multi")).map((e) => e.type)).toEqual(["operation.refunded"]);
    expect(await store.list("OP-ref-multi")).toEqual([r1, r2]);

    const n = record("OP-ref-legacy");
    expect(await store.record(n, undefined)).toEqual({ kind: "inserted", all: [n] });
    expect(await store.record(record("OP-ref-legacy", { refund_ref: "R1" }), undefined)).toEqual({ kind: "mixed", first: n });
    expect(await rows("OP-ref-legacy")).toEqual([[null, 60_000]]);

    // Мимо хранилища: (op_ref, NULL) — не больше одного (NULLS NOT DISTINCT), пара — одна; пустая ссылка — CHECK.
    const ins = (op_ref: string, refund_ref: string | null) =>
      db.pool.query("INSERT INTO operation_refunds (op_ref, refund_ref, agent_code, mandate_id, amount, currency, at) VALUES ($1, $2, NULL, NULL, 1, 'RUB', $3)", [op_ref, refund_ref, AT]);
    expect(await code(ins("OP-ref-legacy", null))).toBe("23505");
    expect(await code(ins("OP-ref-multi", "R1"))).toBe("23505");
    expect(await code(ins("OP-ref-empty", ""))).toBe("23514");
    expect(await code(db.pool.query("UPDATE operation_refunds SET refund_ref = 'X' WHERE op_ref = 'OP-ref-legacy'"))).toBe("23001");
    // Один индекс на обе формы, op_ref — первый столбец: поиск WHERE op_ref = $1 идёт по нему (нюанс 3).
    const idx = await db.pool.query<{ indexdef: string }>("SELECT indexdef FROM pg_indexes WHERE tablename = 'operation_refunds' AND schemaname = current_schema()");
    expect(idx.rows.map((x) => x.indexdef)).toEqual([expect.stringMatching(/UNIQUE INDEX operation_refunds_op_ref_key .*\(op_ref, refund_ref\) NULLS NOT DISTINCT/)]);
  });

  /** Ворота: open() — пройти; passed — промис, который разрешается, когда точка достигнута. */
  const gate = () => {
    let open!: () => void;
    let reach!: () => void;
    const opened = new Promise<void>((r) => (open = r));
    const passed = new Promise<void>((r) => (reach = r));
    return { open, reach, opened, passed };
  };
  /** Ждать, пока соединение не встанет в очередь на блокировку возвратов op_ref (pg_locks, advisory, не выдана). */
  const lockWaiter = async (op_ref: string, maxMs = 3_000): Promise<boolean> => {
    const key = BigInt.asUintN(64, BigInt(refundLockKey(op_ref)));
    const classid = Number(key >> 32n);
    const objid = Number(key & 0xffffffffn);
    for (const end = Date.now() + maxMs; Date.now() < end; ) {
      const r = await db.pool.query<{ n: string }>(
        "SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND classid = $1::oid AND objid = $2::oid AND objsubid = 1",
        [classid, objid],
      );
      if (Number(r.rows[0]!.n) > 0) return true;
      await new Promise((r) => setTimeout(r, 20));
    }
    return false;
  };
  /** A вставил и держит транзакцию (точка inserted); B стартует и ждёт блокировку; A фиксируется; исходы обоих. */
  const race = async (op_ref: string, a: RefundRecord, b: RefundRecord): Promise<[RefundOutcome, RefundOutcome]> => {
    const g = gate();
    const storeA = new PgRefundStore(db.pool, {
      ...LOCK,
      hooks: {
        inserted: async () => {
          g.reach();
          await g.opened;
        },
      },
    });
    const storeB = new PgRefundStore(pool2, LOCK);
    const pa = storeA.record(a, await refundedEventFor(a));
    await g.passed;
    const pb = storeB.record(b, await refundedEventFor(b));
    await lockWaiter(op_ref);
    g.open();
    return Promise.all([pa, pb]);
  };

  it("гонка одной пары с двух соединений — одна вставка, второй — повтор (нюанс 2)", async () => {
    const r = record("OP-ref-race-pair", { refund_ref: "R1" });
    expect(await race("OP-ref-race-pair", r, r)).toEqual([
      { kind: "inserted", all: [r] },
      { kind: "duplicate", prior: r },
    ]);
    expect(await rows("OP-ref-race-pair")).toEqual([["R1", 60_000]]);
    expect((await events("OP-ref-race-pair")).map((e) => e.type)).toEqual(["operation.refunded"]);
  });

  it("гонка возврата без ссылки и со ссылкой — одна форма, второй — mixed без записи (нюанс 1, 2)", async () => {
    const a = record("OP-ref-race-mixed");
    const b = record("OP-ref-race-mixed", { refund_ref: "R1" });
    expect(await race("OP-ref-race-mixed", a, b)).toEqual([
      { kind: "inserted", all: [a] },
      { kind: "mixed", first: a },
    ]);
    expect(await rows("OP-ref-race-mixed")).toEqual([[null, 60_000]]);
  });

  it("гонка двух разных ссылок — две записи, одно событие (нюанс 2)", async () => {
    const a = record("OP-ref-race-two", { refund_ref: "R1", amount: 10_000 });
    const b = record("OP-ref-race-two", { refund_ref: "R2", amount: 5_000 });
    expect(await race("OP-ref-race-two", a, b)).toEqual([
      { kind: "inserted", all: [a] },
      { kind: "inserted", all: [a, b] },
    ]);
    expect(await rows("OP-ref-race-two")).toEqual([
      ["R1", 10_000],
      ["R2", 5_000],
    ]);
    expect((await events("OP-ref-race-two")).map((e) => e.type)).toEqual(["operation.refunded"]);
  });

  it("ожидание блокировки дольше lockTimeoutMs — исключение 55P03, записи нет (Р-1048); lockTimeoutMs не целое ≥ 1 — отказ", async () => {
    const g = gate();
    const a = record("OP-ref-timeout", { refund_ref: "R1" });
    const holder = new PgRefundStore(db.pool, {
      ...LOCK,
      hooks: {
        inserted: async () => {
          g.reach();
          await g.opened;
        },
      },
    });
    const pa = holder.record(a, undefined);
    await g.passed;
    expect(await code(new PgRefundStore(pool2, { lockTimeoutMs: 50 }).record(record("OP-ref-timeout", { refund_ref: "R2" }), undefined))).toBe("55P03");
    g.open();
    expect(await pa).toEqual({ kind: "inserted", all: [a] });
    expect(await rows("OP-ref-timeout")).toEqual([["R1", 60_000]]);
    expect(() => new PgRefundStore(db.pool, { lockTimeoutMs: 0 })).toThrow(/lockTimeoutMs/);
    expect(() => new PgRefundStore(db.pool, { lockTimeoutMs: 1.5 })).toThrow(/lockTimeoutMs/);
  });

  it("ПИ-3 REFUND с разными refund_ref с двух экземпляров одновременно — две записи, одно событие; сумма больше клиринга — инцидент", async () => {
    await settled("OP-ref-pi3-multi");
    const logs: Record<string, unknown>[] = [];
    const log = (_l: "info" | "warn", f: Record<string, unknown>) => void logs.push(f);
    const m = (refund_ref: string, amount: number) => ({ op_ref: "OP-ref-pi3-multi", msg_type: "REFUND", amount, currency: "RUB", refund_ref });
    expect(await Promise.all([acceptRefund({ ...instance(db.pool), log }, m("R1", 40_000)), acceptRefund({ ...instance(pool2), log }, m("R2", 30_000))])).toEqual([202, 202]);
    expect(await rows("OP-ref-pi3-multi")).toEqual([
      ["R1", 40_000],
      ["R2", 30_000],
    ]);
    expect((await events("OP-ref-pi3-multi")).map((e) => e.type)).toEqual(["operation.refunded"]);
    expect(logs.filter((f) => f.incident === true)).toEqual([expect.objectContaining({ total: 70_000, final_amount: 60_000 })]);
  });
});

describe.skipIf(!DATABASE_URL)("миграция sql/122 поверх прежних возвратов (РП71, «Что меняет»)", () => {
  it("прежняя запись без ссылки сохраняется (refund_ref = NULL), читается и задаёт форму; новые — по паре", async () => {
    const schema = `t_${process.pid}_${Date.now()}_refmig`;
    const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
    const pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path=${schema}`, max: 4 });
    const dir = mkdtempSync(join(tmpdir(), "refmig-"));
    try {
      await admin.query(`CREATE SCHEMA ${schema}`);
      const platform = platformMigrationsDir();
      const files = readdirSync(platform).filter((f) => f.endsWith(".sql")).sort();
      expect(files).toContain("122_operation_refunds_ref.sql");
      for (const f of files.filter((x) => x < "122")) copyFileSync(join(platform, f), join(dir, f));
      await applyMigrations(pool, migrationsDir());
      await applyMigrations(pool, dir);
      await pool.query("INSERT INTO operation_refunds (op_ref, agent_code, mandate_id, amount, currency, at) VALUES ('OP-old', $1, 'mnd_old', 7000, 'RUB', $2)", [AGENT, AT]);
      for (const f of files.filter((x) => x >= "122")) copyFileSync(join(platform, f), join(dir, f));
      expect(await applyMigrations(pool, dir)).toEqual(files.filter((x) => x >= "122"));
      const store = new PgRefundStore(pool, LOCK);
      const old = { op_ref: "OP-old", refund_ref: null, agent_code: AGENT, mandate_id: "mnd_old", amount: 7_000, currency: "RUB", at: AT };
      expect(await store.list("OP-old")).toEqual([old]);
      expect(await store.record({ ...old, at: "2026-10-31T00:00:00.000Z" }, undefined)).toEqual({ kind: "duplicate", prior: old });
      expect(await store.record({ ...old, refund_ref: "R1" }, undefined)).toEqual({ kind: "mixed", first: old });
      const fresh = { ...old, op_ref: "OP-new", refund_ref: "R1" };
      expect(await store.record(fresh, undefined)).toEqual({ kind: "inserted", all: [fresh] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await pool.end();
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });
});
