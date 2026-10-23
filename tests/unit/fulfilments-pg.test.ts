// Запись об исполнении и operation.settled на PostgreSQL (PS-16 ч. 2, РП53 п. 1, 8–10; sql/115): только вставка, одна на
// op_ref; событие — в транзакции записи (третий источник ленты sql/114); одновременные представления с двух экземпляров —
// одна запись и одно событие; ПИ-3 PRESENTMENT по записям ADP и итогам на базе; GET — SETTLED с fulfilment.
// П3 здесь — подмена (закрепление удержаний ядра на PG проверяют тесты П3). В CI (РП30 п. 7); локально без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { PgOutcomeStore, type OperationOutcome } from "../../src/fulfilment/outcomes.js";
import { acceptPresentment, fulfilmentRefFor, PgFulfilmentStore, settledEventFor, type FulfilmentRecord } from "../../src/fulfilment/records.js";
import { operationFor } from "../../src/fulfilment/view.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { StateResult } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:fulfil-pg:v1";
const AT = "2026-10-23T10:00:00.000Z";
const HASH = "b".repeat(64);

const facts: OperationFacts = {
  agent_code: AGENT,
  order_ref: "ORD-ful-1",
  channel: "CARD",
  merchant_id: "MER-1042",
  amount: 60_000,
  currency: "RUB",
  aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_f" },
};

const record = (op_ref: string, over: Partial<FulfilmentRecord> = {}): FulfilmentRecord => ({
  op_ref,
  fulfilment_ref: fulfilmentRefFor(op_ref),
  agent_code: AGENT,
  mandate_id: "mnd_f",
  order_ref: "ORD-ful-1",
  merchant_id: "MER-1042",
  authorized_amount: 60_000,
  final_amount: 60_000,
  currency: "RUB",
  scope_check: "WITHIN_LIMITS",
  spent_position: 60_000,
  at: AT,
  ...over,
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

/** П3-подмена: удержание открыто на 60 000, закрепление — успех, закреплено по мандату — committed. */
const fakeState = (committed: number) => {
  const commits: { hold_id: string; amount: number }[] = [];
  const hold = { id: "h", account: "mandate:mnd_f", ref: "r", currency: "RUB", amount: 60_000, committed: 0, released: 0, state: "RESERVED", expires_at: null };
  return {
    commits,
    state: {
      hold: async (hold_id: string): Promise<StateResult> => ({ ok: true, hold: { ...hold, id: hold_id } }) as StateResult,
      commit: async (hold_id: string, money: { amount: number }): Promise<StateResult> => {
        commits.push({ hold_id, amount: money.amount });
        return { ok: true, hold: { ...hold, id: hold_id, committed: money.amount } } as StateResult;
      },
      committed: async () => committed,
    },
  };
};

describe.skipIf(!DATABASE_URL)("запись об исполнении и operation.settled на PostgreSQL (РП53, sql/115)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("fulfilments");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const events = async (op_ref: string) =>
    (await db.pool.query<{ type: string; data: string; event_id: string }>("SELECT type, data, event_id FROM pao_events WHERE op_ref = $1 ORDER BY type", [op_ref])).rows;
  const authorized = async (op_ref: string) => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin(op_ref, HASH, AT)).toBeUndefined();
    await ops.finish({
      op_ref,
      msg_hash: HASH,
      decision: { decision: "APPROVE", reason: null, reservation_id: "h-cart", decided_in_ms: 1 },
      mandate_id: "mnd_f",
      holds: ["h-cart", "h-intent"],
      at: AT,
      facts,
    });
    const o: OperationOutcome = { op_ref, agent_code: AGENT, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT };
    expect(await new PgOutcomeStore(db.pool).record(o, undefined)).toBeUndefined();
  };

  it("запись и событие — одной транзакцией; повтор — прежняя запись без второго события; суммы — числа; только вставка (23001)", async () => {
    const store = new PgFulfilmentStore(db.pool);
    const f = record("OP-ful-once");
    expect(await store.record(f, settledEventFor(f))).toBeUndefined();
    expect(await store.get("OP-ful-once")).toEqual(f);
    expect(await store.record(record("OP-ful-once", { final_amount: 50_000 }), settledEventFor(f))).toEqual(f);
    expect(await events("OP-ful-once")).toEqual([
      { type: "operation.settled", data: JSON.stringify({ op_ref: "OP-ful-once" }), event_id: operationEventIdFor("OP-ful-once", "operation.settled") },
    ]);
    expect(await code(db.pool.query("UPDATE fulfilments SET final_amount = 1 WHERE op_ref = 'OP-ful-once'"))).toBe("23001");
    expect(await code(db.pool.query("DELETE FROM fulfilments WHERE op_ref = 'OP-ful-once'"))).toBe("23001");
    expect(await code(db.pool.query("TRUNCATE fulfilments"))).toBe("23001");
    // Ссылка не по форме и scope_check вне перечня — CHECK.
    expect(await code(store.record(record("OP-ful-bad", { fulfilment_ref: "ful_X" }), undefined))).toBe("23514");
    expect(await code(store.record(record("OP-ful-bad", { scope_check: "OK" as FulfilmentRecord["scope_check"] }), undefined))).toBe("23514");
  });

  it("агент не установлен — запись без события", async () => {
    const f = record("OP-ful-noagent", { agent_code: null });
    expect(await new PgFulfilmentStore(db.pool).record(f, settledEventFor(f))).toBeUndefined();
    expect(await events("OP-ful-noagent")).toEqual([]);
  });

  it("два экземпляра, барьер: второй ждёт фиксации первого на ключе и читает прежнюю запись — одно событие", async () => {
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    let held!: () => void;
    const holding = new Promise<void>((r) => (held = r));
    const a = new PgFulfilmentStore(db.pool, {
      inserted: async () => {
        held();
        await gate;
      },
    });
    const b = new PgFulfilmentStore(pool2);
    const f = record("OP-ful-race");
    const pa = a.record(f, settledEventFor(f));
    await holding;
    const pb = b.record(record("OP-ful-race", { final_amount: 45_000 }), settledEventFor(f));
    for (let i = 0; i < 150; i++) {
      const r = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
      if (Number(r.rows[0]!.n) > 0) break;
      await new Promise((res) => setTimeout(res, 20));
    }
    open();
    const [ra, rb] = await Promise.all([pa, pb]);
    expect(ra).toBeUndefined();
    expect(rb).toEqual(f);
    expect((await events("OP-ful-race")).map((e) => e.type)).toEqual(["operation.settled"]);
  });

  it("ПИ-3 PRESENTMENT по записям на базе: закреплены оба удержания суммой представления, запись и событие; GET — SETTLED с fulfilment", async () => {
    await authorized("OP-ful-pi3");
    const { state, commits } = fakeState(45_000);
    const deps = {
      operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }),
      outcomes: new PgOutcomeStore(db.pool),
      fulfilments: new PgFulfilmentStore(db.pool),
      state,
      now: () => new Date(AT),
    };
    expect(await acceptPresentment(deps, { op_ref: "OP-ful-pi3", msg_type: "PRESENTMENT", amount: 45_000, currency: "RUB" })).toBe(202);
    expect(commits).toEqual([
      { hold_id: "h-cart", amount: 45_000 },
      { hold_id: "h-intent", amount: 45_000 },
    ]);
    expect((await events("OP-ful-pi3")).map((e) => e.type)).toEqual(["operation.settled"]);
    expect(await operationFor(deps, AGENT, "OP-ful-pi3")).toMatchObject({
      status: "SETTLED",
      reason: null,
      fulfilment: { fulfilment_ref: fulfilmentRefFor("OP-ful-pi3"), final_amount: 45_000, scope_check: "WITHIN_LIMITS", spent_position: 45_000, at: AT },
    });
    // Повтор — без нового закрепления и события.
    expect(await acceptPresentment(deps, { op_ref: "OP-ful-pi3", msg_type: "PRESENTMENT", amount: 45_000, currency: "RUB" })).toBe(202);
    expect(commits).toHaveLength(2);
    expect(await events("OP-ful-pi3")).toHaveLength(1);
  });
});
