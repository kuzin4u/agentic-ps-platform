// Итог операции и operation.* на PostgreSQL (PS-16 ч. 1, РП52 п. 7–9; sql/114): факты операции — тем же UPDATE решения;
// итог — только вставка, один на op_ref; событие — в транзакции итога, третий источник ленты (CHECK «ровно один»,
// UNIQUE (op_ref, type)); сборщик с двух экземпляров — один итог и одно событие; горизонт — только события.
// В CI (РП30 п. 7); локально без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { eventFor, OperationOutcomeCollector, PgOutcomeStore, type OperationOutcome } from "../../src/fulfilment/outcomes.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { Decision } from "../../src/shared/canonical.generated.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:outcome-pg:v1";
const AT = "2026-10-22T10:00:00.000Z";
const HASH = "a".repeat(64);

const facts = (agent_code: string | null): OperationFacts => ({
  agent_code,
  order_ref: "ORD-pg-1",
  channel: "CARD",
  merchant_id: "MER-1042",
  amount: 60_000,
  currency: "RUB",
  aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_x" },
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

describe.skipIf(!DATABASE_URL)("итог операции и operation.* на PostgreSQL (РП52, sql/114)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("op_outcomes");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const decided = async (op_ref: string, decision: Decision, agent_code: string | null = AGENT, at = AT) => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin(op_ref, HASH, at)).toBeUndefined();
    await ops.finish({ op_ref, msg_hash: HASH, decision, mandate_id: "mnd_x", holds: [], at, facts: facts(agent_code) });
  };
  const decline = (reason: Decision["reason"]): Decision => ({ decision: "DECLINE", reason, decided_in_ms: 1 });
  const events = async (op_ref: string) =>
    (await db.pool.query<{ type: string; data: string; event_id: string; agent_code: string }>("SELECT type, data, event_id, agent_code FROM pao_events WHERE op_ref = $1", [op_ref])).rows;

  it("факты операции пишутся тем же UPDATE решения: агент по домену, сумма парой с валютой, aoi; token_ref нет", async () => {
    await decided("OP-pg-facts", decline("LIMIT_EXCEEDED"));
    const r = await db.pool.query("SELECT agent_code, order_ref, channel, merchant_id, msg_amount, msg_currency, aoi FROM adp_operations WHERE op_ref = 'OP-pg-facts'");
    expect(r.rows[0]).toEqual({
      agent_code: AGENT,
      order_ref: "ORD-pg-1",
      channel: "CARD",
      merchant_id: "MER-1042",
      msg_amount: "60000",
      msg_currency: "RUB",
      aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_x" },
    });
  });

  it("сборщик с двух экземпляров одновременно — один итог и одно событие; data ровно {op_ref}; повтор — без второго", async () => {
    await decided("OP-pg-race", decline("MANDATE_REVOKED"));
    const a = new OperationOutcomeCollector(new PgOutcomeStore(db.pool), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 });
    const b = new OperationOutcomeCollector(new PgOutcomeStore(pool2), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 });
    const [ra, rb] = await Promise.all([a.runOnce(), b.runOnce()]);
    expect(ra.failed + rb.failed).toBe(0);
    await a.runOnce();
    const evs = await events("OP-pg-race");
    expect(evs).toEqual([{ type: "operation.declined", data: JSON.stringify({ op_ref: "OP-pg-race" }), event_id: operationEventIdFor("OP-pg-race", "operation.declined"), agent_code: AGENT }]);
    expect((await db.pool.query("SELECT status, reason, source FROM operation_outcomes WHERE op_ref = 'OP-pg-race'")).rows).toEqual([
      { status: "DECLINED", reason: "MANDATE_REVOKED", source: "ADP" },
    ]);
  });

  it("агент не установлен — итог без события; CONFIRMATION_REQUIRED — итог без события; APPROVE — без итога", async () => {
    await decided("OP-pg-noagent", decline("AGENT_UNKNOWN"), null);
    await decided("OP-pg-cr", { decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED", split_detected: false, decided_in_ms: 1 });
    await decided("OP-pg-ok", { decision: "APPROVE", reason: null, reservation_id: null, decided_in_ms: 1 });
    await new OperationOutcomeCollector(new PgOutcomeStore(db.pool), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 }).runOnce();
    const outcomes = await db.pool.query<{ op_ref: string; status: string }>(
      "SELECT op_ref, status FROM operation_outcomes WHERE op_ref IN ('OP-pg-noagent', 'OP-pg-cr', 'OP-pg-ok') ORDER BY op_ref",
    );
    expect(outcomes.rows).toEqual([
      { op_ref: "OP-pg-cr", status: "CONFIRMATION_REQUIRED" },
      { op_ref: "OP-pg-noagent", status: "DECLINED" },
    ]);
    expect([...(await events("OP-pg-noagent")), ...(await events("OP-pg-cr")), ...(await events("OP-pg-ok"))]).toEqual([]);
  });

  it("горизонт: решение старше горизонта — сборщик его не берёт, события нет", async () => {
    await decided("OP-pg-old", decline("LIMIT_EXCEEDED"), AGENT, "2026-10-01T00:00:00.000Z");
    await new OperationOutcomeCollector(new PgOutcomeStore(db.pool), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) }).runOnce();
    expect(await events("OP-pg-old")).toEqual([]);
  });

  it("второй иной итог — прежний возвращается, события нет; итог и событие не меняются и не удаляются (триггеры)", async () => {
    const store = new PgOutcomeStore(db.pool);
    const first: OperationOutcome = { op_ref: "OP-pg-once", agent_code: AGENT, status: "DECLINED", reason: "LIMIT_EXCEEDED", source: "ADP", at: AT };
    expect(await store.record(first, eventFor(first))).toBeUndefined();
    const second: OperationOutcome = { ...first, status: "AUTHORIZED", reason: null, source: "ISSUER" };
    expect(await store.record(second, eventFor(second))).toEqual(first);
    expect((await events("OP-pg-once")).map((e) => e.type)).toEqual(["operation.declined"]);
    expect(await code(db.pool.query("UPDATE operation_outcomes SET reason = 'X' WHERE op_ref = 'OP-pg-once'"))).toBeDefined();
    expect(await code(db.pool.query("DELETE FROM operation_outcomes WHERE op_ref = 'OP-pg-once'"))).toBeDefined();
    expect(await code(db.pool.query("TRUNCATE operation_outcomes"))).toBeDefined();
  });

  it("CHECK «ровно один источник»: operation.* без op_ref и op_ref у не operation.* — отказ; второе событие того же типа — отказ", async () => {
    const ins = (type: string, op_ref: string | null, n: number) =>
      db.pool.query(
        `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, op_ref) VALUES ($1, $2, $3, $4, $5, '{}', $6)`,
        [AGENT, 1000 + n, operationEventIdFor(`chk-${n}`, "operation.declined"), type, AT, op_ref],
      );
    expect(await code(ins("operation.declined", null, 1))).toBe("23514");
    expect(await code(ins("mandate.signed", "OP-x", 2))).toBe("23514");
    expect(await code(ins("operation.declined", "OP-pg-once", 3))).toBe("23505");
  });
});
