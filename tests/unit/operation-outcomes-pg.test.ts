// Итог операции и operation.* на PostgreSQL (PS-16 ч. 1, РП52 п. 7–9; sql/114): факты операции — тем же UPDATE решения;
// итог — только вставка, один на op_ref; событие — в транзакции итога, третий источник ленты (CHECK «ровно один»,
// UNIQUE (op_ref, type)); сборщик с двух экземпляров — один итог и одно событие; горизонт — только события.
// В CI (РП30 п. 7); локально без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { factsOf } from "../../src/adp/decide.js";
import { PgOperationStore, type OperationFacts } from "../../src/adp/operations.js";
import { acceptIssuerResponse, eventFor, OperationOutcomeCollector, PgOutcomeStore, type OperationOutcome } from "../../src/fulfilment/outcomes.js";
import { operationFor } from "../../src/fulfilment/view.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
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

  /** Ждать, пока хоть один сеанс схемы теста ждёт блокировку (вставка второго экземпляра на первичном ключе). */
  const lockWaiter = async (): Promise<void> => {
    for (let i = 0; i < 150; i++) {
      const r = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
      if (Number(r.rows[0]!.n) > 0) return;
      await new Promise((res) => setTimeout(res, 20));
    }
    throw new Error("второй экземпляр не дошёл до ожидания блокировки");
  };

  it("сборщик с двух экземпляров, барьер: второй ждёт фиксации первого на ключе и читает прежний итог — одно событие; data ровно {op_ref}", async () => {
    await decided("OP-pg-race", decline("MANDATE_REVOKED"));
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    let held!: () => void;
    const holding = new Promise<void>((r) => (held = r));
    const a = new OperationOutcomeCollector(
      new PgOutcomeStore(db.pool, {
        inserted: async () => {
          held();
          await gate;
        },
      }),
      { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 },
    );
    const b = new OperationOutcomeCollector(new PgOutcomeStore(pool2), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 });
    const pa = a.runOnce();
    await holding;
    const pb = b.runOnce();
    await lockWaiter();
    open();
    const [ra, rb] = await Promise.all([pa, pb]);
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
    // Условие к д1 (РП52 «Дополнения» п. 1, РП53 п. 10): итог агенту — из записи операции ADP, без итога сборщика.
    const view = { operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }), outcomes: new PgOutcomeStore(db.pool) };
    expect(await operationFor(view, AGENT, "OP-pg-old")).toMatchObject({ op_ref: "OP-pg-old", status: "DECLINED", reason: "LIMIT_EXCEEDED", amount: 60_000, order_ref: "ORD-pg-1" });
    expect(await operationFor(view, "nspk:agent:someone-else:v1", "OP-pg-old")).toBeUndefined();
  });

  it("второй иной итог — прежний возвращается, события нет; итог и событие не меняются и не удаляются (триггеры)", async () => {
    const store = new PgOutcomeStore(db.pool);
    const first: OperationOutcome = { op_ref: "OP-pg-once", agent_code: AGENT, status: "DECLINED", reason: "LIMIT_EXCEEDED", source: "ADP", at: AT };
    expect(await store.record(first, await eventFor(first))).toBeUndefined();
    const second: OperationOutcome = { ...first, status: "AUTHORIZED", reason: null, source: "ISSUER" };
    expect(await store.record(second, await eventFor(second))).toEqual(first);
    expect((await events("OP-pg-once")).map((e) => e.type)).toEqual(["operation.declined"]);
    // restrict_violation триггера consent_append_only (sql/100), а не любая ошибка.
    expect(await code(db.pool.query("UPDATE operation_outcomes SET reason = 'X' WHERE op_ref = 'OP-pg-once'"))).toBe("23001");
    expect(await code(db.pool.query("DELETE FROM operation_outcomes WHERE op_ref = 'OP-pg-once'"))).toBe("23001");
    expect(await code(db.pool.query("TRUNCATE operation_outcomes"))).toBe("23001");
  });

  it("факты с NUL и одиночным суррогатом — решение записано, факты null (ревью КТ1 № 1); get отдаёт факты, сумма — число, валюта без пробелов", async () => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    expect(await ops.begin("OP-pg-nul", HASH, AT)).toBeUndefined();
    const dirty = factsOf(
      {
        op_ref: "OP-pg-nul",
        msg_type: "AUTH_REQUEST",
        channel: "CARD",
        amount: 60_000,
        currency: "RUB",
        merchant: { id: "MER-\u0000" } as CanonicalMessage["merchant"],
        instrument: { kind: "AGENT_TOKEN" } as CanonicalMessage["instrument"],
        order_ref: "ORD-\u0000",
        aoi: { indicator: true, agent_code: AGENT, fulfilment_ref: "\uD800", deal_ref: "x\u0000" },
      },
      AGENT,
    );
    await ops.finish({ op_ref: "OP-pg-nul", msg_hash: HASH, decision: decline("LIMIT_EXCEEDED"), mandate_id: "mnd_x", holds: [], at: AT, facts: dirty });
    const rec = await ops.get("OP-pg-nul");
    expect(rec?.decision).toEqual(decline("LIMIT_EXCEEDED"));
    expect(rec?.facts).toEqual({ agent_code: AGENT, order_ref: null, channel: "CARD", merchant_id: null, amount: 60_000, currency: "RUB", aoi: { indicator: true, agent_code: AGENT } });
    expect(await ops.get("OP-pg-absent")).toBeUndefined();
  });

  /** ПИ-3 на базе: чтение записи — PG, итог — PG, освобождение — заглушка П3 (удержаний ядра в тесте нет). */
  const issuer = (pool: pg.Pool, op_ref: string, issuer_approved: boolean, released: string[] = []) =>
    acceptIssuerResponse(
      {
        operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
        store: new PgOutcomeStore(pool),
        state: {
          release: async (h: string) => {
            released.push(h);
            return { ok: false as const, code: "RESERVATION_RELEASED" as const };
          },
        },
        now: () => new Date(AT),
      },
      { op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved },
    );

  it("ПИ-3 на базе: одобрение — AUTHORIZED и одно operation.authorized, повтор — без второго; два одновременных ответа с разным исходом — один итог, одно событие", async () => {
    const ok: Decision = { decision: "APPROVE", reason: null, reservation_id: "h-1", decided_in_ms: 1 };
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    for (const op of ["OP-pg-iss", "OP-pg-iss-race"]) {
      expect(await ops.begin(op, HASH, AT)).toBeUndefined();
      await ops.finish({ op_ref: op, msg_hash: HASH, decision: ok, mandate_id: "mnd_x", holds: ["h-1"], at: AT, facts: facts(AGENT) });
    }
    expect(await issuer(db.pool, "OP-pg-iss", true)).toBe(202);
    expect(await issuer(pool2, "OP-pg-iss", true)).toBe(202);
    expect((await events("OP-pg-iss")).map((e) => [e.type, e.data])).toEqual([["operation.authorized", JSON.stringify({ op_ref: "OP-pg-iss" })]]);

    const released: string[] = [];
    const [x, y] = await Promise.all([issuer(db.pool, "OP-pg-iss-race", true, released), issuer(pool2, "OP-pg-iss-race", false, released)]);
    expect([x, y]).toEqual([202, 202]);
    const evs = await events("OP-pg-iss-race");
    expect(evs).toHaveLength(1);
    const o = (await db.pool.query<{ status: string }>("SELECT status FROM operation_outcomes WHERE op_ref = 'OP-pg-iss-race'")).rows;
    expect(o).toHaveLength(1);
    // Освобождение — только если победил отказ: иной второй исход — инцидент без освобождения.
    expect(released).toEqual(o[0]!.status === "DECLINED" ? ["h-1"] : []);
    expect(evs[0]!.type).toBe(o[0]!.status === "DECLINED" ? "operation.declined" : "operation.authorized");
  });

  it("запись до sql/114 (без фактов): get — без facts, ПИ-3 — итог без агента и без события; сборщик — агент из столбца уведомителя", async () => {
    const ops = new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 });
    const ok: Decision = { decision: "APPROVE", reason: null, reservation_id: null, decided_in_ms: 1 };
    expect(await ops.begin("OP-pg-pre", HASH, AT)).toBeUndefined();
    await ops.finish({ op_ref: "OP-pg-pre", msg_hash: HASH, decision: ok, mandate_id: "mnd_x", holds: [], at: AT });
    expect((await ops.get("OP-pg-pre"))?.facts).toBeUndefined();
    expect(await issuer(db.pool, "OP-pg-pre", true)).toBe(202);
    expect((await db.pool.query("SELECT agent_code, status FROM operation_outcomes WHERE op_ref = 'OP-pg-pre'")).rows).toEqual([{ agent_code: null, status: "AUTHORIZED" }]);
    expect(await events("OP-pg-pre")).toEqual([]);

    // Отказ до sql/114 с клиентом мандата: агент — из столбца уведомителя (РП52 «Нюансы реализации» п. 4).
    expect(await ops.begin("OP-pg-pre-dec", HASH, AT)).toBeUndefined();
    await ops.finish({
      op_ref: "OP-pg-pre-dec",
      msg_hash: HASH,
      decision: decline("LIMIT_EXCEEDED"),
      mandate_id: "mnd_x",
      holds: [],
      at: AT,
      notify: { participant_code: "bank:pg", principal_ref: "prn_pg", agent_code: AGENT },
    });
    await new OperationOutcomeCollector(new PgOutcomeStore(db.pool), { horizonSec: 86_400, maxDelaySec: 30, now: () => Date.parse(AT) + 1_000 }).runOnce();
    expect((await events("OP-pg-pre-dec")).map((e) => e.type)).toEqual(["operation.declined"]);
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
