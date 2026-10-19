// П4 запись операции ADP на PostgreSQL (PS-10 К2.1, доп. РП43 п. 16): условная вставка «в работе» — из одновременных
// запросов с двух экземпляров (два пула) к резерву проходит один; решение пишется один раз; решённую строку триггер не
// даёт изменить или удалить. ПС10 через ADP (К2.4): два экземпляра ADP на двух пулах — 20 одновременных авторизаций по
// 1 000 ₽ при 3 000 ₽ — ровно 3 APPROVE; один op_ref с двух экземпляров — одно одобрение. В CI (РП30 п. 7); локально
// без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Adp, PgOperationStore, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const H = "a".repeat(64);
const AT = "2026-10-19T10:00:00.000Z";
const APPROVE: Decision = { decision: "APPROVE", reason: null, reservation_id: "h1", decided_in_ms: 3 };
let seq = 0;
const opRef = (): string => `OPKC-PG-${++seq}`;

describe.skipIf(!DATABASE_URL)("запись операции ADP на PostgreSQL (доп. РП43 п. 16)", () => {
  let db: TestDb;
  let s1: PgOperationStore;
  let s2: PgOperationStore;

  beforeAll(async () => {
    db = await openTestDb("adp");
    s1 = new PgOperationStore(db.pool);
    s2 = new PgOperationStore(db.reopen());
  });
  afterAll(async () => {
    await db?.close();
  });

  it("20 одновременных begin с двух экземпляров — «в работе» создаёт ровно один, остальные видят его запись", async () => {
    const op = opRef();
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? s1 : s2).begin(op, H, AT)));
    const first = rs.filter((r) => r === undefined);
    expect(first, "к резерву по одному op_ref прошли двое (инвариант 4)").toHaveLength(1);
    for (const r of rs.filter((x) => x !== undefined)) expect(r).toMatchObject({ op_ref: op, msg_hash: H, decision: null, holds: [] });
  });

  it("finish пишет решение один раз; повтор begin отдаёт решение и удержания", async () => {
    const op = opRef();
    expect(await s1.begin(op, H, AT)).toBeUndefined();
    await s1.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: "mnd_1", holds: ["h1", "h2"], at: AT });
    await s2.finish({ op_ref: op, msg_hash: H, decision: { ...APPROVE, reservation_id: "other" }, mandate_id: "mnd_1", holds: [], at: AT });
    expect(await s2.begin(op, H, AT)).toEqual({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: "mnd_1", holds: ["h1", "h2"], at: AT });
  });

  it("finish с другим хэшем не меняет запись «в работе»", async () => {
    const op = opRef();
    await s1.begin(op, H, AT);
    await s1.finish({ op_ref: op, msg_hash: "b".repeat(64), decision: APPROVE, mandate_id: null, holds: [], at: AT });
    expect((await s1.begin(op, H, AT))?.decision).toBeNull();
  });

  it("решённую строку нельзя изменить, удалить или очистить TRUNCATE (триггеры, /audit PS-10 № 5)", async () => {
    const op = opRef();
    await s1.begin(op, H, AT);
    await s1.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: null, holds: [], at: AT });
    await expect(db.pool.query("UPDATE adp_operations SET holds = '[]'::jsonb WHERE op_ref = $1", [op])).rejects.toThrow(/не меняются/);
    await expect(db.pool.query("DELETE FROM adp_operations WHERE op_ref = $1", [op])).rejects.toThrow(/удаление запрещено/);
    await expect(db.pool.query("TRUNCATE adp_operations")).rejects.toThrow(/удаление запрещено/);
    expect((await s1.begin(op, H, AT))?.decision).toEqual(APPROVE);
  });
});

const AGENT = "nspk:agent:buyref-01:v3";
let mseq = 0;
const mandate = (): string => `mnd_00000000-0000-4000-8000-${String(++mseq).padStart(12, "0")}`;

/** Журнал согласий: здесь проверяется неделимость на PG, свёртка журнала — в adp-wiring.test.ts. */
class Mandates implements AdpMandates, MandateBudgetSource {
  readonly map = new Map<string, AdpMandate>();
  add(limit: number, scope: string[] = ["MER-1042"]): string {
    const id = mandate();
    this.map.set(id, { status: "ACTIVE", type: "INTENT", merchant_scope: scope, currency: "RUB", amount_limit: limit });
    return id;
  }
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    return agent_code === AGENT ? this.map.get(id) : undefined;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    const m = this.map.get(id);
    return m && { status: "ACTIVE", amount_limit: m.amount_limit, currency: m.currency };
  }
}

const auth = (mandate_id: string, op_ref: string, amount: number, merchant = "MER-1042"): CanonicalMessage => ({
  op_ref,
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount,
  currency: "RUB",
  merchant: { id: merchant },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: AGENT, mandate_id },
});

describe.skipIf(!DATABASE_URL)("ПС10 через ADP на PostgreSQL: два экземпляра (РП43 п. 5, доп. п. 16; инвариант 4)", () => {
  let db: TestDb;
  const mandates = new Mandates();
  const instance = (pool: pg.Pool): Adp =>
    new Adp({
      agents: { get: (c) => (c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      state: new StateService(new PgHoldLedger(pool), mandates, { reservationTtlSec: 600 }),
      operations: new PgOperationStore(pool),
      params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000 },
    });
  let a1: Adp;
  let a2: Adp;
  let ledger: PgHoldLedger;

  beforeAll(async () => {
    db = await openTestDb("adp_ps10");
    a1 = instance(db.pool);
    a2 = instance(db.reopen());
    ledger = new PgHoldLedger(db.pool);
  });
  afterAll(async () => {
    await db?.close();
  });

  it("20 одновременных авторизаций по 1 000 ₽ при 3 000 ₽ с двух экземпляров — ровно 3 APPROVE, перерасхода нет", async () => {
    const M = mandates.add(300_000);
    const ds = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a1 : a2).decide(auth(M, `OPKC-PS10-PG-${i}`, 100_000))));
    const pairs = ds.map((d) => parseDecision(d, "adp"));
    const approved = pairs.filter((p) => p.decision === "APPROVE").length;
    expect(approved, `перерасход бюджета: одобрено ${approved} при месте для 3 (инвариант 4)`).toBe(3);
    expect(pairs.filter((p) => p.reason === "LIMIT_EXCEEDED")).toHaveLength(17);
    const a = await ledger.account(accountId(M));
    expect(a.reserved + a.committed, "перерасход: закреплено + зарезервировано > предела").toBeLessThanOrEqual(a.limit);
    expect(a.reserved).toBe(300_000);
  });

  it("один op_ref с двух экземпляров одновременно, продавцы разные — одобрение одно, второй STATE_UNAVAILABLE", async () => {
    const M = mandates.add(300_000, ["MER-1042", "MER-77"]);
    const [d1, d2] = await Promise.all([a1.decide(auth(M, "OPKC-PG-DUP", 100_000)), a2.decide(auth(M, "OPKC-PG-DUP", 100_000, "MER-77"))]);
    const kinds = [parseDecision(d1, "adp"), parseDecision(d2, "adp")];
    expect(kinds.filter((k) => k.decision === "APPROVE"), "к резерву по одному op_ref прошли двое").toHaveLength(1);
    expect(kinds.filter((k) => k.reason === "STATE_UNAVAILABLE")).toHaveLength(1);
    expect((await ledger.account(accountId(M))).reserved).toBe(100_000);
  });
});
