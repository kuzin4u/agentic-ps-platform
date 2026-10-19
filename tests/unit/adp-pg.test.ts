// П4 запись операции ADP на PostgreSQL (PS-10 К2.1, доп. РП43 п. 16): условная вставка «в работе» — из одновременных
// запросов с двух экземпляров (два пула) к резерву проходит один; решение пишется один раз; решённую строку триггер не
// даёт изменить или удалить. В CI (РП30 п. 7); локально без базы — пропуск.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgOperationStore } from "../../src/adp/index.js";
import type { Decision } from "../../src/shared/canonical.generated.js";
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

  it("решённую строку нельзя изменить или удалить (триггер)", async () => {
    const op = opRef();
    await s1.begin(op, H, AT);
    await s1.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: null, holds: [], at: AT });
    await expect(db.pool.query("UPDATE adp_operations SET holds = '[]'::jsonb WHERE op_ref = $1", [op])).rejects.toThrow(/не меняются/);
    await expect(db.pool.query("DELETE FROM adp_operations WHERE op_ref = $1", [op])).rejects.toThrow(/удаление запрещено/);
  });
});
