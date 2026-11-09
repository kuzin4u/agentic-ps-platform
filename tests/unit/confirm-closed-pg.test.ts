// Закрытие запроса подтверждения Платформой после отзыва мандата на PostgreSQL (РП76 п. 3–4; sql/123): REJECTED без
// решения банка, closed_reason и closed_at, confirmation.rejected той же транзакцией; CHECK — решение и причина
// закрытия не вместе, причина и момент — парой, причина — только у REJECTED; из двух экземпляров закрывает один.
// В CI (РП30 п. 7); локально без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newConfirmationId, newConfirmationRef, PgConfirmationStore, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:cnf-closed-pg:v1";
const AT = "2026-11-09T10:00:00.000Z";
const NOW = "2026-11-09T10:05:00.000Z";
const EXPIRES = "2099-01-01T00:00:00.000Z";
const M = "mnd_00000000-0000-4000-8000-000000000776";

const pending = (order_ref: string, over: Partial<ConfirmationRecord> = {}): ConfirmationRecord => ({
  confirmation_id: newConfirmationId(),
  agent_code: AGENT,
  mandate_id: M,
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref,
  split_detected: false,
  status: "PENDING",
  created_at: AT,
  expires_at: EXPIRES,
  confirmation_ref: null,
  decision: null,
  op_ref: null,
  ...over,
});

const decision = (r: ConfirmationRecord, d: "APPROVE" | "REJECT" = "APPROVE") => ({
  participant_code: "bank:pg",
  kid: "kid-pg",
  decision: d,
  totals_hash: totalsHash(r),
  decided_at: AT,
  signature: "s".repeat(86),
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

describe.skipIf(!DATABASE_URL)("закрытие запроса после отзыва мандата на PostgreSQL (РП76, sql/123)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("cnf_closed");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const types = async (confirmation_id: string) =>
    (await db.pool.query<{ type: string }>("SELECT type FROM pao_events WHERE confirmation_id = $1 ORDER BY seq", [confirmation_id])).rows.map((x) => x.type);

  it("PENDING → REJECTED с closed и без решения, событие confirmation.rejected; повтор и не PENDING — undefined", async () => {
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending("ORD-closed-1"));
    const done = await store.closeRevoked(r.confirmation_id, NOW);
    expect(done).toEqual({ ...r, status: "REJECTED", closed: { reason: "MANDATE_REVOKED", at: NOW } });
    expect(await store.get(r.confirmation_id)).toEqual(done);
    expect(await types(r.confirmation_id)).toEqual(["confirmation.required", "confirmation.rejected"]);
    expect(await store.closeRevoked(r.confirmation_id, NOW)).toBeUndefined();

    const approved = await store.create(pending("ORD-closed-2"));
    await store.decide(approved.confirmation_id, decision(approved), newConfirmationRef(), AT);
    expect(await store.closeRevoked(approved.confirmation_id, NOW)).toBeUndefined();
    expect((await store.get(approved.confirmation_id))?.status).toBe("APPROVED");

    const late = await store.create(pending("ORD-closed-3", { expires_at: "2026-11-09T10:01:00.000Z" }));
    expect(await store.closeRevoked(late.confirmation_id, NOW), "срок вышел — не закрывается").toBeUndefined();
    expect((await store.get(late.confirmation_id))?.status).toBe("PENDING");
  });

  it("pendingByAgent — только PENDING этого агента в сроке, по порядку записи", async () => {
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const a = await store.create(pending("ORD-list-1", { agent_code: "nspk:agent:cnf-list-pg:v1" }));
    const b = await store.create(pending("ORD-list-2", { agent_code: "nspk:agent:cnf-list-pg:v1" }));
    await store.create(pending("ORD-list-3", { agent_code: "nspk:agent:cnf-list-pg:v1", expires_at: "2026-11-09T10:01:00.000Z" }));
    await store.create(pending("ORD-list-4", { agent_code: "nspk:agent:cnf-other-pg:v1" }));
    await store.decide(b.confirmation_id, decision(b, "REJECT"), null, AT);
    expect((await store.pendingByAgent("nspk:agent:cnf-list-pg:v1", NOW)).map((x) => x.confirmation_id)).toEqual([a.confirmation_id]);
  });

  it("CHECK sql/123: решение и closed_reason не вместе; REJECTED без обоих; причина без момента; причина не у REJECTED; вне перечня", async () => {
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    // Каждое нарушение — на своей строке PENDING: прошедшее UPDATE не меняет условия следующего (триггер не даёт перехода
    // из REJECTED); expect.soft — в отчёте все нарушения, а не первое.
    let n = 0;
    const violates = async (what: string, set: string, extra: (r: ConfirmationRecord) => unknown[] = () => []) => {
      const r = await store.create(pending(`ORD-check-${++n}`));
      const got = await code(db.pool.query(`UPDATE confirmations SET ${set} WHERE confirmation_id = $1`, [r.confirmation_id, ...extra(r)]));
      expect.soft(got, what).toBe("23514");
      expect.soft((await store.get(r.confirmation_id))?.status, `${what}: запись прежняя`).toBe("PENDING");
    };
    await violates("REJECTED без решения и без причины", "status = 'REJECTED'");
    await violates("причина без момента", "status = 'REJECTED', closed_reason = 'MANDATE_REVOKED'");
    await violates("причина не у REJECTED", "status = 'EXPIRED', closed_reason = 'MANDATE_REVOKED', closed_at = $2", () => [NOW]);
    await violates("причина вне перечня", "status = 'REJECTED', closed_reason = 'OTHER', closed_at = $2", () => [NOW]);
    await violates(
      "решение вместе с причиной закрытия",
      `status = 'REJECTED', closed_reason = 'MANDATE_REVOKED', closed_at = $2, participant_code = $3, kid = $4, decision = 'REJECT',
       totals_hash = $5, decided_at = $6, signature = $7`,
      (r) => {
        const d = decision(r, "REJECT");
        return [NOW, d.participant_code, d.kid, d.totals_hash, d.decided_at, d.signature];
      },
    );
    // Отказ человеком — как прежде: решение без причины.
    const r = await store.create(pending("ORD-check-human"));
    expect((await store.decide(r.confirmation_id, decision(r, "REJECT"), null, AT))?.status).toBe("REJECTED");
  });

  it("два экземпляра закрывают один запрос — один переход и одно событие", async () => {
    const [s1, s2] = [new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }), new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })];
    const r = await s1.create(pending("ORD-closed-race"));
    const out = await Promise.all([s1, s2].map((s) => s.closeRevoked(r.confirmation_id, NOW)));
    expect(out.filter((x) => x?.status === "REJECTED")).toHaveLength(1);
    expect(await types(r.confirmation_id)).toEqual(["confirmation.required", "confirmation.rejected"]);
  });

  it("закрытие против решения банка — проходит одно, событие одно", async () => {
    const [s1, s2] = [new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }), new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })];
    const r = await s1.create(pending("ORD-closed-vs-decide"));
    const [closed, decided] = await Promise.all([s1.closeRevoked(r.confirmation_id, NOW), s2.decide(r.confirmation_id, decision(r), newConfirmationRef(), NOW)]);
    expect([closed, decided].filter((x) => x !== undefined)).toHaveLength(1);
    expect((await types(r.confirmation_id)).filter((t) => t !== "confirmation.required")).toHaveLength(1);
  });
});
