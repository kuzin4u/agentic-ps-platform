// События confirmation.* на PostgreSQL (PS-19 ч. 2, РП51 п. 1–4; sql/112): переход запроса подтверждения и событие —
// одна транзакция (сбой события откатывает переход); у ленты два источника, CHECK «ровно один»; на переход — одно событие
// (UNIQUE (confirmation_id, type)); номер — общий у агента; из двух экземпляров решение, вставку и истечение пишет один;
// ожидание блокировки при создании запроса — не дольше lockTimeoutMs (Дополнения РП51 п. 1).
// В CI (РП30 п. 7); локально без базы — пропуск.
import { canonicalJson } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newConfirmationId, newConfirmationRef, PgConfirmationStore, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { PgConsentStore } from "../../src/consent/store.js";
import { confirmationEventIdFor, eventSeqLockKey } from "../../src/pao/events.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:cnf-pg:v1";
const AT = "2026-10-22T10:00:00.000Z";
const EXPIRES = "2099-01-01T00:00:00.000Z";
const M = "mnd_00000000-0000-4000-8000-000000000777";

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

const decision = (r: ConfirmationRecord) => ({
  participant_code: "bank:pg",
  kid: "kid-pg",
  decision: "APPROVE" as const,
  totals_hash: totalsHash(r),
  decided_at: AT,
  signature: "s".repeat(86),
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

describe.skipIf(!DATABASE_URL)("события confirmation.* на PostgreSQL (РП51 п. 1–4, sql/112)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("cnf_events");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  const rows = async (confirmation_id: string) =>
    (
      await db.pool.query<{ seq: string; type: string; data: string; journal_chain: string | null; journal_seq: string | null; event_id: string }>(
        "SELECT seq, type, data, journal_chain, journal_seq, event_id FROM pao_events WHERE confirmation_id = $1 ORDER BY seq",
        [confirmation_id],
      )
    ).rows;

  it("вставка запроса, решение, истечение — событие в той же транзакции; повтор ключа — без второго; лента — общий номер агента", async () => {
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending("ORD-pg-1"));
    expect((await store.create(pending("ORD-pg-1"))).confirmation_id).toBe(r.confirmation_id);
    await store.decide(r.confirmation_id, decision(r), newConfirmationRef(), "2026-10-22T10:01:00.000Z");
    const late = await store.create(pending("ORD-pg-2", { expires_at: "2026-10-22T10:15:00.000Z" }));
    expect(await store.expire(late.confirmation_id, "2026-10-22T10:20:00.000Z")).toBe(true);
    expect(await store.expire(late.confirmation_id, "2026-10-22T10:20:00.000Z")).toBe(false);

    const a = await rows(r.confirmation_id);
    expect(a.map((x) => x.type)).toEqual(["confirmation.required", "confirmation.approved"]);
    for (const x of a) {
      expect(x.data).toBe(canonicalJson({ confirmation_id: r.confirmation_id }));
      expect([x.journal_chain, x.journal_seq]).toEqual([null, null]);
    }
    expect(a[1]!.event_id).toBe(confirmationEventIdFor(r.confirmation_id, "confirmation.approved"));
    expect((await rows(late.confirmation_id)).map((x) => x.type)).toEqual(["confirmation.required", "confirmation.expired"]);

    // Лента агента читает оба источника одной последовательностью.
    const feed = await new PgConsentStore(db.pool).listEvents(AGENT, undefined, 100);
    expect(feed.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(feed[0]).toMatchObject({ type: "confirmation.required", data: { confirmation_id: r.confirmation_id }, journal_chain: null, journal_seq: null });
  });

  it("сбой вставки события — решение не записано: переход и событие откатываются вместе (РП51 п. 3)", async () => {
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending("ORD-pg-rollback"));
    // Событие этого перехода уже стоит в ленте (под чужим агентом) — вставка в транзакции решения упадёт по UNIQUE.
    await db.pool.query(
      `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, confirmation_id)
       VALUES ('nspk:agent:cnf-pg-blocker:v1', 1, $1, 'confirmation.approved', $2, $3, $4)`,
      [confirmationEventIdFor(r.confirmation_id, "confirmation.approved"), AT, canonicalJson({ confirmation_id: r.confirmation_id }), r.confirmation_id],
    );
    expect(await code(store.decide(r.confirmation_id, decision(r), newConfirmationRef(), AT))).toBe("23505");
    const after = await store.get(r.confirmation_id);
    expect(after?.status, "решение откатилось вместе с событием").toBe("PENDING");
    expect(after?.confirmation_ref).toBeNull();
  });

  it("CHECK «ровно один источник» и UNIQUE (confirmation_id, type)", async () => {
    const insert = (over: { type?: string; confirmation_id?: string | null; journal?: boolean; event_id?: string }) =>
      db.pool.query(
        `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, journal_chain, journal_seq, confirmation_id)
         VALUES ('nspk:agent:cnf-pg-check:v1', (SELECT COALESCE(MAX(seq), 0) + 1 FROM pao_events WHERE agent_code = 'nspk:agent:cnf-pg-check:v1'),
           $1, $2, $3, '{}', $4, $5, $6)`,
        [
          over.event_id ?? confirmationEventIdFor(newConfirmationId(), "confirmation.required"),
          over.type ?? "confirmation.required",
          AT,
          over.journal ? "chain-x" : null,
          over.journal ? 1 : null,
          over.confirmation_id === undefined ? newConfirmationId() : over.confirmation_id,
        ],
      );
    expect(await code(insert({ confirmation_id: null })), "нет источника").toBe("23514");
    expect(await code(insert({ type: "mandate.signed" })), "запрос подтверждения с типом мандата").toBe("23514");
    expect(await code(insert({ journal: true })), "оба источника").toBe("23514");
    expect(await code(insert({ journal: true, confirmation_id: null })), "пара журнала с типом confirmation.*").toBe("23514");
    const id = newConfirmationId();
    await insert({ confirmation_id: id });
    expect(await code(insert({ confirmation_id: id })), "второе событие того же типа по запросу").toBe("23505");
  });

  it("два экземпляра решают один запрос — одно решение и одно событие", async () => {
    const [s1, s2] = [new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }), new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })];
    const r = await s1.create(pending("ORD-pg-race"));
    const out = await Promise.all([s1, s2].map((s) => s.decide(r.confirmation_id, decision(r), newConfirmationRef(), AT)));
    expect(out.filter((x) => x?.status === "APPROVED")).toHaveLength(1);
    expect((await rows(r.confirmation_id)).map((x) => x.type)).toEqual(["confirmation.required", "confirmation.approved"]);
  });

  it("два экземпляра создают один запрос и истекают одновременно — одно confirmation.required и одно confirmation.expired", async () => {
    const [s1, s2] = [new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }), new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })];
    const recs = [pending("ORD-pg-twice", { expires_at: "2026-10-22T10:15:00.000Z" }), pending("ORD-pg-twice", { expires_at: "2026-10-22T10:15:00.000Z" })];
    const [a, b] = await Promise.all([s1.create(recs[0]!), s2.create(recs[1]!)]);
    expect(a.confirmation_id).toBe(b.confirmation_id);
    const later = "2026-10-22T10:20:00.000Z";
    const expired = await Promise.all([s1.expire(a.confirmation_id, later), s2.expire(a.confirmation_id, later)]);
    expect(expired.filter(Boolean)).toHaveLength(1);
    expect((await rows(a.confirmation_id)).map((x) => x.type)).toEqual(["confirmation.required", "confirmation.expired"]);
  });

  it("Дополнения РП51 п. 1: блокировка агента занята дольше lockTimeoutMs — создание запроса отказывает (55P03), запроса и события нет", async () => {
    const agent = "nspk:agent:cnf-pg-lock:v1";
    const holder = await db.pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock($1::bigint)", [eventSeqLockKey(agent)]);
      const rec = pending("ORD-pg-lock", { agent_code: agent });
      const t0 = Date.now();
      expect(await code(new PgConfirmationStore(pool2, { lockTimeoutMs: 100 }).create(rec))).toBe("55P03");
      expect(Date.now() - t0, "отказ по пределу, а не по таймауту теста").toBeLessThan(2_000);
      const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
      expect(await store.byKey(rec)).toEqual([]);
      expect(await rows(rec.confirmation_id)).toEqual([]);
    } finally {
      await holder.query("ROLLBACK");
      holder.release();
    }
  });

  it("lockTimeoutMs — целое ≥ 1, иначе отказ конструктора", () => {
    for (const v of [0, -1, 1.5, Number.NaN]) expect(() => new PgConfirmationStore(db.pool, { lockTimeoutMs: v }), String(v)).toThrow(/lockTimeoutMs/);
  });
});
