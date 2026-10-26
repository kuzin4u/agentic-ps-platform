// Однократность confirmation_ref на PostgreSQL (PS-19 ч. 1, РП50 п. 2, 5, 10; инвариант 7, A7 п. 7.2): две авторизации
// одной ссылкой одновременно на двух экземплярах — ровно одна APPROVE, вторая CONFIRMATION_REQUIRED, её удержание
// освобождено. Погашение — один условный UPDATE … WHERE status = 'APPROVED'; запрос в ожидании на ключ — один (частичный
// уникальный индекс); триггер sql/111 не даёт перехода вне РП50 п. 5. Решение человека — записью хранилища, не через
// ПИ-8 (не доказательство ПИ-8). В CI (РП30 п. 7); локально без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Adp, PgOperationStore, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import {
  newConfirmationId,
  newConfirmationRef,
  PgConfirmationStore,
  totalsHash,
  type ConfirmationRecord,
  type ConfirmationStore,
} from "../../src/confirm/index.js";
import { opaqueRef } from "../../src/credentials/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { agentToken, agentTokenCredentials } from "../support/agent-token.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:buyref-01:v3";
const AT = "2026-10-22T10:00:00.000Z";
const EXPIRES = "2099-01-01T00:00:00.000Z";
let seq = 0;

class Mandates implements AdpMandates, MandateBudgetSource {
  readonly map = new Map<string, AdpMandate>();
  /** CART под своим корнем INTENT; предел корня больше предела CART. */
  add(limit: number): string {
    const next = () => `mnd_00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
    const [root, id] = [next(), next()];
    const client = { participant_code: "bank:pg", principal_ref: opaqueRef("prn_") };
    this.map.set(root, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: 1_000 * limit, client });
    this.map.set(id, { status: "ACTIVE", type: "CART", parent_id: root, merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: limit, client });
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

const pending = (mandate_id: string, order_ref: string, amount: number): ConfirmationRecord => ({
  confirmation_id: newConfirmationId(),
  agent_code: AGENT,
  mandate_id,
  merchant_id: "MER-1042",
  amount,
  currency: "RUB",
  order_ref,
  split_detected: false,
  status: "PENDING",
  created_at: AT,
  expires_at: EXPIRES,
  confirmation_ref: null,
  decision: null,
  op_ref: null,
});

/** Решение человека — записью хранилища (не ПИ-8). */
async function approved(store: ConfirmationStore, r: ConfirmationRecord): Promise<string> {
  const ref = newConfirmationRef();
  const d = { participant_code: "bank:pg", kid: "kid-pg", decision: "APPROVE" as const, totals_hash: totalsHash(r), decided_at: AT, signature: "s".repeat(86) };
  const done = await store.decide(r.confirmation_id, d, ref, AT);
  if (done?.status !== "APPROVED") throw new Error("подтверждение не записано");
  return ref;
}

const auth = (mandate_id: string, order_ref: string, op_ref: string, amount: number, confirmation_ref?: string): CanonicalMessage =>
  agentToken({
    op_ref,
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5462" },
    instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_pg" },
    aoi: { indicator: true, agent_code: AGENT, mandate_id },
    order_ref,
    ...(confirmation_ref ? { confirmation_ref } : {}),
  });

/**
 * Обе авторизации доходят до погашения прежде, чем любая его выполнит: обе прошли проверку ссылки (APPROVED) и
 * зарезервировали — дальше решает только условие UPDATE. Предохранитель: не дождались второго — погашение по таймеру.
 */
function gateConsume(stores: ConfirmationStore[], fuseMs = 3_000): ConfirmationStore[] {
  let waiting = stores.length;
  let open!: () => void;
  const gate = new Promise<void>((r) => (open = r));
  const fuse = setTimeout(() => open(), fuseMs);
  return stores.map((s) => {
    const w = Object.create(s) as ConfirmationStore;
    w.consume = async (ref, op, now) => {
      if (--waiting === 0) {
        clearTimeout(fuse);
        open();
      }
      await gate;
      return s.consume(ref, op, now);
    };
    return w;
  });
}

/**
 * Обе стороны прочитали ключ (запроса нет) прежде, чем любая вставит: дальше решает только ON CONFLICT по частичному
 * уникальному индексу (ворота К1 № 2). Предохранитель — как у gateConsume.
 */
function gateByKey(stores: ConfirmationStore[], fuseMs = 3_000): ConfirmationStore[] {
  let waiting = stores.length;
  let open!: () => void;
  const gate = new Promise<void>((r) => (open = r));
  const fuse = setTimeout(() => open(), fuseMs);
  return stores.map((s) => {
    const w = Object.create(s) as ConfirmationStore;
    w.byKey = async (key) => {
      const rows = await s.byKey(key);
      if (--waiting === 0) {
        clearTimeout(fuse);
        open();
      }
      await gate;
      return rows;
    };
    return w;
  });
}

/** Отказ триггера sql/111 — restrict_violation (23001), а не любая ошибка (ворота К1 № 8). */
async function guarded(p: Promise<unknown>, what: string): Promise<void> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e as { code?: string },
  );
  expect(err?.code, what).toBe("23001");
}

describe.skipIf(!DATABASE_URL)("однократность confirmation_ref на PostgreSQL: два экземпляра (РП50 п. 10, инвариант 7)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  const mandates = new Mandates();
  const instance = (pool: pg.Pool, store: ConfirmationStore): Adp =>
    new Adp({
      agents: { get: async (c) =>(c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      clientLimits: { get: async () => [] },
      state: new StateService(new PgHoldLedger(pool), mandates, { reservationTtlSec: 600 }),
      operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
      credentials: agentTokenCredentials,
      confirmations: { store, order_hold_sec: 900 },
      params: { aoi_rollout_phase: 3, confirm_above_kop: 300_000, split_window_sec: 600, split_min_ops: 21, client_limit_period_tz: "Europe/Moscow" },
    });

  beforeAll(async () => {
    db = await openTestDb("adp_confirm");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  it("две авторизации одной ссылкой одновременно — ровно одна APPROVE, вторая CONFIRMATION_REQUIRED, удержание освобождено", async () => {
    const M = mandates.add(1_000_000);
    const s1 = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await s1.create(pending(M, "ORD-race", 340_000));
    const ref = await approved(s1, r);
    const [g1, g2] = gateConsume([s1, new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })]);
    const [a1, a2] = [instance(db.pool, g1!), instance(pool2, g2!)];
    const ds = await Promise.all([
      a1.decide(auth(M, "ORD-race", "OPKC-CNF-PG-1", 340_000, ref)),
      a2.decide(auth(M, "ORD-race", "OPKC-CNF-PG-2", 340_000, ref)),
    ]);
    const pairs = ds.map((d) => parseDecision(d, "adp"));
    expect(pairs.filter((p) => p.decision === "APPROVE"), "одна ссылка подтверждения одобрена дважды (инвариант 7)").toHaveLength(1);
    expect(
      pairs.filter((p) => p.decision !== "APPROVE").map((p) => p.decision),
      "проигравшая авторизация: ожидался CONFIRMATION_REQUIRED по погашенной ссылке (РП50 п. 10)",
    ).toEqual(["CONFIRMATION_REQUIRED"]);
    const a = await new PgHoldLedger(db.pool).account(accountId(M));
    expect(a.reserved, "удержание проигравшей не освобождено (инвариант 4)").toBe(340_000);
    const used = await s1.byRef(ref);
    const winner = ds.findIndex((d) => d.decision === "APPROVE");
    expect(used).toMatchObject({ status: "USED", op_ref: `OPKC-CNF-PG-${winner + 1}` });
  });

  it("CONFIRMATION_REQUIRED на один заказ с двух экземпляров одновременно — один запрос в ожидании", async () => {
    const M = mandates.add(1_000_000);
    const [g1, g2] = gateByKey([new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }), new PgConfirmationStore(pool2, { lockTimeoutMs: 5_000 })]);
    const [a1, a2] = [instance(db.pool, g1!), instance(pool2, g2!)];
    const ds = await Promise.all([
      a1.decide(auth(M, "ORD-twice", "OPKC-CNF-PG-3", 340_000)),
      a2.decide(auth(M, "ORD-twice", "OPKC-CNF-PG-4", 340_000)),
    ]);
    expect(ds.map((d) => d.decision)).toEqual(["CONFIRMATION_REQUIRED", "CONFIRMATION_REQUIRED"]);
    const rows = await new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 }).byKey({ mandate_id: M, merchant_id: "MER-1042", order_ref: "ORD-twice", amount: 340_000, currency: "RUB" });
    expect(rows.map((x) => x.status)).toEqual(["PENDING"]);
  });

  it("триггер: итоговые значения не меняются, USED назад не возвращается, решение после USED и удаление — запрещены", async () => {
    const M = mandates.add(1_000_000);
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending(M, "ORD-guard", 340_000));
    const ref = await approved(store, r);
    expect(await store.consume(ref, "OPKC-CNF-PG-5", AT)).toBe(true);
    expect(await store.consume(ref, "OPKC-CNF-PG-6", AT), "второе погашение").toBe(false);
    const id = r.confirmation_id;
    for (const sql of [
      `UPDATE confirmations SET amount = 1 WHERE confirmation_id = '${id}'`,
      `UPDATE confirmations SET status = 'APPROVED', op_ref = NULL WHERE confirmation_id = '${id}'`,
      `UPDATE confirmations SET status = 'REJECTED', confirmation_ref = NULL, op_ref = NULL, decision = 'REJECT' WHERE confirmation_id = '${id}'`,
      `DELETE FROM confirmations WHERE confirmation_id = '${id}'`,
      "TRUNCATE confirmations",
    ]) {
      await guarded(db.pool.query(sql), sql);
    }
    // Переходы вне РП50 п. 5 из других статусов: EXPIRED → APPROVED, REJECTED → APPROVED, APPROVED → EXPIRED/REJECTED,
    // PENDING → USED.
    const d = { participant_code: "bank:pg", kid: "kid-pg", totals_hash: "0".repeat(64), decided_at: AT, signature: "s".repeat(86) };
    const exp = await store.create(pending(M, "ORD-g-exp", 1));
    await store.expire(exp.confirmation_id, EXPIRES);
    const rej = await store.create(pending(M, "ORD-g-rej", 1));
    await store.decide(rej.confirmation_id, { ...d, decision: "REJECT" }, null, AT);
    const apr = await store.create(pending(M, "ORD-g-apr", 1));
    const aprRef = await approved(store, apr);
    const pen = await store.create(pending(M, "ORD-g-pen", 1));
    const approve = (cid: string) =>
      `UPDATE confirmations SET status = 'APPROVED', confirmation_ref = '${newConfirmationRef()}', participant_code = 'bank:pg', kid = 'kid-pg',
         decision = 'APPROVE', totals_hash = '${"0".repeat(64)}', decided_at = '${AT}', signature = '${"s".repeat(86)}' WHERE confirmation_id = '${cid}'`;
    await guarded(db.pool.query(approve(exp.confirmation_id)), "EXPIRED → APPROVED");
    await guarded(db.pool.query(approve(rej.confirmation_id)), "REJECTED → APPROVED");
    await guarded(
      db.pool.query(`UPDATE confirmations SET status = 'EXPIRED', confirmation_ref = NULL, participant_code = NULL, kid = NULL, decision = NULL,
         totals_hash = NULL, decided_at = NULL, signature = NULL WHERE confirmation_id = '${apr.confirmation_id}'`),
      "APPROVED → EXPIRED",
    );
    await guarded(
      db.pool.query(`UPDATE confirmations SET status = 'REJECTED', confirmation_ref = NULL, decision = 'REJECT' WHERE confirmation_id = '${apr.confirmation_id}'`),
      "APPROVED → REJECTED",
    );
    await guarded(db.pool.query(`UPDATE confirmations SET status = 'USED', op_ref = 'OPKC-x' WHERE confirmation_id = '${pen.confirmation_id}'`), "PENDING → USED");
    expect((await store.byRef(aprRef))?.status).toBe("APPROVED");
    await guarded(
      db.pool.query(
        `INSERT INTO confirmations (confirmation_id, agent_code, mandate_id, merchant_id, amount, currency, order_ref, split_detected, status, created_at, expires_at)
         VALUES ($1, $2, $3, 'MER-1042', 1, 'RUB', 'ORD-x', false, 'EXPIRED', $4, $5)`,
        [newConfirmationId(), AGENT, M, AT, EXPIRES],
      ),
      "вставка не в ожидании",
    );
    expect((await store.get(id))?.status).toBe("USED");
  });

  it("instrument_chosen (sql/113, РП51 п. 13): хранится с решением, погашение его не меняет; без решения и не CARD/SBP — CHECK", async () => {
    const M = mandates.add(1_000_000);
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending(M, "ORD-instr", 340_000));
    const ref = newConfirmationRef();
    const d = { participant_code: "stand:upk-emulator", kid: "kid-upk", decision: "APPROVE" as const, totals_hash: totalsHash(r), decided_at: AT, signature: "s".repeat(86), instrument_chosen: "SBP" as const };
    expect((await store.decide(r.confirmation_id, d, ref, AT))?.decision).toEqual(d);
    expect(await store.consume(ref, "OPKC-CNF-PG-instr", AT)).toBe(true);
    expect((await store.get(r.confirmation_id))?.decision?.instrument_chosen, "после USED").toBe("SBP");
    // Решение банка без инструмента читается без поля — запись побайтно прежняя.
    const plain = await store.create(pending(M, "ORD-instr-plain", 1));
    await approved(store, plain);
    expect((await store.get(plain.confirmation_id))?.decision).not.toHaveProperty("instrument_chosen");
    const id = r.confirmation_id;
    await guarded(db.pool.query(`UPDATE confirmations SET instrument_chosen = 'CARD' WHERE confirmation_id = '${id}'`), "USED: смена инструмента");
    await guarded(db.pool.query(`UPDATE confirmations SET instrument_chosen = NULL WHERE confirmation_id = '${id}'`), "USED: снятие инструмента");
    // Погашение APPROVED → USED не меняет выбор человека (кортеж триггера sql/113): смена и снятие — 23001; погашение
    // без смены — проходит. Строка USED выше этого не доказывает: USED → USED запрещён и без кортежа (КТ1, поломка 1b64c84).
    const apr = await store.create(pending(M, "ORD-instr-apr", 1));
    await store.decide(apr.confirmation_id, { ...d, totals_hash: totalsHash(apr) }, newConfirmationRef(), AT);
    const consume = (set: string) => `UPDATE confirmations SET status = 'USED', op_ref = 'OPKC-instr-x'${set} WHERE confirmation_id = '${apr.confirmation_id}'`;
    await guarded(db.pool.query(consume(", instrument_chosen = 'CARD'")), "APPROVED → USED со сменой SBP → CARD");
    await guarded(db.pool.query(consume(", instrument_chosen = NULL")), "APPROVED → USED со снятием инструмента");
    expect((await store.get(apr.confirmation_id))?.status).toBe("APPROVED");
    await db.pool.query(consume(""));
    expect((await store.get(apr.confirmation_id))?.decision?.instrument_chosen, "погашение без смены").toBe("SBP");
    const pen = await store.create(pending(M, "ORD-instr-pen", 1));
    for (const [what, sql] of [
      ["инструмент без решения", `UPDATE confirmations SET status = 'EXPIRED', instrument_chosen = 'CARD' WHERE confirmation_id = '${pen.confirmation_id}'`],
      ["инструмент не CARD/SBP", `UPDATE confirmations SET status = 'APPROVED', confirmation_ref = '${newConfirmationRef()}', participant_code = 'bank:pg', kid = 'kid-pg',
         decision = 'APPROVE', totals_hash = '${"0".repeat(64)}', decided_at = '${AT}', signature = '${"s".repeat(86)}', instrument_chosen = 'PAN'
         WHERE confirmation_id = '${pen.confirmation_id}'`],
    ] as const) {
      const err = await db.pool.query(sql).then(
        () => undefined,
        (e: unknown) => e as { code?: string },
      );
      expect(err?.code, what).toBe("23514");
    }
  });

  it("Дополнения РП50 п. 1: на ключ одна запись за всё время — после USED вставка на тот же ключ строку не добавляет", async () => {
    const M = mandates.add(1_000_000);
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create(pending(M, "ORD-once", 340_000));
    const ref = await approved(store, r);
    expect(await store.consume(ref, "OPKC-CNF-PG-7", AT)).toBe(true);
    const again = await store.create(pending(M, "ORD-once", 340_000));
    expect(again, "возвращена прежняя запись, а не новый запрос").toMatchObject({ confirmation_id: r.confirmation_id, status: "USED" });
    const key = { mandate_id: M, merchant_id: "MER-1042", order_ref: "ORD-once", amount: 340_000, currency: "RUB" };
    expect((await store.byKey(key)).map((x) => x.status)).toEqual(["USED"]);
  });

  it("Дополнения РП50 п. 4: формат сроков (toISOString) и валюты, срок позже создания — CHECK (23514)", async () => {
    const M = mandates.add(1_000_000);
    const insert = (over: { created_at?: string; expires_at?: string; currency?: string }) =>
      db.pool.query(
        `INSERT INTO confirmations (confirmation_id, agent_code, mandate_id, merchant_id, amount, currency, order_ref, split_detected, status, created_at, expires_at)
         VALUES ($1, $2, $3, 'MER-1042', 1, $4, $5, false, 'PENDING', $6, $7)`,
        [newConfirmationId(), AGENT, M, over.currency ?? "RUB", opaqueRef("ORD-"), over.created_at ?? AT, over.expires_at ?? EXPIRES],
      );
    const cases: [string, Parameters<typeof insert>[0]][] = [
      ["created_at без миллисекунд", { created_at: "2026-10-22T10:00:00Z" }],
      ["expires_at со смещением", { expires_at: "2099-01-01T03:00:00.000+03:00" }],
      ["expires_at не позже created_at", { expires_at: AT }],
      ["валюта строчными", { currency: "rub" }],
    ];
    for (const [what, over] of cases) {
      const err = await insert(over).then(
        () => undefined,
        (e: unknown) => e as { code?: string },
      );
      expect(err?.code, what).toBe("23514");
    }
  });

  it("решение после срока не записывается; PENDING после срока переходит в EXPIRED", async () => {
    const M = mandates.add(1_000_000);
    const store = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const r = await store.create({ ...pending(M, "ORD-late", 340_000), expires_at: "2026-10-22T10:15:00.000Z" });
    const later = "2026-10-22T10:15:00.000Z";
    const d = { participant_code: "bank:pg", kid: "kid-pg", decision: "APPROVE" as const, totals_hash: totalsHash(r), decided_at: AT, signature: "s".repeat(86) };
    expect(await store.decide(r.confirmation_id, d, newConfirmationRef(), later)).toBeUndefined();
    expect(await store.expire(r.confirmation_id, later)).toBe(true);
    expect((await store.get(r.confirmation_id))?.status).toBe("EXPIRED");
  });
});
