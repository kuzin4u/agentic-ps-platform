// Одноразовость криптограммы на PostgreSQL (PS-14 К1.3б, РП47 п. 8; A3 п. 4.4, инвариант 4): две авторизации одной
// криптограммой одновременно на двух экземплярах — ровно одна APPROVE, вторая CREDENTIAL_INVALID, её удержание
// освобождено. Погашение — один условный UPDATE … WHERE status = 'ISSUED'; триггер sql/108 не даёт вернуть USED.
// В CI (РП30 п. 7); локально без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Adp, PgOperationStore, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import { opaqueRef, PgCredentialStore, sha256Hex, type CredentialRecord, type CredentialStore } from "../../src/credentials/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:buyref-01:v3";
const AT = "2026-10-20T10:00:00.000Z";
const VALID_TO = "2099-01-01T00:00:00.000Z";
let seq = 0;

class Mandates implements AdpMandates, MandateBudgetSource {
  readonly map = new Map<string, AdpMandate>();
  readonly roots = new Map<string, string>();
  /** CART под своим корнем INTENT (РП49 (б): агентский токен — только по CART); предел корня больше предела CART. */
  add(limit: number): string {
    const next = () => `mnd_00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
    const [root, id] = [next(), next()];
    const client = { participant_code: "bank:pg", principal_ref: opaqueRef("prn_") };
    this.map.set(root, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: 1_000 * limit, client });
    this.map.set(id, { status: "ACTIVE", type: "CART", parent_id: root, merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: limit, client });
    this.roots.set(id, root);
    return id;
  }
  root(id: string): string {
    return this.roots.get(id) as string;
  }
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    return agent_code === AGENT ? this.map.get(id) : undefined;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    const m = this.map.get(id);
    return m && { status: "ACTIVE", amount_limit: m.amount_limit, currency: m.currency };
  }
}

/** Реквизит на мандат: токен и запись, как после выдачи П5 (выдача — credentials.test.ts, ps05.test.ts). */
async function issued(store: CredentialStore, mandate_id: string, cryptogram: string, amount_max: number): Promise<CredentialRecord> {
  const token_ref = opaqueRef("tok_ag_");
  await store.putToken({ token_ref, agent_code: AGENT, mandate_id, merchant_scope: ["MER-1042"], valid_to: VALID_TO, funding_ref: "fnd_pg", created_at: AT });
  return store.putCredential({
    credential_ref: opaqueRef("crd_"),
    agent_code: AGENT,
    mandate_id,
    token_ref,
    order_ref: opaqueRef("ORD-"),
    merchant_id: "MER-1042",
    amount_max,
    currency: "RUB",
    valid_to: VALID_TO,
    cryptogram_sha256: sha256Hex(cryptogram),
    status: "ISSUED",
    op_ref: null,
    created_at: AT,
  });
}

const auth = (mandate_id: string, token_ref: string, cryptogram: string, op_ref: string, amount: number): CanonicalMessage => ({
  op_ref,
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount,
  currency: "RUB",
  merchant: { id: "MER-1042" },
  instrument: { kind: "AGENT_TOKEN", token_ref, cryptogram },
  aoi: { indicator: true, agent_code: AGENT, mandate_id },
});

/**
 * Обе авторизации доходят до погашения прежде, чем любая его выполнит: обе прошли п. 4 (ISSUED) и зарезервировали —
 * дальше решает только условие UPDATE. Предохранитель: не дождались второго — погашение идёт по таймеру.
 */
function gateConsume(stores: CredentialStore[], fuseMs = 3_000): CredentialStore[] {
  let waiting = stores.length;
  let open!: () => void;
  const gate = new Promise<void>((r) => (open = r));
  const fuse = setTimeout(() => open(), fuseMs);
  return stores.map((s) => {
    const w = Object.create(s) as CredentialStore;
    w.consume = async (ref, op) => {
      if (--waiting === 0) {
        clearTimeout(fuse);
        open();
      }
      await gate;
      return s.consume(ref, op);
    };
    return w;
  });
}

describe.skipIf(!DATABASE_URL)("одноразовость криптограммы на PostgreSQL: два экземпляра (РП47 п. 8, A3 п. 4.4)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  const mandates = new Mandates();
  const instance = (pool: pg.Pool, credentials: CredentialStore): Adp =>
    new Adp({
      agents: { get: (c) => (c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      clientLimits: { get: async () => [] },
      state: new StateService(new PgHoldLedger(pool), mandates, { reservationTtlSec: 600 }),
      operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
      credentials,
      params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000, split_window_sec: 600, split_min_ops: 21, client_limit_period_tz: "Europe/Moscow" },
    });

  beforeAll(async () => {
    db = await openTestDb("adp_cred");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  it("две авторизации одной криптограммой одновременно — ровно одна APPROVE, вторая CREDENTIAL_INVALID, удержание освобождено", async () => {
    const M = mandates.add(300_000);
    const s1 = new PgCredentialStore(db.pool);
    const cred = await issued(s1, M, "cg-race", 100_000);
    const [g1, g2] = gateConsume([s1, new PgCredentialStore(pool2)]);
    const [a1, a2] = [instance(db.pool, g1!), instance(pool2, g2!)];
    const ds = await Promise.all([
      a1.decide(auth(M, cred.token_ref, "cg-race", "OPKC-CRED-PG-1", 100_000)),
      a2.decide(auth(M, cred.token_ref, "cg-race", "OPKC-CRED-PG-2", 100_000)),
    ]);
    const pairs = ds.map((d) => parseDecision(d, "adp"));
    expect(pairs.filter((p) => p.decision === "APPROVE"), "одна криптограмма одобрена дважды (A3 п. 4.4)").toHaveLength(1);
    expect(
      pairs.filter((p) => p.decision === "DECLINE").map((p) => p.reason),
      "проигравшая авторизация: ожидался отказ CREDENTIAL_INVALID по погашенной криптограмме (РП47 п. 8)",
    ).toEqual(["CREDENTIAL_INVALID"]);
    const a = await new PgHoldLedger(db.pool).account(accountId(M));
    expect(a.reserved, "удержание проигравшей не освобождено (инвариант 4)").toBe(100_000);
    // У CART — и счёт корня (РП43 п. 6): проигравшая освобождает оба удержания.
    expect((await new PgHoldLedger(db.pool).account(accountId(mandates.root(M)))).reserved, "удержание корня проигравшей не освобождено").toBe(100_000);
    const winner = ds[0]?.decision === "APPROVE" ? "OPKC-CRED-PG-1" : "OPKC-CRED-PG-2";
    expect(await s1.credentialByCryptogram(cred.token_ref, sha256Hex("cg-race"))).toMatchObject({ status: "USED", op_ref: winner });
  });

  it("10 одновременных авторизаций одной криптограммой с двух экземпляров — одна APPROVE, перерасхода нет", async () => {
    const M = mandates.add(1_000_000);
    const s1 = new PgCredentialStore(db.pool);
    const s2 = new PgCredentialStore(pool2);
    const cred = await issued(s1, M, "cg-burst", 50_000);
    const [a1, a2] = [instance(db.pool, s1), instance(pool2, s2)];
    const ds = await Promise.all(
      Array.from({ length: 10 }, (_, i) => (i % 2 ? a1 : a2).decide(auth(M, cred.token_ref, "cg-burst", `OPKC-CRED-BURST-${i}`, 50_000))),
    );
    expect(ds.filter((d) => d.decision === "APPROVE"), "одна криптограмма одобрена больше одного раза").toHaveLength(1);
    expect(ds.filter((d) => d.decision !== "APPROVE").map((d) => d.reason)).toEqual(Array(9).fill("CREDENTIAL_INVALID"));
    expect((await new PgHoldLedger(db.pool).account(accountId(M))).reserved).toBe(50_000);
    expect((await new PgHoldLedger(db.pool).account(accountId(mandates.root(M)))).reserved).toBe(50_000);
  });

  it("одновременная запись реквизита одного заказа и токена одного CART с двух экземпляров — одна строка", async () => {
    const M = mandates.add(10_000);
    const s1 = new PgCredentialStore(db.pool);
    const s2 = new PgCredentialStore(pool2);
    const token = (ref: string) => ({ token_ref: ref, agent_code: AGENT, mandate_id: M, merchant_scope: ["MER-1042"], valid_to: VALID_TO, funding_ref: "fnd_pg", created_at: AT });
    const [t1, t2] = await Promise.all([s1.putToken(token("tok_ag_one")), s2.putToken(token("tok_ag_two"))]);
    expect(t1).toEqual(t2);
    const rec = (ref: string, h: string): CredentialRecord => ({
      credential_ref: ref,
      agent_code: AGENT,
      mandate_id: M,
      token_ref: t1.token_ref,
      order_ref: "ORD-same",
      merchant_id: "MER-1042",
      amount_max: 10_000,
      currency: "RUB",
      valid_to: VALID_TO,
      cryptogram_sha256: sha256Hex(h),
      status: "ISSUED",
      op_ref: null,
      created_at: AT,
    });
    const [c1, c2] = await Promise.all([s1.putCredential(rec("crd_one", "a")), s2.putCredential(rec("crd_two", "b"))]);
    expect(c1).toEqual(c2);
    const n = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM agent_credentials WHERE mandate_id = $1", [M]);
    expect(Number(n.rows[0]?.n)).toBe(1);
    // Реквизит по ссылке (GET, РП49 (г)) — с другого экземпляра та же запись; неизвестная ссылка — undefined.
    expect(await s2.credentialByRef(c1.credential_ref, AGENT)).toEqual(c1);
    expect(await s2.credentialByRef("crd_unknown", AGENT)).toBeUndefined();
    // Пара (credential_ref, agent_code) — один запрос: чужой агент для хранилища — «не найдено», как неизвестный.
    expect(await s2.credentialByRef(c1.credential_ref, "nspk:agent:other:v1")).toBeUndefined();
  });

  it("триггер: USED не возвращается в ISSUED, ключевые поля не меняются, удаление и TRUNCATE запрещены", async () => {
    const M = mandates.add(10_000);
    const s1 = new PgCredentialStore(db.pool);
    const cred = await issued(s1, M, "cg-guard", 10_000);
    expect(await s1.consume(cred.credential_ref, "OPKC-G-1")).toBe(true);
    expect(await s1.consume(cred.credential_ref, "OPKC-G-2")).toBe(false);
    const ref = cred.credential_ref;
    await expect(db.pool.query("UPDATE agent_credentials SET status = 'ISSUED', op_ref = NULL WHERE credential_ref = $1", [ref])).rejects.toThrow(/только погашение/);
    await expect(db.pool.query("UPDATE agent_credentials SET amount_max = 1 WHERE credential_ref = $1", [ref])).rejects.toThrow(/только погашение/);
    await expect(db.pool.query("DELETE FROM agent_credentials WHERE credential_ref = $1", [ref])).rejects.toThrow(/удаление запрещено/);
    await expect(db.pool.query("TRUNCATE agent_credentials")).rejects.toThrow(/удаление запрещено/);
  });

  it("номера карты нет в строках agent_tokens и agent_credentials: без серий из 13–19 цифр (хэш — отдельно, инвариант 1)", async () => {
    const r = await db.pool.query("SELECT * FROM agent_tokens");
    const c = await db.pool.query<Record<string, unknown>>("SELECT * FROM agent_credentials");
    expect(c.rows.length).toBeGreaterThan(0);
    for (const row of c.rows) expect(String(row.cryptogram_sha256)).toMatch(/^[0-9a-f]{64}$/);
    const rows = c.rows.map((row) => {
      const rest = { ...row };
      delete rest.cryptogram_sha256;
      return rest;
    });
    const dump = JSON.stringify([r.rows, rows]);
    expect(dump).not.toMatch(/\d{13,19}/);
  });
});
