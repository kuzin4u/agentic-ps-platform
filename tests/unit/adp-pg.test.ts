// П4 запись операции ADP на PostgreSQL (PS-10 К2.1, доп. РП43 п. 16): условная вставка «в работе» — из одновременных
// запросов с двух экземпляров (два пула) к резерву проходит один; решение пишется один раз; решённую строку триггер не
// даёт изменить или удалить. ПС10 через ADP (К2.4): два экземпляра ADP на двух пулах — 20 одновременных авторизаций по
// 1 000 ₽ при 3 000 ₽ — ровно 3 APPROVE; один op_ref с двух экземпляров — одно одобрение. Окно дробления (PS-13, РП44
// п. 4): вход под блокировкой ключа окна — из двух долей с двух экземпляров одобряется одна; бюджет и дробление в одном
// залпе (доп. п. 1); столбцы окна — один раз. В CI (РП30 п. 7); локально без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  Adp,
  PgOperationStore,
  splitWindowLockKey,
  type AdpMandate,
  type AdpMandates,
  type PgOperationHooks,
} from "../../src/adp/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { agentToken, agentTokenCredentials } from "../support/agent-token.js";
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
    s1 = new PgOperationStore(db.pool, { lockTimeoutMs: 150 });
    s2 = new PgOperationStore(db.reopen(), { lockTimeoutMs: 150 });
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

  it("признаки уведомителя — тем же UPDATE, что решение; решением не меняются (РП46 доп. п. 9 (о1))", async () => {
    const op = opRef();
    await s1.begin(op, H, AT);
    const notify = {
      participant_code: "bank:a",
      principal_ref: "prn_1",
      agent_code: "nspk:agent:buyref-01:v3",
      limit_source: "CLIENT" as const,
      client_account: "client:bank:a:prn_1:DAY:2026-10-20",
      client_left_after: 0,
    };
    await s1.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: "mnd_1", holds: ["h1"], at: AT, notify });
    await s2.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: "mnd_1", holds: ["h1"], at: AT, notify: { ...notify, client_left_after: 5 } });
    const r = await db.pool.query(
      "SELECT participant_code, principal_ref, agent_code, limit_source, client_account, client_left_after FROM adp_operations WHERE op_ref = $1",
      [op],
    );
    expect(r.rows[0]).toEqual({ ...notify, client_left_after: "0" });
    const bare = opRef();
    await s1.begin(bare, H, AT);
    await s1.finish({ op_ref: bare, msg_hash: H, decision: APPROVE, mandate_id: null, holds: [], at: AT });
    const b = await db.pool.query("SELECT participant_code, limit_source FROM adp_operations WHERE op_ref = $1", [bare]);
    expect(b.rows[0]).toEqual({ participant_code: null, limit_source: null });
    // Предел инструмента — INSTRUMENT (РП49 (е)): CHECK sql/109 его принимает.
    const inst = opRef();
    await s1.begin(inst, H, AT);
    const declined: Decision = { decision: "DECLINE", reason: "LIMIT_EXCEEDED", decided_in_ms: 3 };
    await s1.finish({ op_ref: inst, msg_hash: H, decision: declined, mandate_id: "mnd_1", holds: [], at: AT, notify: { ...notify, limit_source: "INSTRUMENT" } });
    const i = await db.pool.query("SELECT limit_source FROM adp_operations WHERE op_ref = $1", [inst]);
    expect(i.rows[0]).toEqual({ limit_source: "INSTRUMENT" });
  });

  it("finish с другим хэшем не меняет запись «в работе»", async () => {
    const op = opRef();
    await s1.begin(op, H, AT);
    await s1.finish({ op_ref: op, msg_hash: "b".repeat(64), decision: APPROVE, mandate_id: null, holds: [], at: AT });
    expect((await s1.begin(op, H, AT))?.decision).toBeNull();
  });

  it("столбцы окна — один раз у записи «в работе»; решением и повторно не меняются (РП44 п. 4)", async () => {
    const op = opRef();
    const e = { key: "mnd_w", amount: 100, currency: "RUB", at_ms: 1 };
    const rule = { since_ms: 0, threshold: 300_000, min_ops: 2 };
    await expect(s1.enterWindow(op, e, rule), "вход без записи «в работе»").rejects.toThrow();
    await s1.begin(op, H, AT);
    expect(await s1.enterWindow(op, e, rule)).toEqual({ entered: true, ops: 1, sum: 100 });
    await expect(s2.enterWindow(op, e, rule), "второй вход той же записи").rejects.toThrow();
    await expect(db.pool.query("UPDATE adp_operations SET amount = 1 WHERE op_ref = $1", [op])).rejects.toThrow(/один раз/);
    await s1.finish({ op_ref: op, msg_hash: H, decision: APPROVE, mandate_id: null, holds: [], at: AT });
    const r = await db.pool.query("SELECT window_key, amount, currency, window_at_ms FROM adp_operations WHERE op_ref = $1", [op]);
    expect(r.rows[0]).toEqual({ window_key: "mnd_w", amount: "100", currency: "RUB", window_at_ms: "1" });
    const other = opRef();
    await s1.begin(other, H, AT);
    await expect(s1.enterWindow(other, { ...e, currency: "USD" }, rule)).rejects.toThrow(/валют/);
  });

  it("вставка только «в работе» без решения и окна (BEFORE INSERT, доп. РП44 п. 2)", async () => {
    const ins = (cols: string, vals: string) =>
      db.pool.query(`INSERT INTO adp_operations (op_ref, msg_hash, at, ${cols}) VALUES ($1, $2, $3, ${vals})`, [opRef(), H, AT]);
    await expect(ins("decision", `'{"decision":"APPROVE","reason":null}'::jsonb`)).rejects.toThrow(/только «в работе»/);
    await expect(ins("window_key, amount, currency, window_at_ms", "'mnd_x', 1, 'RUB', 1")).rejects.toThrow(/только «в работе»/);
  });

  it("ожидание блокировки окна — не дольше lockTimeoutMs: исключение без входа в окно (доп. РП44 п. 2)", async () => {
    const op = opRef();
    const key = `mnd_lock_${op}`;
    await s1.begin(op, H, AT);
    const holder = await db.pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock($1::bigint)", [splitWindowLockKey(key)]);
      const quick = new PgOperationStore(db.reopen(), { lockTimeoutMs: 50 });
      await expect(quick.enterWindow(op, { key, amount: 1, currency: "RUB", at_ms: 1 }, { since_ms: 0, threshold: 300_000, min_ops: 2 })).rejects.toThrow(
        /lock timeout|блокировк/i,
      );
    } finally {
      await holder.query("ROLLBACK");
      holder.release();
    }
    const r = await db.pool.query("SELECT window_key FROM adp_operations WHERE op_ref = $1", [op]);
    expect(r.rows[0]).toEqual({ window_key: null });
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
  readonly roots = new Map<string, string>();
  /**
   * CART под своим корнем INTENT (РП49 (б): агентский токен — только по CART). Предел корня больше предела CART —
   * решает предел CART, как прежде у INTENT; ключ окна дробления у CART — корень (РП44 п. 2), он у каждого мандата свой.
   */
  add(limit: number, scope: string[] = ["MER-1042"]): string {
    const root = mandate();
    const id = mandate();
    // Клиент — свой на мандат: лимиты клиента здесь не заданы (они — adp-client-pg.test.ts).
    const client = { participant_code: "bank:pg", principal_ref: `prn_${mseq}` };
    this.map.set(root, { status: "ACTIVE", type: "INTENT", merchant_scope: scope, currency: "RUB", amount_limit: 1_000 * limit, client });
    this.map.set(id, { status: "ACTIVE", type: "CART", parent_id: root, merchant_scope: scope, currency: "RUB", amount_limit: limit, client });
    this.roots.set(id, root);
    return id;
  }
  /** Корень INTENT со своим пределом и CART под ним (связывающий корень: сумма CART больше предела корня). */
  addRoot(limit: number): string {
    const root = mandate();
    this.map.set(root, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: limit, client: { participant_code: "bank:pg", principal_ref: `prn_${mseq}` } });
    return root;
  }
  addCart(root: string, limit: number): string {
    const id = mandate();
    const r = this.map.get(root) as AdpMandate;
    this.map.set(id, { ...r, type: "CART", parent_id: root, amount_limit: limit });
    this.roots.set(id, root);
    return id;
  }
  /** Ключ окна дробления мандата — его корень INTENT. */
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

const auth = (mandate_id: string, op_ref: string, amount: number, merchant = "MER-1042"): CanonicalMessage =>
  agentToken({
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
  const instance = (
    pool: pg.Pool,
    p: { threshold?: number; splitMinOps?: number; lockTimeoutMs?: number } = {},
    hooks?: PgOperationHooks,
  ): Adp =>
    new Adp({
      agents: { get: (c) => (c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      clientLimits: { get: async () => [] },
      state: new StateService(new PgHoldLedger(pool), mandates, { reservationTtlSec: 600 }),
      credentials: agentTokenCredentials,
      // Предел ожидания блокировки окна в бою — adp_timeout_ms; в залпах на CI — с запасом, чтобы не мерить скорость CI.
      operations: new PgOperationStore(pool, { lockTimeoutMs: p.lockTimeoutMs ?? 5_000, ...(hooks ? { hooks } : {}) }),
      params: {
        aoi_rollout_phase: 3,
        confirm_above_kop: p.threshold ?? 1_000_000,
        split_window_sec: 600,
        // ПС10 проверяет одно решение — бюджет: правило доли вне залпа (21 > 20 операций; РП44 доп. п. 1).
        split_min_ops: p.splitMinOps ?? 21, client_limit_period_tz: "Europe/Moscow",
      },
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

  it("связывающий корень: две CART по 3 000 ₽ под INTENT 3 000 ₽, 20 по 1 000 ₽ с двух экземпляров — ровно 3 APPROVE, удержания CART у отказанных освобождены", async () => {
    // Ревью К1б № 6 (решение владельца): решает счёт корня, а не CART — путь «CART прошёл, корень отказал» под гонкой.
    const root = mandates.addRoot(300_000);
    const [c1, c2] = [mandates.addCart(root, 300_000), mandates.addCart(root, 300_000)];
    const ds = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a1 : a2).decide(auth(i % 4 < 2 ? c1 : c2, `OPKC-ROOT-PG-${i}`, 100_000))));
    const pairs = ds.map((d) => parseDecision(d, "adp"));
    const approved = pairs.filter((p) => p.decision === "APPROVE").length;
    expect(approved, `перерасход корня: одобрено ${approved} при месте для 3 (инвариант 4)`).toBe(3);
    expect(pairs.filter((p) => p.reason === "LIMIT_EXCEEDED")).toHaveLength(17);
    const r = await ledger.account(accountId(root));
    expect(r.reserved + r.committed, "перерасход: закреплено + зарезервировано > предела корня").toBeLessThanOrEqual(r.limit);
    expect(r.reserved).toBe(300_000);
    // Отказ корня освобождает удержание CART: на счетах CART держится ровно одобренное.
    const held = (await ledger.account(accountId(c1))).reserved + (await ledger.account(accountId(c2))).reserved;
    expect(held, "удержание CART не освобождено после отказа корня (РП43 п. 6)").toBe(300_000);
  });

  it("бюджет и дробление в одном залпе (РП44 доп. п. 1): 20 по 1 000 ₽ при пределе и пороге 3 000 ₽ — ровно 3 APPROVE", async () => {
    const M = mandates.add(300_000);
    const [b1, b2] = [instance(db.pool, { threshold: 300_000, splitMinOps: 2 }), instance(db.reopen(), { threshold: 300_000, splitMinOps: 2 })];
    const ds = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? b1 : b2).decide(auth(M, `OPKC-MIX-PG-${i}`, 100_000))));
    expect(ds.filter((d) => d.decision === "APPROVE"), "бюджет превышен или недобран (инвариант 4)").toHaveLength(3);
    // Остальные 17 — доли: к резерву не идут; ответ — по остатку, прочитанному без резерва (до резервов трёх первых —
    // CONFIRMATION_REQUIRED со split_detected: true, после — LIMIT_EXCEEDED без поля).
    for (const d of ds.filter((x) => x.decision !== "APPROVE")) {
      if (d.decision === "CONFIRMATION_REQUIRED") expect(d.split_detected).toBe(true);
      else expect([parseDecision(d, "adp").reason, d.split_detected]).toEqual(["LIMIT_EXCEEDED", undefined]);
    }
    expect((await ledger.account(accountId(M))).reserved).toBe(300_000);
    const w = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM adp_operations WHERE window_key = $1", [mandates.root(M)]);
    expect(Number(w.rows[0]?.n), "в окно вошли только одобренные").toBe(3);
  });

  it("две доли с двух экземпляров, гонка между чтением и записью окна — одобрена одна (блокировка ключа окна)", async () => {
    const M = mandates.add(1_000_000);
    // Управляемая пауза без тайм-аута (доп. РП44 п. 2): первый, прочитав окно, ждёт, пока второй пройдёт beforeLock и
    // либо встанет на блокировке ключа окна (видно в pg_locks), либо — без блокировки — сам прочитает окно. С блокировкой
    // второй читает окно только после COMMIT первого и видит его вход (доля); без неё оба читают пустое окно — две доли
    // одобрены (поломка К1.5, К2.1а).
    let tried = 0;
    let readers = 0;
    let secondRead = false;
    const watcher = db.reopen();
    // Ожидание именно этой блокировки: pg_locks — на весь кластер, ключ advisory — classid (старшие 32 бита) и objid.
    const secondBlocked = async (): Promise<boolean> => {
      const r = await watcher.query<{ n: string }>(
        `SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
            AND ((classid::bigint << 32) | objid::bigint) = $1::bigint`,
        [splitWindowLockKey(mandates.root(M))],
      );
      return Number(r.rows[0]?.n) > 0;
    };
    const hooks: PgOperationHooks = {
      beforeLock: async () => {
        tried++;
      },
      windowRead: async () => {
        if (++readers > 1) {
          secondRead = true;
          return;
        }
        // Второй вошёл в транзакцию (beforeLock — до или после этого чтения), затем стоит на блокировке или читает сам.
        while (!(tried >= 2 && (secondRead || (await secondBlocked())))) await new Promise((r) => setTimeout(r, 5));
      },
    };
    const [c1, c2] = [instance(db.pool, { threshold: 300_000, splitMinOps: 2 }, hooks), instance(db.reopen(), { threshold: 300_000, splitMinOps: 2 }, hooks)];
    const ds = await Promise.all([c1.decide(auth(M, "OPKC-SPLIT-PG-1", 170_000)), c2.decide(auth(M, "OPKC-SPLIT-PG-2", 170_000))]);
    expect(ds.filter((d) => d.decision === "APPROVE"), "две доли под порогом одобрены (обход порога дроблением)").toHaveLength(1);
    expect(ds.filter((d) => d.decision === "CONFIRMATION_REQUIRED" && d.split_detected === true)).toHaveLength(1);
    await watcher.end();
  });

  it("ожидание блокировки окна дольше предела — STATE_UNAVAILABLE без входа в окно и без резерва (доп. РП44 п. 2)", async () => {
    const M = mandates.add(1_000_000);
    const a = instance(db.reopen(), { threshold: 300_000, splitMinOps: 2, lockTimeoutMs: 50 });
    const holder = await db.pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock($1::bigint)", [splitWindowLockKey(mandates.root(M))]);
      const d = await a.decide(auth(M, "OPKC-LOCK-PG-1", 170_000));
      expect([d.decision, d.reason]).toEqual(["DECLINE", "STATE_UNAVAILABLE"]);
    } finally {
      await holder.query("ROLLBACK");
      holder.release();
    }
    const r = await db.pool.query("SELECT window_key, holds FROM adp_operations WHERE op_ref = $1", ["OPKC-LOCK-PG-1"]);
    expect(r.rows[0]).toEqual({ window_key: null, holds: [] });
  });

  it("ПС12 на PG: вторая доля — CONFIRMATION_REQUIRED с split_detected; вне окна (через 600 с) — APPROVE", async () => {
    const M = mandates.add(1_000_000);
    let ms = Date.parse("2026-10-19T10:00:00Z");
    const a = new Adp({
      agents: { get: (c) => (c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      clientLimits: { get: async () => [] },
      state: new StateService(new PgHoldLedger(db.pool), mandates, { reservationTtlSec: 600 }),
      credentials: agentTokenCredentials,
      operations: new PgOperationStore(db.pool, { lockTimeoutMs: 150 }),
      params: { aoi_rollout_phase: 3, confirm_above_kop: 300_000, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
      now: () => new Date(ms),
    });
    expect((await a.decide(auth(M, "OPKC-PS12-PG-1", 170_000))).decision).toBe("APPROVE");
    const d = await a.decide(auth(M, "OPKC-PS12-PG-2", 170_000));
    expect([d.decision, d.split_detected]).toEqual(["CONFIRMATION_REQUIRED", true]);
    ms += 600_000;
    expect((await a.decide(auth(M, "OPKC-PS12-PG-3", 170_000))).decision).toBe("APPROVE");
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
