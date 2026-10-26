// П3/П4 лимит клиента на PostgreSQL (PS-20 К1.5, РП45 п. 1; инвариант 4): второй счёт удержаний ядра — условие по
// остатку и изменение одной операцией, поэтому и на двух экземплярах (два пула) по двум мандатам одного клиента сумма
// одобрений не выше per_period. Контрольная точка PS-20 части 1; поломка — через CI. Локально без базы — пропуск.
import { PgHoldLedger } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Adp, PgOperationStore, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { periodStart } from "../../src/participants/limits.js";
import { parseDecision } from "../../src/shared/codes.js";
import {
  accountId,
  clientAccountId,
  StateService,
  type ClientAccount,
  type MandateBudget,
  type MandateBudgetSource,
} from "../../src/state/index.js";
import { agentToken, agentTokenCredentials } from "../support/agent-token.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:buyref-01:v3";
const TZ = "Europe/Moscow";
let mseq = 0;
let cseq = 0;
const mandate = (): string => `mnd_00000000-0000-4000-8100-${String(++mseq).padStart(12, "0")}`;
/** Свой клиент на каждый тест: счета клиента не пересекаются между тестами одной схемы. */
const client = () => ({ participant_code: "bank:pg", principal_ref: `prn_pg_${++cseq}` });

/** Журнал согласий: мандаты одного клиента; свёртка журнала — в consent-client.test.ts, здесь — неделимость на PG. */
class Mandates implements AdpMandates, MandateBudgetSource {
  readonly map = new Map<string, AdpMandate>();
  readonly roots = new Map<string, string>();
  /** CART под своим корнем INTENT (РП49 (б): агентский токен — только по CART); предел корня больше предела CART. */
  add(limit: number, c: { participant_code: string; principal_ref: string }): string {
    const root = mandate();
    const id = mandate();
    this.map.set(root, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: 1_000 * limit, client: c });
    this.map.set(id, { status: "ACTIVE", type: "CART", parent_id: root, merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: limit, client: c });
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

const auth = (mandate_id: string, op_ref: string, amount: number): CanonicalMessage =>
  agentToken({
    op_ref,
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5411" },
    instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
    aoi: { indicator: true, agent_code: AGENT, mandate_id },
  });

describe.skipIf(!DATABASE_URL)("лимит клиента на PostgreSQL: два экземпляра (РП45 п. 1, инвариант 4)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  let ledger: PgHoldLedger;
  const mandates = new Mandates();
  /** Записи лимитов по principal_ref: хранилище записей проверено в participants-limits.test.ts. */
  const limits = new Map<string, unknown>();

  const instance = (pool: pg.Pool): Adp =>
    new Adp({
      agents: { get: async (c) =>(c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
      mandates,
      state: new StateService(new PgHoldLedger(pool), mandates, { reservationTtlSec: 600 }),
      credentials: agentTokenCredentials,
      operations: new PgOperationStore(pool, { lockTimeoutMs: 5_000 }),
      // Проверяется одно правило — лимит клиента: порог и правило доли вне залпа.
      params: { aoi_rollout_phase: 3, confirm_above_kop: 10_000_000, split_window_sec: 600, split_min_ops: 41, client_limit_period_tz: TZ },
      clientLimits: { get: async (c) => (limits.has(c.principal_ref) ? [{ limits: limits.get(c.principal_ref), received_at: "2026-09-01T00:00:00Z" }] : []) },
    });

  beforeAll(async () => {
    db = await openTestDb("client_limit");
    pool2 = db.reopen();
    ledger = new PgHoldLedger(db.pool);
  });
  afterAll(async () => {
    await db?.close();
  });

  it("контрольная точка: 20 по 1 000 ₽ с двух экземпляров по двум мандатам одного клиента при per_period 3 000 ₽ — ровно 3 APPROVE", async () => {
    const c = client();
    limits.set(c.principal_ref, { per_period: 300_000, period: "DAY", currency: "RUB" });
    // У каждого мандата места на 3 — без лимита клиента одобрено было бы 6.
    const [m1, m2] = [mandates.add(300_000, c), mandates.add(300_000, c)];
    const [a1, a2] = [instance(db.pool), instance(pool2)];
    const ds = await Promise.all(
      Array.from({ length: 20 }, (_, i) => (i % 2 ? a1 : a2).decide(auth(i % 4 < 2 ? m1 : m2, `OPKC-CL-PG-${cseq}-${i}`, 100_000))),
    );
    const pairs = ds.map((d) => parseDecision(d, "adp"));
    const approved = pairs.filter((p) => p.decision === "APPROVE").length;
    expect(approved, `лимит клиента превышен: одобрено ${approved} при per_period на 3 (инвариант 4)`).toBe(3);
    expect(pairs.filter((p) => p.reason === "LIMIT_EXCEEDED")).toHaveLength(17);
    const acc: Omit<ClientAccount, "limit"> = { ...c, period: "DAY", period_start: periodStart("DAY", TZ, new Date()) };
    const a = await ledger.account(clientAccountId(acc));
    expect(a.reserved + a.committed, "перерасход лимита клиента: закреплено + зарезервировано > per_period").toBeLessThanOrEqual(a.limit);
    expect(a.reserved).toBe(300_000);
    // Отказ по клиенту освобождает резерв мандата: на счетах мандатов держится ровно одобренное.
    const held = (await ledger.account(accountId(m1))).reserved + (await ledger.account(accountId(m2))).reserved;
    expect(held, "резерв мандата не освобождён после отказа лимита клиента").toBe(300_000);
    // У CART — и счёт корня (РП43 п. 6): держится ровно одобренное.
    const heldRoots = (await ledger.account(accountId(mandates.root(m1)))).reserved + (await ledger.account(accountId(mandates.root(m2)))).reserved;
    expect(heldRoots, "резерв корня не освобождён после отказа лимита клиента").toBe(300_000);
  });

  it("StateService на двух пулах: 20 одновременных reserveClient по 1 000 ₽ при 3 000 ₽ — ровно 3", async () => {
    const c = client();
    const acc: ClientAccount = { ...c, period: "DAY", period_start: "2026-10-19", limit: { amount: 300_000, currency: "RUB" } };
    const s1 = new StateService(new PgHoldLedger(db.pool), mandates, { reservationTtlSec: 600 });
    const s2 = new StateService(new PgHoldLedger(pool2), mandates, { reservationTtlSec: 600 });
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? s1 : s2).reserveClient(acc, { amount: 100_000, currency: "RUB" }, `op-${i}`)));
    expect(rs.filter((r) => r.ok), "лимит клиента превышен на двух экземплярах (инвариант 4)").toHaveLength(3);
    expect(rs.filter((r) => !r.ok && r.code === "LIMIT_EXCEEDED")).toHaveLength(17);
    // Повтор того же op_key с другого экземпляра — то же удержание, не второй резерв.
    const first = rs.findIndex((r) => r.ok);
    const again = await (first % 2 ? s2 : s1).reserveClient(acc, { amount: 100_000, currency: "RUB" }, `op-${first}`);
    const prior = rs[first];
    expect(again.ok && prior?.ok && again.hold.id === prior.hold.id).toBe(true);
    expect((await ledger.account(clientAccountId(acc))).reserved).toBe(300_000);
  });

  it("сужение в периоде на двух пулах (РП46 (г)): 20 одновременных reserveClient по новой записи — одобрений не выше нового предела", async () => {
    const c = client();
    const at = (amount: number): ClientAccount => ({ ...c, period: "DAY", period_start: "2026-10-19", limit: { amount, currency: "RUB" } });
    const s1 = new StateService(new PgHoldLedger(db.pool), mandates, { reservationTtlSec: 600 });
    const s2 = new StateService(new PgHoldLedger(pool2), mandates, { reservationTtlSec: 600 });
    expect((await s1.reserveClient(at(300_000), { amount: 50_000, currency: "RUB" }, "nar-0")).ok).toBe(true);
    // Банк сузил до 1 000 ₽: удержано 500 ₽ — место ровно на 5 по 100 ₽, с обоих экземпляров одновременно.
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? s1 : s2).reserveClient(at(100_000), { amount: 10_000, currency: "RUB" }, `nar-${i + 1}`)));
    const ok = rs.filter((r) => r.ok).length;
    expect(ok, `сужение не применено на двух экземплярах: одобрено ${ok} при месте на 5 (инвариант 4)`).toBe(5);
    expect(rs.filter((r) => !r.ok && r.code !== "LIMIT_EXCEEDED"), "гонка setLimit с резервом дала не LIMIT_EXCEEDED").toEqual([]);
    expect(await ledger.account(clientAccountId(at(100_000)))).toMatchObject({ limit: 100_000, reserved: 100_000 });
  });
});
