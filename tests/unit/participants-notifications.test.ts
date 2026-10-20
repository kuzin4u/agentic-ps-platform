// П10 Уведомления клиента через банк (PS-20 ч. 3; РП46 (б), доп. п. 7, 9; A3 п. 5.3): уведомитель по сохранённым записям
// операций ADP вне пути авторизации, ключ против повторов по операции, мандату и счёту периода, номер в ленте участника под
// локом участника; нет сохранённой записи решения — нет уведомления (остаточный риск Р-111). Память и PostgreSQL.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MemoryOperationStore,
  PgOperationStore,
  type OperationNotify,
  type OperationStore,
} from "../../src/adp/operations.js";
import {
  draftsFor,
  MemoryParticipantNotificationStore,
  NotificationCursorUnknown,
  notificationIdFor,
  notifyLockKey,
  ParticipantNotifier,
  PgParticipantNotificationStore,
  type ParticipantNotificationStore,
  type PgNotificationHooks,
  type StoredNotification,
} from "../../src/participants/notifications.js";
import type { Decision } from "../../src/shared/canonical.generated.js";
import { buildServer } from "../../src/server.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const BANK = "bank:a";
const OTHER_BANK = "bank:b";
const AGENT = "nspk:agent:buyref-01:v3";
const M1 = "mnd_00000000-0000-4000-8000-000000000001";
const M2 = "mnd_00000000-0000-4000-8000-000000000002";
const ACCOUNT = "client:bank:a:prn_1:DAY:2026-10-20";
const H = "a".repeat(64);
const HORIZON = 86_400;
const NOW = Date.parse("2026-10-20T12:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

const APPROVE: Decision = { decision: "APPROVE", reason: null, reservation_id: "h1", agent_level: 1, decided_in_ms: 1 };
const DECLINE = (reason: Decision["reason"]): Decision => ({ decision: "DECLINE", reason, decided_in_ms: 1 }) as Decision;
const client = (over: Partial<OperationNotify> = {}): OperationNotify => ({
  participant_code: BANK,
  principal_ref: "prn_1",
  agent_code: AGENT,
  ...over,
});

let n = 0;
/** Уникальный op_ref на всю базу теста: схема общая для файла. */
const opRef = (): string => `OPKC-NTF-${process.pid}-${++n}`;

interface Ctx {
  readonly ops: OperationStore;
  readonly store: ParticipantNotificationStore;
}

/** Сохранённое решение ADP — как его пишет Adp.decideOnce: begin «в работе», затем finish. */
async function decided(
  ctx: Ctx,
  decision: Decision,
  opts: { notify?: OperationNotify; mandate_id?: string; at?: number; op_ref?: string } = {},
): Promise<string> {
  const op_ref = opts.op_ref ?? opRef();
  const at = iso(opts.at ?? NOW - 1_000);
  await ctx.ops.begin(op_ref, H, at);
  await ctx.ops.finish({
    op_ref,
    msg_hash: H,
    decision,
    mandate_id: opts.mandate_id ?? M1,
    holds: [],
    at,
    ...(opts.notify === undefined ? {} : { notify: opts.notify }),
  });
  return op_ref;
}

const notifier = (store: ParticipantNotificationStore, now = NOW, log?: (f: Record<string, unknown>, m: string) => void) =>
  new ParticipantNotifier(store, { horizonSec: HORIZON, now: () => now, ...(log ? { log: (_l, f, m) => log(f, m) } : {}) });

const feed = async (store: ParticipantNotificationStore, participant = BANK): Promise<StoredNotification[]> => [
  ...(await store.page(participant, undefined, 1_000)),
];
const types = async (store: ParticipantNotificationStore, participant = BANK) =>
  (await feed(store, participant)).map((x) => [x.type, x.seq]);

function suite(make: () => Promise<Ctx>): void {
  it("первое одобрение по мандату — client.mandate_first_use один раз; второе — без нового уведомления", async () => {
    const ctx = await make();
    const before = (await feed(ctx.store)).length;
    await decided(ctx, APPROVE, { notify: client(), mandate_id: M2 });
    await notifier(ctx.store).runOnce();
    await decided(ctx, APPROVE, { notify: client(), mandate_id: M2 });
    await notifier(ctx.store).runOnce();
    const mine = (await feed(ctx.store)).slice(before).filter((x) => x.data.mandate_id === M2);
    expect(mine.map((x) => x.type), "первое использование мандата повторено").toEqual(["client.mandate_first_use"]);
    expect(mine[0]?.data).toEqual({ principal_ref: "prn_1", mandate_id: M2, agent_code: AGENT });
    expect(mine[0]?.notification_id).toBe(notificationIdFor(BANK, "client.mandate_first_use", M2));
  });

  it("LIMIT_EXCEEDED — client.limit_declined одно на операцию с признаком чьего предела; прочие отказы — без уведомлений", async () => {
    const ctx = await make();
    const before = (await feed(ctx.store)).length;
    const op = await decided(ctx, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "CLIENT" }) });
    await decided(ctx, DECLINE("MANDATE_REVOKED"), { notify: client() });
    await decided(ctx, DECLINE("STATE_UNAVAILABLE"), { notify: client() });
    await notifier(ctx.store).runOnce();
    await notifier(ctx.store).runOnce();
    const mine = (await feed(ctx.store)).slice(before);
    expect(mine.map((x) => x.type)).toEqual(["client.limit_declined"]);
    expect(mine[0]?.data).toEqual({ principal_ref: "prn_1", mandate_id: M1, agent_code: AGENT, op_ref: op, reason: "CLIENT" });
  });

  it("остаток счёта клиента стал 0 — client.limit_exhausted одно на счёт периода", async () => {
    const ctx = await make();
    const account = `${ACCOUNT}:${opRef()}`;
    const before = (await feed(ctx.store)).length;
    await decided(ctx, APPROVE, { notify: client({ client_account: account, client_left_after: 0 }) });
    await decided(ctx, APPROVE, { notify: client({ client_account: account, client_left_after: 0 }) });
    await decided(ctx, APPROVE, { notify: client({ client_account: `${account}:x`, client_left_after: 5 }) });
    await notifier(ctx.store).runOnce();
    const exhausted = (await feed(ctx.store)).slice(before).filter((x) => x.type === "client.limit_exhausted");
    expect(exhausted, "исчерпание лимита клиента повторено").toHaveLength(1);
    expect(exhausted[0]?.notification_id).toBe(notificationIdFor(BANK, "client.limit_exhausted", account));
  });

  it("Р-111: нет сохранённой записи решения (запись «в работе») — нет уведомления; без клиента мандата — нет уведомления", async () => {
    const ctx = await make();
    const before = (await feed(ctx.store)).length;
    await ctx.ops.begin(opRef(), H, iso(NOW - 1_000));
    await decided(ctx, APPROVE, { mandate_id: M2 });
    const r = await notifier(ctx.store).runOnce();
    expect(r.settled).toBe(0);
    expect((await feed(ctx.store)).slice(before)).toEqual([]);
  });

  it("номер в ленте участника — 1, 2, 3 без пропусков; лента только своя; курсор чужого участника — отказ", async () => {
    const ctx = await make();
    await decided(ctx, DECLINE("LIMIT_EXCEEDED"), { notify: client({ participant_code: OTHER_BANK, limit_source: "MANDATE" }) });
    await notifier(ctx.store).runOnce();
    const all = await feed(ctx.store);
    expect(all.map((x) => x.seq)).toEqual(all.map((_, i) => i + 1));
    const other = await feed(ctx.store, OTHER_BANK);
    expect(other.map((x) => x.participant_code)).toEqual(other.map(() => OTHER_BANK));
    expect(all.some((x) => x.participant_code !== BANK)).toBe(false);
    const first = all[0]!;
    expect((await ctx.store.page(BANK, first.notification_id, 1_000)).map((x) => x.seq)).toEqual(all.slice(1).map((x) => x.seq));
    await expect(ctx.store.page(OTHER_BANK, first.notification_id, 10)).rejects.toBeInstanceOf(NotificationCursorUnknown);
    await expect(ctx.store.page(BANK, "ntf_00000000-0000-8000-8000-000000000000", 10)).rejects.toBeInstanceOf(NotificationCursorUnknown);
  });

  it("горизонт: запись старше горизонта не разбирается; старше половины — признак PARTICIPANT_NOTIFY_LAGGING", async () => {
    const ctx = await make();
    const base = NOW + 10 * HORIZON * 1000;
    const before = (await feed(ctx.store)).length;
    await decided(ctx, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "MANDATE" }), at: base - HORIZON * 1000 - 1 });
    const half = await decided(ctx, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "MANDATE" }), at: base - (HORIZON * 1000) / 2 - 1 });
    const logs: string[] = [];
    const lagging = notifier(ctx.store, base, (f) => logs.push(String(f.code)));
    expect(await lagging.lagging()).toBe(true);
    // Проход разбирает запись в горизонте — отставания больше нет; старше горизонта — не разобрана и не видна.
    const r = await lagging.runOnce();
    expect(r).toMatchObject({ lagging: false });
    const mine = (await feed(ctx.store)).slice(before);
    expect(mine.map((x) => x.data.op_ref)).toEqual([half]);
    expect(logs).toEqual([]);
  });

  it("повторный разбор той же записи (два уведомителя) — без второго уведомления (ключ против повторов)", async () => {
    const ctx = await make();
    const before = (await feed(ctx.store)).length;
    const op_ref = await decided(ctx, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "MANDATE" }) });
    const [pending] = (await ctx.store.pending(iso(NOW - HORIZON * 1000), 1_000)).filter((p) => p.op_ref === op_ref);
    expect(pending).toBeDefined();
    await ctx.store.settle(pending!, draftsFor(pending!), iso(NOW));
    await ctx.store.settle(pending!, draftsFor(pending!), iso(NOW));
    expect((await feed(ctx.store)).slice(before).map((x) => x.data.op_ref), "уведомление по операции повторено").toEqual([op_ref]);
  });
}

describe("уведомления клиента через банк — память (РП46 доп. п. 7)", () => {
  const ops = new MemoryOperationStore();
  const store = new MemoryParticipantNotificationStore(ops);
  suite(async () => ({ ops, store }));

  it("сбой записи уведомления — в журнал процесса, запись остаётся неразобранной и берётся следующим проходом", async () => {
    const o = new MemoryOperationStore();
    const s = new MemoryParticipantNotificationStore(o);
    await decided({ ops: o, store: s }, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "MANDATE" }) });
    const settle = s.settle.bind(s);
    s.settle = () => Promise.reject(new Error("ECONNRESET"));
    const logs: string[] = [];
    expect(await notifier(s, NOW, (_f, m) => logs.push(m)).runOnce()).toMatchObject({ settled: 0, failed: 1 });
    expect(logs).toEqual(["П10: уведомление по записи операции не записано"]);
    s.settle = settle;
    expect(await notifier(s).runOnce()).toMatchObject({ settled: 1, failed: 0 });
    expect(await types(s)).toEqual([["client.limit_declined", 1]]);
  });
});

describe("состояние уведомителя в /health (ревью КТ1): остановка видна мониторингу без журнала", () => {
  it("проход не выполнялся дольше половины горизонта — признак PARTICIPANT_NOTIFY_LAGGING в ответе /health; после прохода — снят", async () => {
    let now = NOW;
    const n = new ParticipantNotifier(new MemoryParticipantNotificationStore(new MemoryOperationStore()), { horizonSec: HORIZON, now: () => now });
    const app = buildServer({ env: "dev", notifier: n });
    const health = async () => (await app.inject({ method: "GET", url: "/health" })).json() as Record<string, unknown>;
    expect(await health()).toEqual({ status: "ok", env: "dev", participant_notify: { last_pass_at: null, lagging: false } });
    now += (HORIZON * 1000) / 2 + 1;
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode, "отставание уведомителя не снимает готовность").toBe(200);
    expect(res.json()).toMatchObject({ participant_notify: { last_pass_at: null, lagging: true, code: "PARTICIPANT_NOTIFY_LAGGING" } });
    await n.runOnce();
    expect(await health()).toMatchObject({ participant_notify: { last_pass_at: iso(now), lagging: false } });
    now += (HORIZON * 1000) / 2 + 1;
    expect(await health()).toMatchObject({ participant_notify: { last_pass_at: iso(now - (HORIZON * 1000) / 2 - 1), lagging: true, code: "PARTICIPANT_NOTIFY_LAGGING" } });
  });

  it("последний проход нашёл запись старше половины горизонта — признак держится до прохода без отставания", async () => {
    const ops = new MemoryOperationStore();
    const store = new MemoryParticipantNotificationStore(ops);
    let now = NOW;
    const n = new ParticipantNotifier(store, { horizonSec: HORIZON, now: () => now });
    await decided({ ops, store }, DECLINE("LIMIT_EXCEEDED"), { notify: client({ limit_source: "MANDATE" }), at: NOW - (HORIZON * 1000) / 2 - 1 });
    const slow = store.settle.bind(store);
    store.settle = () => Promise.reject(new Error("ECONNRESET"));
    await n.runOnce();
    expect(n.health()).toMatchObject({ lagging: true, code: "PARTICIPANT_NOTIFY_LAGGING" });
    store.settle = slow;
    now += 1_000;
    await n.runOnce();
    expect(n.health()).toEqual({ last_pass_at: iso(now), lagging: false });
  });
});

describe.skipIf(!DATABASE_URL)("уведомления клиента через банк — PostgreSQL, два экземпляра (РП46 доп. п. 7, 9)", () => {
  let db: TestDb;
  let ops: PgOperationStore;
  beforeAll(async () => {
    db = await openTestDb("notify");
    ops = new PgOperationStore(db.pool, { lockTimeoutMs: 150 });
  });
  afterAll(async () => {
    await db?.close();
  });

  suite(async () => ({ ops, store: new PgParticipantNotificationStore(db.pool) }));

  /** Ждать сессию, ожидающую advisory-лок участника; нет за 3 с — отказ своим сообщением (как ленты агента, РП39 доп. п. 5). */
  const waitNotifyLockWaiter = async (participant: string): Promise<void> => {
    const k = BigInt.asUintN(64, BigInt(notifyLockKey(participant)));
    const [classid, objid] = [String(k >> 32n), String(k & 0xffffffffn)];
    for (const t0 = Date.now(); Date.now() - t0 < 3_000; await new Promise((r) => setTimeout(r, 20))) {
      const r = await db.pool.query(
        "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND classid::text = $1 AND objid::text = $2",
        [classid, objid],
      );
      if (r.rows.length > 0) return;
    }
    throw new Error("второй экземпляр не ждал лок участника: номер в ленте выдан без лока прохода");
  };

  it("барьер: пока первый экземпляр держит лок участника, второй ждёт его; номера — по порядку фиксации", async () => {
    const participant = `bank:barrier-${process.pid}`;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const inside = new Promise<void>((r) => (entered = r));
    let first = true;
    const hooks: PgNotificationHooks = {
      locked: async () => {
        if (!first) return;
        first = false;
        entered();
        await held;
      },
    };
    const a = new PgParticipantNotificationStore(db.pool, { hooks });
    const b = new PgParticipantNotificationStore(db.reopen());
    const opA = await decided({ ops, store: a }, DECLINE("LIMIT_EXCEEDED"), { notify: client({ participant_code: participant, limit_source: "MANDATE" }) });
    const opB = await decided({ ops, store: b }, DECLINE("LIMIT_EXCEEDED"), { notify: client({ participant_code: participant, limit_source: "CLIENT" }) });
    const pending = await a.pending(iso(NOW - HORIZON * 1000), 1_000);
    const pA = pending.find((p) => p.op_ref === opA)!;
    const pB = pending.find((p) => p.op_ref === opB)!;
    const settledA = a.settle(pA, draftsFor(pA), iso(NOW));
    await inside;
    const settledB = b.settle(pB, draftsFor(pB), iso(NOW));
    try {
      await waitNotifyLockWaiter(participant);
    } finally {
      release();
      await Promise.allSettled([settledA, settledB]);
    }
    await settledA;
    await settledB;
    expect((await feed(a, participant)).map((x) => [x.data.op_ref, x.seq])).toEqual([
      [opA, 1],
      [opB, 2],
    ]);
  });

  it("два экземпляра разбирают одни записи одновременно — по уведомлению на событие, номера 1…n без пропусков", async () => {
    const participant = `bank:race-${process.pid}`;
    const s1 = new PgParticipantNotificationStore(db.pool);
    const s2 = new PgParticipantNotificationStore(db.reopen());
    const refs: string[] = [];
    for (let i = 0; i < 10; i++) {
      refs.push(await decided({ ops, store: s1 }, DECLINE("LIMIT_EXCEEDED"), { notify: client({ participant_code: participant, limit_source: "CLIENT" }) }));
    }
    await decided({ ops, store: s1 }, APPROVE, { notify: client({ participant_code: participant }), mandate_id: M2 });
    await decided({ ops, store: s1 }, APPROVE, { notify: client({ participant_code: participant }), mandate_id: M2 });
    const results = await Promise.allSettled([notifier(s1).runOnce(), notifier(s2).runOnce(), notifier(s1).runOnce(), notifier(s2).runOnce()]);
    expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled", "fulfilled", "fulfilled"]);
    await notifier(s1).runOnce();
    const got = await feed(s1, participant);
    const declined = got.filter((x) => x.type === "client.limit_declined").map((x) => x.data.op_ref);
    expect(declined.sort(), "уведомление по операции повторено").toEqual([...refs].sort());
    expect(got.filter((x) => x.type === "client.mandate_first_use"), "первое использование мандата повторено").toHaveLength(1);
    expect(got.map((x) => x.seq), "номера ленты участника с пропуском или повтором").toEqual(got.map((_, i) => i + 1));
  });

  it("Outbox участника и отметка разбора — только вставка (триггеры)", async () => {
    await expect(db.pool.query("UPDATE participant_notifications SET type = type")).rejects.toThrow();
    await expect(db.pool.query("DELETE FROM participant_notify_seen")).rejects.toThrow();
    await expect(db.pool.query("TRUNCATE participant_notifications CASCADE")).rejects.toThrow();
  });
});
