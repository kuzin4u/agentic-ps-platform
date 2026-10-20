// П10 Уведомления клиента через банк из журнала согласий (PS-20 ч. 3 К3.5; РП46 (б) п. 2, доп. п. 5, 7):
// client.mandate_exhausted — в транзакции записи MANDATE_EXHAUSTED (лок агента, затем лок участника); client.revoked_all —
// после записей revoke-all, повтор revocation_ref — без второго уведомления. Порядок локов «пара → агент → участник» —
// без взаимной блокировки (PG, в CI). Память и PostgreSQL.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import {
  draftsFor,
  MemoryParticipantNotificationStore,
  notificationIdFor,
  PgParticipantNotificationStore,
  type ParticipantNotificationStore,
  type StoredNotification,
} from "../../src/participants/notifications.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { A, decide, intent, mk, setup, T0, type Ctx } from "../support/state.js";

const RUB = (amount: number) => ({ amount, currency: "RUB" });
/**
 * Случайная непрозрачная ссылка без цифр: семь цифр подряд правило ссылок отклоняет (похоже на номер карты, инвариант 1),
 * и тест на случайном UUID падал изредка (К3.5а, CI 39425809302).
 */
const opaque = (prefix: string): string => `${prefix}${randomUUID().slice(0, 8).replace(/[0-9]/g, (d) => "ghijklmnop"[Number(d)]!)}`;

async function revokeAll(c: Ctx, principal_ref: string, revocation_ref: string) {
  const r = { participant_code: c.emu.participant_code, kid: c.emu.trustedKey.kid, principal_ref, revocation_ref, revoked_at: T0.toISOString() };
  const { principal_ref: _p, ...body } = { ...r, signature: c.emu.signPrincipalRevocation(r) };
  void _p;
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/principals/${principal_ref}/revoke-all`, payload: body });
  return res.statusCode;
}

/** Мандат подписан банком и израсходован целиком: закрепление всего предела пишет MANDATE_EXHAUSTED (РП41 п. 11). */
async function exhaust(c: Ctx, principal_ref: string): Promise<string> {
  const m = await mk(c, intent({ principal_ref }));
  expect(await decide(c, m)).toBe(200);
  const r = await c.state.reserve(m.id, RUB(50_000), `op-${randomUUID()}`);
  if (!r.ok) throw new Error(r.code);
  expect((await c.state.commit(r.hold.id, RUB(50_000))).ok).toBe(true);
  return m.id;
}

const feed = async (store: ParticipantNotificationStore, participant: string): Promise<StoredNotification[]> => [
  ...(await store.page(participant, undefined, 1_000)),
];

function suite(make: () => Promise<{ store: ConsentStore; notifications: ParticipantNotificationStore }>): void {
  it("MANDATE_EXHAUSTED — client.mandate_exhausted в той же записи, одно на мандат", async () => {
    const { store, notifications } = await make();
    const c = setup({ store });
    const principal = opaque("prn_ex_");
    const id = await exhaust(c, principal);
    expect((await c.consent.get(id, A))?.status).toBe("EXHAUSTED");
    // Повтор записи исчерпания (уже EXHAUSTED) — без записи и без уведомления.
    expect(await c.consent.exhausted(id, { committed: 50_000, currency: "RUB" })).toBe(false);
    const mine = (await feed(notifications, c.emu.participant_code)).filter((n) => n.data.principal_ref === principal);
    expect(mine.map((n) => n.type), "исчерпание мандата — не одно уведомление").toEqual(["client.mandate_exhausted"]);
    expect(mine[0]?.data).toEqual({ principal_ref: principal, mandate_id: id, agent_code: A });
    expect(mine[0]?.notification_id).toBe(notificationIdFor(c.emu.participant_code, "client.mandate_exhausted", id));
  });

  it("revoke-all — client.revoked_all после записей; повтор того же revocation_ref — без второго уведомления", async () => {
    const { store, notifications } = await make();
    const c = setup({ store });
    const principal = opaque("prn_ra_");
    const m = await mk(c, intent({ principal_ref: principal }));
    expect(await decide(c, m)).toBe(200);
    const ref = opaque("rev-all-");
    expect(await revokeAll(c, principal, ref)).toBe(200);
    expect(await revokeAll(c, principal, ref)).toBe(200);
    const mine = (await feed(notifications, c.emu.participant_code)).filter((n) => n.data.principal_ref === principal);
    expect(mine.map((n) => [n.type, n.data]), "отзыв всех полномочий — не одно уведомление").toEqual([
      ["client.revoked_all", { principal_ref: principal, revocation_ref: ref }],
    ]);
  });
}

describe("уведомления клиента из журнала согласий — память (РП46 (б) п. 2)", () => {
  const notifications = new MemoryParticipantNotificationStore(new MemoryOperationStore());
  suite(async () => ({ store: new MemoryConsentStore({ notifications }), notifications }));

  it("без Outbox участника (dev без базы) журнал пишет запись, уведомления нет — ошибки нет", async () => {
    const c = setup({ store: new MemoryConsentStore() });
    const id = await exhaust(c, "prn_dev");
    expect((await c.consent.get(id, A))?.status).toBe("EXHAUSTED");
  });
});

describe.skipIf(!DATABASE_URL)("уведомления клиента из журнала согласий — PostgreSQL (РП46 (б) п. 2, доп. п. 5)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("notify_journal");
  });
  afterAll(async () => {
    await db?.close();
  });

  suite(async () => ({ store: new PgConsentStore(db.pool), notifications: new PgParticipantNotificationStore(db.pool) }));

  it("порядок локов «пара → агент → участник»: исчерпание, подписи, revoke-all и уведомитель одного клиента одновременно с двух экземпляров — без взаимной блокировки", async () => {
    const emu = createIssuerEmulator();
    const c1 = setup({ store: new PgConsentStore(db.pool), emu });
    const c2 = setup({ store: new PgConsentStore(db.reopen()), emu });
    const n1 = new PgParticipantNotificationStore(db.pool);
    const n2 = new PgParticipantNotificationStore(db.reopen());
    const principal = opaque("prn_locks_");
    // Подписанные мандаты одного клиента: исчерпание — лок агента, затем участника; подпись — лок пары, затем агента.
    const signed = await Promise.all([1, 2, 3, 4].map(async () => {
      const m = await mk(c1, intent({ principal_ref: principal }));
      expect(await decide(c1, m)).toBe(200);
      return m;
    }));
    const settle = async (n: ParticipantNotificationStore) => {
      for (const op of await n.pending("1970-01-01T00:00:00.000Z", 100)) await n.settle(op, draftsFor(op), T0.toISOString());
    };
    const work = Promise.all([
      ...signed.map(async (m, i) => {
        const c = i % 2 ? c1 : c2;
        const r = await c.state.reserve(m.id, RUB(50_000), `op-${randomUUID()}`);
        if (r.ok) await c.state.commit(r.hold.id, RUB(50_000));
      }),
      ...[1, 2].map(async () => {
        const m = await mk(c2, intent({ principal_ref: principal }));
        await decide(c2, m);
      }),
      revokeAll(c1, principal, opaque("rev-")),
      settle(n1),
      settle(n2),
    ]);
    const limit = new Promise((_, fail) => setTimeout(() => fail(new Error("взаимная блокировка: работа не завершилась за 10 с")), 10_000));
    await Promise.race([work, limit]);
    const got = await feed(n1, emu.participant_code);
    expect(got.map((n) => n.seq), "номера ленты участника с пропуском или повтором").toEqual(got.map((_, i) => i + 1));
    expect(got.filter((n) => n.type === "client.revoked_all" && n.data.principal_ref === principal)).toHaveLength(1);
  }, 15_000);
});
