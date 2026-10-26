// П9 Лента событий агенту (PS-08 К1.2; РП39): событие пишется с записью журнала согласий в одной транзакции
// (Outbox), номер у агента — под блокировкой агента до фиксации; GET /pao/v1/events?after= — только свои, по номеру.
// Журнал — на памяти ядра (всегда) и на PostgreSQL (в CI, РП30 п. 7); ПАО — через стенд.
import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newConfirmationId, newConfirmationRef, PgConfirmationStore, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import type { MandateDecisionPayload, MandateRevocationPayload } from "../../src/consent/model.js";
import { MemoryConsentStore, PgConsentStore, type ConsentStore, type PgConsentStoreHooks } from "../../src/consent/store.js";
import { EventCursorUnknown, eventIdFor, EVENT_ID, eventSeqLockKey, type EventDraft } from "../../src/pao/events.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { Event, MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";

const A = "nspk:agent:events-a:v1";
const T0 = new Date("2026-10-18T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30 };
const SUBJECT = "молоко 2 л, тайный предмет";
const key = (): string => createHash("sha256").update(randomUUID()).digest("hex");
const yes = (): boolean => true;

const intent = (over: Partial<MandateRequest> = {}): MandateRequest => ({
  type: "INTENT",
  subject: SUBJECT,
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});

const decision = (id: string, hash: string, d: "SIGN" | "REJECT" = "SIGN"): MandateDecisionPayload => ({
  participant_code: "BANK-TEST",
  kid: "kid-bank",
  mandate_id: id,
  mandate_hash: hash,
  decision: d,
  signature_type: "simple",
  signature_ref: `sig-${id.slice(-6)}`,
  token_consent: true,
  signed_at: T0.toISOString(),
  signature: "sig",
});

const revocation = (id: string, hash: string): MandateRevocationPayload => ({
  participant_code: "BANK-TEST",
  kid: "kid-bank",
  mandate_id: id,
  mandate_hash: hash,
  revocation_ref: `rev-${id.slice(-6)}`,
  revoked_at: T0.toISOString(),
  signature: "sig",
});

const journalOf = (store: ConsentStore): ConsentJournal =>
  new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });

/**
 * principal_ref — свой у каждого мандата по умолчанию: подписи одной пары клиента идут под локом пары (РП46 (а)) раньше
 * блокировки агента, а здесь проверяется именно блокировка агента.
 */
async function mk(j: ConsentJournal, agent = A, principal_ref = opaquePrincipalRef()): Promise<{ id: string; hash: string }> {
  const m = await j.request(agent, key(), intent({ principal_ref }));
  return { id: m.id!, hash: m.hash! };
}

/** Все события агента: страницами по 2, чтобы курсор проверялся на каждом шаге. */
async function allEvents(j: ConsentJournal, agent: string): Promise<Event[]> {
  const out: Event[] = [];
  for (;;) {
    const page = await j.events(agent, out.at(-1)?.event_id, 2);
    out.push(...page);
    if (page.length < 2) return out;
  }
}

/** Записи журнала с событием — по мандату: [event_id по записи, тип события]. */
async function expectedEvents(store: ConsentStore, id: string): Promise<[string, string][]> {
  const type: Record<string, string> = {
    MANDATE_SIGNED: "mandate.signed",
    MANDATE_REJECTED: "mandate.rejected",
    MANDATE_REVOKED: "mandate.revoked",
    MANDATE_RELINQUISHED: "mandate.revoked",
  };
  const row = (await store.getMandate(id))!;
  return (await store.journal(row.chain).all())
    .filter((e) => e.ref === id && type[e.kind])
    .map((e) => [eventIdFor(row.chain, e.seq), type[e.kind]!]);
}

function suite(open: () => Promise<ConsentStore>): void {
  let store: ConsentStore;
  let j: ConsentJournal;
  beforeAll(async () => {
    store = await open();
    j = journalOf(store);
  });

  it("решение, отзыв, отказ агента — по событию на запись; у запроса события нет; data — только mandate_id (A7 п. 8.3)", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const signed = await mk(j, agent);
    const rejected = await mk(j, agent);
    const revoked = await mk(j, agent);
    const left = await mk(j, agent);
    expect(await allEvents(j, agent)).toEqual([]);
    await j.sign(decision(signed.id, signed.hash), yes, POLICY);
    await j.sign(decision(rejected.id, rejected.hash, "REJECT"), yes, POLICY);
    await j.sign(decision(revoked.id, revoked.hash), yes, POLICY);
    await j.revoke(revocation(revoked.id, revoked.hash), yes);
    await j.relinquish(left.id, agent, "kid-a");
    const got = await allEvents(j, agent);
    expect(got.map((e) => [e.type, e.data])).toEqual([
      ["mandate.signed", { mandate_id: signed.id }],
      ["mandate.rejected", { mandate_id: rejected.id }],
      ["mandate.signed", { mandate_id: revoked.id }],
      ["mandate.revoked", { mandate_id: revoked.id }],
      ["mandate.revoked", { mandate_id: left.id }],
    ]);
    for (const e of got) {
      expect(e.event_id).toMatch(EVENT_ID);
      expect(e.at).toBe(T0.toISOString());
      expect(Object.keys(e).sort()).toEqual(["at", "data", "event_id", "type"]);
    }
    // Предмета, суммы, ссылок банка в событиях нет.
    const text = JSON.stringify(got);
    for (const secret of [SUBJECT, "sig-", "rev-", "prn_"]) expect(text).not.toContain(secret);
    for (const e of got) expect(Object.keys(e.data)).toEqual(["mandate_id"]);
    // Событие ↔ запись: event_id вычисляется от записи журнала, у каждой записи с событием — ровно одно.
    const expected = (await Promise.all([signed, rejected, revoked, left].map((m) => expectedEvents(store, m.id)))).flat();
    expect(got.map((e) => [e.event_id, e.type]).sort()).toEqual(expected.sort());
  });

  it("повтор той же подписи и отзыв уже отозванного — записи нет, события нет", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const m = await mk(j, agent);
    const d = decision(m.id, m.hash);
    await j.sign(d, yes, POLICY);
    expect((await j.sign(d, yes, POLICY)).replayed).toBe(true);
    await j.revoke(revocation(m.id, m.hash), yes);
    expect((await j.revoke(revocation(m.id, m.hash), yes)).replayed).toBe(true);
    expect((await allEvents(j, agent)).map((e) => e.type)).toEqual(["mandate.signed", "mandate.revoked"]);
  });

  it("курсор: повтор чтения — те же event_id; after — следующие; чужой и неизвестный after — EventCursorUnknown", async () => {
    const a = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const b = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    for (const agent of [a, a, a, b]) {
      const m = await mk(j, agent);
      await j.sign(decision(m.id, m.hash), yes, POLICY);
    }
    const first = await j.events(a, undefined, 10);
    expect(first).toHaveLength(3);
    expect(await j.events(a, undefined, 10)).toEqual(first);
    expect(await j.events(a, first[0]!.event_id, 10)).toEqual(first.slice(1));
    expect(await j.events(a, first[0]!.event_id, 1)).toEqual(first.slice(1, 2));
    expect(await j.events(a, first[2]!.event_id, 10)).toEqual([]);
    const theirs = await j.events(b, undefined, 10);
    expect(theirs).toHaveLength(1);
    await expect(j.events(a, theirs[0]!.event_id, 10)).rejects.toBeInstanceOf(EventCursorUnknown);
    await expect(j.events(a, "evt_00000000-0000-8000-8000-000000000000", 10)).rejects.toBeInstanceOf(EventCursorUnknown);
  });

  it("10 одновременных решений по разным мандатам одного агента — 10 событий, порядок без пропусков и повторов", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const ms = await Promise.all(Array.from({ length: 10 }, () => mk(j, agent)));
    await Promise.all(ms.map((m) => j.sign(decision(m.id, m.hash), yes, POLICY)));
    const got = await allEvents(j, agent);
    expect(got.map((e) => e.data.mandate_id).sort()).toEqual(ms.map((m) => m.id).sort());
    expect(new Set(got.map((e) => e.event_id)).size).toBe(10);
  });
}

describe("лента событий — память", () => {
  suite(async () => new MemoryConsentStore());
});

describe.skipIf(!DATABASE_URL)("лента событий — PostgreSQL", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("events");
  });
  afterAll(async () => {
    await db?.close();
  });

  suite(async () => new PgConsentStore(db.pool));

  /**
   * Ждать, пока в базе появится сессия, ожидающая advisory-блокировку агента; нет за 3 с — отказ теста своим
   * сообщением. Предел меньше таймаута теста vitest (5 с), иначе поломка видна только как таймаут (К1.2а, CI 39134465644).
   */
  const waitAdvisoryWaiter = async (lockKey: string): Promise<void> => {
    const k = BigInt.asUintN(64, BigInt(lockKey));
    const [classid, objid] = [String(k >> 32n), String(k & 0xffffffffn)];
    for (const t0 = Date.now(); Date.now() - t0 < 3_000; await new Promise((r) => setTimeout(r, 20))) {
      const r = await db.pool.query(
        "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND classid::text = $1 AND objid::text = $2",
        [classid, objid],
      );
      if (r.rows.length > 0) return;
    }
    throw new Error("никто не ждёт блокировку агента: номер события выдан без блокировки");
  };

  const seqs = async (agent: string): Promise<[string, number][]> =>
    (
      await db.pool.query<{ mandate_id: string; seq: string }>(
        "SELECT data::json->>'mandate_id' AS mandate_id, seq FROM pao_events WHERE agent_code = $1 ORDER BY seq",
        [agent],
      )
    ).rows.map((r) => [r.mandate_id, Number(r.seq)]);

  it("сбой вставки события — откат: записи журнала нет, мандат PENDING_SIGNATURE, события нет (РП39 п. 1)", async () => {
    const hooks: PgConsentStoreHooks = {
      inTx: async (step) => {
        if (step === "event") throw new Error("сбой перед вставкой события");
      },
    };
    const j = journalOf(new PgConsentStore(db.pool, hooks));
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const m = await mk(j, agent);
    await expect(j.sign(decision(m.id, m.hash), yes, POLICY)).rejects.toThrow(/сбой перед вставкой события/);
    expect((await j.get(m.id, agent))?.status).toBe("PENDING_SIGNATURE");
    expect(await expectedEvents(new PgConsentStore(db.pool), m.id)).toEqual([]);
    expect(await j.events(agent, undefined, 10)).toEqual([]);
  });

  it("сбой перед COMMIT — откат обеих вставок", async () => {
    const hooks: PgConsentStoreHooks = {
      inTx: async (step) => {
        if (step === "commit") throw new Error("сбой перед фиксацией");
      },
    };
    const j = journalOf(new PgConsentStore(db.pool, hooks));
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const m = await mk(j, agent);
    await expect(j.revoke(revocation(m.id, m.hash), yes)).rejects.toThrow(/сбой перед фиксацией/);
    expect((await j.get(m.id, agent))?.status).toBe("PENDING_SIGNATURE");
    expect(await seqs(agent)).toEqual([]);
  });

  it("событие без записи журнала — отказ внешнего ключа; UPDATE, DELETE, TRUNCATE ленты — отказ (только вставка)", async () => {
    await expect(
      db.pool.query(
        `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, journal_chain, journal_seq)
         VALUES ($1, 1, $2, 'mandate.signed', $3, '{}', 'consent:mnd_нет', 1)`,
        [`nspk:agent:orphan:v1`, eventIdFor("consent:mnd_нет", 1), T0.toISOString()],
      ),
    ).rejects.toMatchObject({ code: "23503" }); // foreign_key_violation
    const j = journalOf(new PgConsentStore(db.pool));
    const m = await mk(j);
    await j.sign(decision(m.id, m.hash), yes, POLICY);
    await expect(db.pool.query("UPDATE pao_events SET type = type")).rejects.toThrow(/только добавление/);
    await expect(db.pool.query("DELETE FROM pao_events")).rejects.toThrow(/только добавление/);
    // CASCADE: без него отказывает внешний ключ pao_event_deliveries (sql/102) раньше триггера.
    await expect(db.pool.query("TRUNCATE pao_events CASCADE")).rejects.toThrow(/только добавление/);
  });

  it("барьер: номер выдан раньше, фиксация позже — второй ждёт блокировку агента, номера = порядку фиксации (РП39 п. 2)", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const plain = journalOf(new PgConsentStore(db.pool));
    const first = await mk(plain, agent);
    const second = await mk(plain, agent);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let firstHolding!: () => void;
    const holding = new Promise<void>((r) => (firstHolding = r));
    const steps: string[] = [];
    const hooks: PgConsentStoreHooks = {
      inTx: async (step, draft: EventDraft) => {
        const who = "mandate_id" in draft.data && draft.data.mandate_id === first.id ? "first" : "second";
        if (step === "journal") return; // запись журнала — до блокировки, порядок номеров её не касается
        steps.push(`${who}:${step}`);
        if (who === "first" && step === "commit") {
          firstHolding();
          await gate; // номер выдан и вставлен, транзакция не зафиксирована
        }
      },
    };
    const j = journalOf(new PgConsentStore(db.pool, hooks));
    const a = j.sign(decision(first.id, first.hash), yes, POLICY);
    await holding;
    const b = j.sign(decision(second.id, second.hash), yes, POLICY);
    // Пока первая транзакция держит номер, вторая стоит именно на блокировке агента (ожидание advisory в базе) и до
    // события не доходит, а лента не видит ни одного события: курсор не проскочит незафиксированный номер.
    // Без блокировки ожидания advisory не будет — тест красный здесь (`/audit` К1.2 № 2: не по таймеру).
    try {
      await waitAdvisoryWaiter(eventSeqLockKey(agent));
      expect(steps).toEqual(["first:event", "first:commit"]);
      expect(await plain.events(agent, undefined, 10)).toEqual([]);
    } finally {
      // Иначе упавшая проверка оставит обе транзакции висеть и займёт соединения пула для следующих тестов.
      release();
      await Promise.allSettled([a, b]);
    }
    await Promise.all([a, b]);
    expect(steps).toEqual(["first:event", "first:commit", "second:event", "second:commit"]);
    expect(await seqs(agent)).toEqual([
      [first.id, 1],
      [second.id, 2],
    ]);
  });

  it("барьер двух источников (РП51 п. 3): событие мандата держит номер, решение подтверждения того же агента ждёт блокировку агента; номера 1…3 без пропусков и дублей, курсор проходит оба источника", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const plain = journalOf(new PgConsentStore(db.pool));
    const m = await mk(plain, agent);
    const cnf = new PgConfirmationStore(db.pool, { lockTimeoutMs: 5_000 });
    const rec: ConfirmationRecord = {
      confirmation_id: newConfirmationId(),
      agent_code: agent,
      mandate_id: m.id,
      merchant_id: "MER-1042",
      amount: 340_000,
      currency: "RUB",
      order_ref: `ORD-${randomUUID().slice(0, 8)}`,
      split_detected: false,
      status: "PENDING",
      created_at: T0.toISOString(),
      expires_at: "2099-01-01T00:00:00.000Z",
      confirmation_ref: null,
      decision: null,
      op_ref: null,
    };
    await cnf.create(rec); // confirmation.required — номер 1
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let holding!: () => void;
    const held = new Promise<void>((r) => (holding = r));
    const hooks: PgConsentStoreHooks = {
      inTx: async (step) => {
        if (step !== "commit") return;
        holding();
        await gate; // mandate.signed вставлен с номером 2, транзакция не зафиксирована
      },
    };
    const a = journalOf(new PgConsentStore(db.pool, hooks)).sign(decision(m.id, m.hash), yes, POLICY);
    await held;
    const d = { participant_code: "BANK-TEST", kid: "kid-bank", decision: "APPROVE" as const, totals_hash: totalsHash(rec), decided_at: T0.toISOString(), signature: "s".repeat(86) };
    const b = cnf.decide(rec.confirmation_id, d, newConfirmationRef(), T0.toISOString());
    try {
      // Без блокировки агента в транзакции решения ожидания advisory не будет — тест красный здесь.
      await waitAdvisoryWaiter(eventSeqLockKey(agent));
      expect((await plain.events(agent, undefined, 10)).map((e) => e.type)).toEqual(["confirmation.required"]);
    } finally {
      release();
      await Promise.allSettled([a, b]);
    }
    await Promise.all([a, b]);
    const r = await db.pool.query<{ seq: string; type: string }>("SELECT seq, type FROM pao_events WHERE agent_code = $1 ORDER BY seq", [agent]);
    expect(r.rows.map((x) => [Number(x.seq), x.type])).toEqual([
      [1, "confirmation.required"],
      [2, "mandate.signed"],
      [3, "confirmation.approved"],
    ]);
    const all = await allEvents(plain, agent);
    expect(all.map((e) => e.type)).toEqual(["confirmation.required", "mandate.signed", "confirmation.approved"]);
  });

  it("10 одновременных решений — номера в базе ровно 1…10 по агенту", async () => {
    const j = journalOf(new PgConsentStore(db.pool));
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const ms = await Promise.all(Array.from({ length: 10 }, () => mk(j, agent)));
    await Promise.all(ms.map((m) => j.sign(decision(m.id, m.hash), yes, POLICY)));
    expect((await seqs(agent)).map(([, n]) => n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("гонка конца цепочки на двух экземплярах: проигравшая попытка — откат и повтор новой транзакцией; событие на каждую запись, соединения вернулись (дополнение РП39 п. 1)", async () => {
    const agent = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const m = await mk(journalOf(new PgConsentStore(db.pool)), agent);
    // Обе первые попытки встают перед записью журнала вместе: обе прочли один конец цепочки, одна проиграет 23505.
    let arrived = 0;
    let open!: () => void;
    const both = new Promise<void>((r) => (open = r));
    const fuse = setTimeout(() => open(), 3_000);
    const hooks: PgConsentStoreHooks = {
      inTx: async (step) => {
        if (step !== "journal") return;
        if (++arrived <= 2) {
          if (arrived === 2) open();
          await both;
        }
      },
    };
    // Два экземпляра Платформы: у каждого свой лок записи в процессе, общая база.
    const one = journalOf(new PgConsentStore(db.pool, hooks));
    const two = journalOf(new PgConsentStore(db.pool, hooks));
    await Promise.all([one.sign(decision(m.id, m.hash), yes, POLICY), two.revoke(revocation(m.id, m.hash), yes)]);
    clearTimeout(fuse);
    expect(arrived).toBe(3); // две первые попытки и повтор проигравшей
    const expected = await expectedEvents(new PgConsentStore(db.pool), m.id);
    expect(expected).toHaveLength(2);
    expect((await one.events(agent, undefined, 10)).map((e) => [e.event_id, e.type]).sort()).toEqual(expected.sort());
    expect((await seqs(agent)).map(([, n]) => n)).toEqual([1, 2]);
    expect(db.pool.idleCount).toBe(db.pool.totalCount);
    expect(db.pool.waitingCount).toBe(0);
  });

  it("блокировка — на агента: другой агент пишет, пока первый держит транзакцию", async () => {
    const a = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const b = `nspk:agent:events-${randomUUID().slice(0, 8)}:v1`;
    const plain = journalOf(new PgConsentStore(db.pool));
    const ma = await mk(plain, a);
    const mb = await mk(plain, b);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let holdingA!: () => void;
    const holding = new Promise<void>((r) => (holdingA = r));
    const hooks: PgConsentStoreHooks = {
      inTx: async (step, draft) => {
        if (draft.agent_code === a && step === "commit") {
          holdingA();
          await gate;
        }
      },
    };
    const j = journalOf(new PgConsentStore(db.pool, hooks));
    const pa = j.sign(decision(ma.id, ma.hash), yes, POLICY);
    await holding;
    await j.sign(decision(mb.id, mb.hash), yes, POLICY);
    expect(await seqs(b)).toEqual([[mb.id, 1]]);
    release();
    await pa;
    expect(await seqs(a)).toEqual([[ma.id, 1]]);
  });
});

describe("GET /pao/v1/events на стенде (ПАО §5, РП39 п. 7)", () => {
  const code = "nspk:agent:events-http:v1";
  const otherCode = "nspk:agent:events-http-b:v1";
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  const valid_to = new Date(Date.now() + 7 * 86_400_000).toISOString();

  beforeAll(async () => {
    stand = createStand();
    side = newAgentSide();
    other = newAgentSide();
    expect((await stand.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
    expect((await stand.admit(buyerApplication(otherCode, other), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const create = async (as = side, asCode = code): Promise<string> => {
    const res = await signedInject(stand.app, as, asCode, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(intent({ valid_to })),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(res.statusCode).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const events = (query = "", as = side, asCode = code) =>
    signedInject(stand.app, as, asCode, { method: "GET", path: "/pao/v1/events", query });

  it("issuer.sign и issuer.revoke → mandate.signed, mandate.revoked; повтор чтения — те же event_id; after — дальше", async () => {
    const id = await create();
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    expect((await stand.issuer.revoke(id)).statusCode).toBe(200);
    const res = await events();
    expect(res.statusCode).toBe(200);
    const got = res.json() as Event[];
    expect(got.map((e) => [e.type, e.data])).toEqual([
      ["mandate.signed", { mandate_id: id }],
      ["mandate.revoked", { mandate_id: id }],
    ]);
    expect(res.body).not.toContain(SUBJECT);
    expect((await events()).json()).toEqual(got);
    expect((await events(`after=${got[0]!.event_id}`)).json()).toEqual(got.slice(1));
    expect((await events(`after=${got[1]!.event_id}`)).json()).toEqual([]);
    // Событие — сигнал: статус — по GET мандата (РП39 п. 6).
    const m = await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${id}` });
    expect((m.json() as { status: string }).status).toBe("REVOKED");
  });

  it("чужие события не видны; чужой, неизвестный, не по форме, пустой, повторённый after — 400 REQUEST_INVALID", async () => {
    const id = await create(other, otherCode);
    await stand.issuer.sign(id);
    const theirs = (await events("", other, otherCode)).json() as Event[];
    expect(theirs.map((e) => e.data)).toEqual([{ mandate_id: id }]);
    expect(((await events()).json() as Event[]).some((e) => e.data.mandate_id === id)).toBe(false);
    for (const q of [
      `after=${theirs[0]!.event_id}`,
      "after=evt_00000000-0000-8000-8000-000000000000",
      "after=xyz",
      "after=",
      `after=${theirs[0]!.event_id}&after=${theirs[0]!.event_id}`,
    ]) {
      const res = await events(q);
      expect(res.statusCode, q).toBe(400);
      expect(res.json()).toMatchObject({ code: "REQUEST_INVALID" });
    }
  });
});
