// П9 Push-доставка событий с повтором (PS-08 К1.3в–К1.3г; РП40 п. 4–8): ПС23 без подписи (до ПАО 1.5.0), задержка
// nextAttemptDelayMs ядра, исчерпание event_retry_max — событие остаётся в ленте, подмена DNS после подписки,
// SUSPENDED/EXCLUDED — push не выполняется и попытки не тратятся. Стенд — память; PostgreSQL — в CI (РП30 п. 7).
import { createHash, randomUUID } from "node:crypto";
import { createServer, type Socket } from "node:net";
import { nextAttemptDelayMs } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { createAgentReceiver } from "../../src/env/agent/index.js";
import { EventDeliverer, httpsTransport, pinnedLookup } from "../../src/pao/delivery.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { createStandDns, STAND_AGENT_EMULATOR_HOST } from "../../src/stand/dns.js";
import { loadParams } from "../../src/shared/config.js";
import type { Event, MandateRequest } from "../../src/shared/pao.js";
import type { MandateDecisionPayload } from "../../src/consent/model.js";
import type { AgentRecord } from "../../src/registry/model.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = new Date("2026-10-18T10:00:00Z");
const URL_OK = `https://${STAND_AGENT_EMULATOR_HOST}/pao/events`;
const params = loadParams();
const keyHash = (): string => createHash("sha256").update(randomUUID()).digest("hex");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30 };

const intent = (valid_to: string): MandateRequest => ({
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to,
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
});

describe("push-доставка на стенде (ПС23 без подписи; РП40 п. 4–8)", () => {
  let stand: Stand;
  let clock: Date;
  const tick = (ms: number) => {
    clock = new Date(clock.getTime() + ms);
    stand.setClock(clock);
  };

  beforeEach(() => {
    stand = createStand();
    clock = T0;
    stand.setClock(clock);
  });
  afterAll(async () => stand?.close());

  /** Допущенный агент со своей подпиской (или без неё). */
  async function agent(events: Event["type"][] | null = ["mandate.signed", "mandate.revoked"]) {
    const code = `nspk:agent:push-${randomUUID().slice(0, 8)}:v1`;
    const side: AgentSide = newAgentSide();
    expect(stand.admit(buyerApplication(code, side), "op").admitted).toBe(true);
    const call = (c: Parameters<typeof signedInject>[3]) => signedInject(stand.app, side, code, { now: clock, ...c });
    if (events) {
      const r = await call({
        method: "PUT",
        path: "/pao/v1/subscription",
        body: JSON.stringify({ url: URL_OK, events }),
        headers: { "idempotency-key": randomUUID() },
      });
      expect(r.statusCode).toBe(200);
    }
    const mandate = async (): Promise<string> => {
      const r = await call({
        method: "POST",
        path: "/pao/v1/mandates",
        body: JSON.stringify(intent(new Date(clock.getTime() + 7 * 86_400_000).toISOString())),
        headers: { "idempotency-key": randomUUID() },
      });
      expect(r.statusCode).toBe(201);
      return (r.json() as { id: string }).id;
    };
    const feed = () => call({ method: "GET", path: "/pao/v1/events" });
    return { code, side, call, mandate, feed };
  }

  it("ПС23: 500, 500, затем 200 — доставлено с третьей попытки, тот же event_id; повтор не дублирует обработку", async () => {
    const a = await agent();
    const id = await a.mandate();
    stand.agentReceiver.respond(500, 500);
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    const [ev] = (await a.feed()).json() as Event[];

    expect(await stand.deliverEvents()).toBe(1);
    // Повтор — не раньше задержки ядра: до неё попыток нет.
    tick(nextAttemptDelayMs(1) - 1);
    expect(await stand.deliverEvents()).toBe(0);
    tick(1);
    expect(await stand.deliverEvents()).toBe(1);
    tick(nextAttemptDelayMs(2));
    expect(await stand.deliverEvents()).toBe(1);

    const got = stand.agentReceiver.received;
    expect(got.map((d) => d.status)).toEqual([500, 500, 200]);
    expect(new Set(got.map((d) => d.event_id))).toEqual(new Set([ev!.event_id]));
    expect(got.every((d) => d.header_event_id === ev!.event_id && d.url === URL_OK)).toBe(true);
    expect(got[2]!.event).toEqual(ev);
    expect(stand.agentReceiver.handled).toEqual([ev]);
    // Доставлено — больше попыток нет.
    tick(3_600_000);
    expect(await stand.deliverEvents()).toBe(0);
  });

  it("исчерпание event_retry_max попыток — событие остаётся в ленте, дальше попыток нет", async () => {
    const a = await agent();
    const id = await a.mandate();
    stand.agentReceiver.respond(...Array<number>(params.event_retry_max).fill(503));
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    for (let n = 1; n <= params.event_retry_max; n++) {
      expect(await stand.deliverEvents(), `попытка ${n}`).toBe(1);
      tick(nextAttemptDelayMs(n));
    }
    expect(await stand.deliverEvents()).toBe(0);
    tick(3_600_000);
    expect(await stand.deliverEvents()).toBe(0);
    expect(stand.agentReceiver.received).toHaveLength(params.event_retry_max);
    expect(stand.agentReceiver.handled).toEqual([]);
    const feed = (await a.feed()).json() as Event[];
    expect(feed.map((e) => [e.type, e.data])).toEqual([["mandate.signed", { mandate_id: id }]]);
    expect(await stand.delivery(feed[0]!.event_id)).toMatchObject({
      state: "EXHAUSTED",
      attempts: params.event_retry_max,
      last_reason: "http_503",
    });
  });

  it.each([
    ["перенаправление", 302],
    ["ошибка агента", 400],
  ])("%s (%i) — неуспешная попытка, повтор", async (_name, status) => {
    const a = await agent();
    stand.agentReceiver.respond(status);
    expect((await stand.issuer.sign(await a.mandate())).statusCode).toBe(200);
    await stand.deliverEvents();
    tick(nextAttemptDelayMs(1));
    await stand.deliverEvents();
    expect(stand.agentReceiver.received.map((d) => d.status)).toEqual([status, 200]);
  });

  it("подмена DNS на внутренний адрес после подписки — соединения нет; DNS вернулся — доставлено", async () => {
    const a = await agent();
    stand.dns.set(STAND_AGENT_EMULATOR_HOST, ["10.0.0.7"]);
    expect((await stand.issuer.sign(await a.mandate())).statusCode).toBe(200);
    expect(await stand.deliverEvents()).toBe(1);
    expect(stand.agentReceiver.received).toEqual([]);
    stand.dns.reset();
    tick(nextAttemptDelayMs(1));
    expect(await stand.deliverEvents()).toBe(1);
    expect(stand.agentReceiver.received.map((d) => d.status)).toEqual([200]);
  });

  it("событие до подписки и тип вне подписки — без push, только лента", async () => {
    const a = await agent(null);
    const before = await a.mandate();
    expect((await stand.issuer.sign(before)).statusCode).toBe(200);
    const r = await a.call({
      method: "PUT",
      path: "/pao/v1/subscription",
      body: JSON.stringify({ url: URL_OK, events: ["mandate.revoked"] }),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(r.statusCode).toBe(200);
    const after = await a.mandate();
    expect((await stand.issuer.sign(after)).statusCode).toBe(200);
    expect(await stand.deliverEvents()).toBe(0);
    expect((await stand.issuer.revoke(after)).statusCode).toBe(200);
    expect(await stand.deliverEvents()).toBe(1);
    expect(stand.agentReceiver.handled.map((e) => [e.type, e.data])).toEqual([["mandate.revoked", { mandate_id: after }]]);
    expect(((await a.feed()).json() as Event[]).map((e) => e.type)).toEqual(["mandate.signed", "mandate.signed", "mandate.revoked"]);
  });

  it.each(["SUSPENDED", "EXCLUDED"] as const)(
    "%s: push не выполняется и не догоняет, лента — 403; события сохраняются (РП40 п. 6–7)",
    async (to) => {
      const a = await agent();
      const id = await a.mandate();
      expect((await stand.issuer.sign(id)).statusCode).toBe(200);
      // Строка попытки создана при ACTIVE, статус сменился до отправки — SKIPPED без попытки.
      stand.registry.changeStatus(a.code, { to, ground: "KEY_COMPROMISE" });
      expect(await stand.deliverEvents()).toBe(1);
      // Событие во время приостановки — без строки попытки.
      expect((await stand.issuer.revoke(id)).statusCode).toBe(200);
      tick(3_600_000);
      expect(await stand.deliverEvents()).toBe(0);
      expect(stand.agentReceiver.received).toEqual([]);
      const denied = await a.feed();
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
      if (to === "SUSPENDED") {
        stand.registry.changeStatus(a.code, { to: "ACTIVE" });
        const feed = (await a.feed()).json() as Event[];
        expect(feed.map((e) => e.type)).toEqual(["mandate.signed", "mandate.revoked"]);
        expect(await stand.deliverEvents()).toBe(0);
        expect(stand.agentReceiver.received).toEqual([]);
      }
    },
  );
});

describe("обработчик доставки: попытки, статус, стендовый порт (РП40 п. 5–8)", () => {
  const A = "nspk:agent:deliverer:v1";
  const active = { agent_code: A, status: "ACTIVE" } as AgentRecord;
  const sub = { url: URL_OK, events: ["mandate.signed"] as const };

  async function signed(store: ConsentStore, now: Date): Promise<string> {
    const j = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => now, pushFor: () => true });
    const m = await j.request(A, keyHash(), intent("2026-10-24T10:00:00Z"));
    const d: MandateDecisionPayload = {
      participant_code: "BANK-TEST",
      kid: "kid-bank",
      mandate_id: m.id!,
      mandate_hash: m.hash!,
      decision: "SIGN",
      signature_type: "simple",
      signature_ref: "sig-1",
      token_consent: true,
      signed_at: now.toISOString(),
      signature: "sig",
    };
    await j.sign(d, () => true, POLICY);
    const [ev] = await store.listEvents(A, undefined, 10);
    return ev!.event_id;
  }

  it("статус агента не прочитан — отправки нет, попытка не тратится (инвариант 3)", async () => {
    const store = new MemoryConsentStore();
    const eventId = await signed(store, T0);
    const receiver = createAgentReceiver();
    let t = T0.getTime();
    const logged: unknown[] = [];
    const d = new EventDeliverer({
      store,
      agent: () => {
        throw new Error("реестр недоступен");
      },
      subscription: () => sub,
      resolveHost: createStandDns().resolve,
      transport: receiver.transport,
      params,
      now: () => t,
      stand: true,
      log: (level, fields) => logged.push([level, fields]),
    });
    // Задержка растёт по номеру взятия, попытка не тратится, причина — в журнале процесса (дополнение РП40 п. 16).
    for (let claim = 1; claim <= params.event_retry_max + 2; claim++) {
      expect(await d.runOnce(), `взятие ${claim}`).toBe(1);
      expect(await store.delivery(eventId)).toMatchObject({
        state: "PENDING",
        attempts: 0,
        claims: claim,
        last_reason: "status_unavailable",
        next_at_ms: t + nextAttemptDelayMs(claim),
      });
      t += nextAttemptDelayMs(claim) - 1;
      expect(await d.runOnce()).toBe(0);
      t += 1;
    }
    expect(receiver.received).toEqual([]);
    expect(logged).toHaveLength(params.event_retry_max + 2);
    expect(logged[0]).toEqual(["warn", { agent_code: A, event_id: eventId, attempt: 1, reason: "status_unavailable" }]);
  });

  it("строку взяли снова после последней попытки (сбой до итога) — EXHAUSTED без отправки (дополнение РП40 п. 15)", async () => {
    const store = new MemoryConsentStore();
    const eventId = await signed(store, T0);
    const receiver = createAgentReceiver();
    let t = T0.getTime();
    // event_retry_max попыток засчитано, итога ни одной нет: обработчик падал после отправки.
    for (let n = 1; n <= params.event_retry_max; n++) {
      const [d] = await store.claimDue(t, t + 10_000, 1);
      expect(d).toMatchObject({ attempts: n });
      t += 10_000;
    }
    const logged: unknown[] = [];
    const d = new EventDeliverer({
      store,
      agent: () => active,
      subscription: () => sub,
      resolveHost: createStandDns().resolve,
      transport: receiver.transport,
      params,
      now: () => t,
      stand: true,
      log: (level, fields) => logged.push([level, fields]),
    });
    expect(await d.runOnce()).toBe(1);
    expect(receiver.received).toEqual([]);
    expect(await store.delivery(eventId)).toMatchObject({ state: "EXHAUSTED", last_reason: "lease_expired" });
    expect(logged).toEqual([
      ["warn", { agent_code: A, event_id: eventId, attempt: params.event_retry_max + 1, reason: "lease_expired" }],
    ]);
    t += 3_600_000;
    expect(await d.runOnce()).toBe(0);
  });

  it("попытка взята и не завершена (сбой обработчика) — повтор того же event_id после аренды", async () => {
    const store = new MemoryConsentStore();
    const eventId = await signed(store, T0);
    const t = T0.getTime();
    const [first] = await store.claimDue(t, t + 10_000, 10);
    expect(first).toMatchObject({ attempts: 1, claim: 1, event: { event_id: eventId } });
    expect(await store.claimDue(t + 9_999, t + 20_000, 10)).toEqual([]);
    const [again] = await store.claimDue(t + 10_000, t + 30_000, 10);
    expect(again).toMatchObject({ attempts: 2, claim: 2, event: { event_id: eventId } });
    // Второй взявший вернул попытку (статус не прочитан): attempts снова 1, но номер взятия — 2.
    await store.finish(eventId, 2, { state: "PENDING", next_at_ms: t + 31_000, reason: "status_unavailable", refund: true });
    expect(await store.delivery(eventId)).toMatchObject({ state: "PENDING", attempts: 1, claims: 2 });
    // Итог устаревшего взятия не перезаписывает строку, хотя attempts совпадает.
    await store.finish(eventId, 1, { state: "DELIVERED" });
    expect(await store.delivery(eventId)).toMatchObject({ state: "PENDING", attempts: 1, claims: 2 });
  });

  it("стендовый транспорт или разрешение имени без stand: true — отказ запуска (РП40 п. 8)", () => {
    const base = { store: new MemoryConsentStore(), agent: () => active, subscription: () => sub, params };
    expect(() => new EventDeliverer({ ...base, resolveHost: createStandDns().resolve, transport: httpsTransport })).toThrow(
      /стендовый порт доставки/,
    );
    expect(
      () => new EventDeliverer({ ...base, resolveHost: async () => ["8.8.8.8"], transport: createAgentReceiver().transport }),
    ).toThrow(/стендовый порт доставки/);
  });
});

describe("HTTPS-транспорт: соединение с проверенным IP (РП40 п. 4)", () => {
  it("pinnedLookup отдаёт проверенный адрес для любого имени", async () => {
    const lookup = pinnedLookup("192.0.32.10");
    const one = await new Promise<unknown[]>((ok) => lookup("other.example", {}, (...a: unknown[]) => ok(a)));
    expect(one).toEqual([null, "192.0.32.10", 4]);
    const all = await new Promise<unknown[]>((ok) => lookup("other.example", { all: true }, (...a: unknown[]) => ok(a)));
    expect(all).toEqual([null, [{ address: "192.0.32.10", family: 4 }]]);
  });

  it("имя не разрешается DNS, соединение — на проверенный IP; ответа нет — сбой не позже тайм-аута", async () => {
    const sockets: Socket[] = [];
    const server = createServer((s) => void sockets.push(s));
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    const port = (server.address() as { port: number }).port;
    const t0 = performance.now();
    await expect(
      httpsTransport({ url: `https://agent.invalid:${port}/e`, host: "agent.invalid", address: "127.0.0.1" }, "{}", {}, 300),
    ).rejects.toThrow();
    expect(performance.now() - t0).toBeLessThan(2_000);
    expect(sockets).toHaveLength(1);
    for (const s of sockets) s.destroy();
    await new Promise((ok) => server.close(ok));
  });
});

describe.skipIf(!DATABASE_URL)("попытки доставки — PostgreSQL (РП40 п. 5)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("deliveries");
  });
  afterAll(async () => {
    await db?.close();
  });

  const A = "nspk:agent:deliveries-pg:v1";
  const journal = (store: ConsentStore, push: boolean) =>
    new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0, pushFor: () => push });
  const decide = async (j: ConsentJournal): Promise<void> => {
    const m = await j.request(A, keyHash(), intent("2026-10-24T10:00:00Z"));
    await j.sign({
      participant_code: "BANK-TEST",
      kid: "kid-bank",
      mandate_id: m.id!,
      mandate_hash: m.hash!,
      decision: "SIGN",
      signature_type: "simple",
      signature_ref: `sig-${randomUUID().slice(0, 6)}`,
      token_consent: true,
      signed_at: T0.toISOString(),
      signature: "sig",
    }, () => true, POLICY);
  };

  it("строка попытки — в транзакции события: push — есть, без push — нет", async () => {
    const store = new PgConsentStore(db.pool);
    await decide(journal(store, true));
    await decide(journal(store, false));
    const evs = await store.listEvents(A, undefined, 10);
    expect(await store.delivery(evs[0]!.event_id)).toMatchObject({ state: "PENDING", attempts: 0, next_at_ms: T0.getTime() });
    expect(await store.delivery(evs[1]!.event_id)).toBeUndefined();
  });

  it("сбой транзакции события — ни события, ни строки попытки", async () => {
    const store = new PgConsentStore(db.pool, {
      inTx: async (step) => {
        if (step === "commit") throw new Error("сбой перед COMMIT");
      },
    });
    const count = async (t: string): Promise<number> => (await db.pool.query(`SELECT count(*)::int AS n FROM ${t}`)).rows[0].n as number;
    const [events, deliveries] = [await count("pao_events"), await count("pao_event_deliveries")];
    await expect(decide(journal(store, true))).rejects.toThrow();
    expect([await count("pao_events"), await count("pao_event_deliveries")]).toEqual([events, deliveries]);
  });

  it("строка, занятая другим обработчиком, пропускается без ожидания (FOR UPDATE SKIP LOCKED); итог — по номеру взятия", async () => {
    const store = new PgConsentStore(db.pool);
    for (let i = 0; i < 3; i++) await decide(journal(store, true));
    const t = T0.getTime();
    const due = (await db.pool.query<{ event_id: string }>(
      "SELECT event_id FROM pao_event_deliveries WHERE state = 'PENDING' AND next_at_ms <= $1 ORDER BY next_at_ms",
      [t],
    )).rows.map((r) => r.event_id);
    expect(due.length).toBeGreaterThanOrEqual(3);
    // Барьер: другой обработчик держит блокировку строки due[0] в открытой транзакции.
    const holder = await db.pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT 1 FROM pao_event_deliveries WHERE event_id = $1 FOR UPDATE", [due[0]]);
      const claimed = await Promise.race([
        store.claimDue(t, t + 60_000, 50),
        new Promise<never>((_, fail) => setTimeout(() => fail(new Error("claimDue ждёт занятую строку — нет SKIP LOCKED")), 3_000)),
      ]);
      const ids = claimed.map((d) => d.event.event_id);
      expect(ids).not.toContain(due[0]);
      expect(ids).toEqual(expect.arrayContaining(due.slice(1)));
    } finally {
      await holder.query("ROLLBACK");
      holder.release();
    }
    const [d0] = await store.claimDue(t, t + 60_000, 1);
    expect(d0!.event.event_id).toBe(due[0]);
    expect(d0!.event.data).toHaveProperty("mandate_id");
    await store.finish(d0!.event.event_id, d0!.claim + 1, { state: "DELIVERED" });
    expect(await store.delivery(d0!.event.event_id)).toMatchObject({ state: "PENDING" });
    await store.finish(d0!.event.event_id, d0!.claim, { state: "PENDING", next_at_ms: t + 1, reason: "status_unavailable", refund: true });
    expect(await store.delivery(d0!.event.event_id)).toMatchObject({ state: "PENDING", attempts: 0, next_at_ms: t + 1 });
    const [d1] = await store.claimDue(t + 1, t + 60_000, 1);
    await store.finish(d1!.event.event_id, d1!.claim, { state: "EXHAUSTED", reason: "http_503" });
    expect(await store.delivery(d1!.event.event_id)).toMatchObject({ state: "EXHAUSTED", attempts: 1, last_reason: "http_503" });
    await store.finish(d1!.event.event_id, d1!.claim, { state: "DELIVERED" });
    expect(await store.delivery(d1!.event.event_id)).toMatchObject({ state: "EXHAUSTED" });
  });
});
