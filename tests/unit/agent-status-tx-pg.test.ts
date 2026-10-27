// Статус и событие agent.* одной транзакцией на PostgreSQL (РП64 п. 4–5, PS-05в ч. 2б-2; РП54 остаточные риски 2, 8):
// строка агента FOR UPDATE, смена, строка push и событие — одна фиксация; время — часы базы до миллисекунды; событие
// не вставилось — откат; повтор — без второго события; два экземпляра — события в порядке версий.
// В CI (РП30 п. 7); локально без базы — пропуск.
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgConsentStore } from "../../src/consent/store.js";
import { agentStatusEventIdFor } from "../../src/pao/events.js";
import {
  AgentNotFoundError,
  AgentRegistry,
  AgentStatusEventConflictError,
  AgentStatusService,
  PgAgentRegistryStore,
  StatusTransitionError,
  type AgentKey,
  type AgentRecord,
} from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const T = "2026-10-26T10:00:00.000Z";

const record = (id: string): AgentRecord => ({
  agent_code: `nspk:agent:${id}:v1`,
  issuer: "nspk:agent",
  id,
  version: 1,
  operator: "op-a",
  class: "BUYER",
  level: 1,
  status: "ACTIVE",
  status_ground: null,
  model: "m",
  runtime: "r",
  contour: "sandbox",
  conformance_run_ref: null,
  admitted_at: T,
  status_changed_at: T,
  suspended_at: null,
  row_version: 1,
});

const key = (agent_code: string, kid: string): AgentKey => ({
  kid,
  agent_code,
  alg: "ed25519",
  public_key: `pk-${kid}`,
  valid_from: T,
  valid_to: "2027-01-24T10:00:00.000Z",
  revoked_at: null,
  row_version: 1,
});

let n = 0;
const uid = (): string => `s${++n}x${Date.now().toString(36)}`;

/** Ворота: открываются вызовом open(); ждущий — wait(). */
const gate = () => {
  let open!: () => void;
  const p = new Promise<void>((r) => (open = r));
  return { open, wait: () => p };
};

describe.skipIf(!DATABASE_URL)("статус и событие agent.* одной транзакцией на PostgreSQL (РП64 п. 4–5)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("agentstatustx");
    pool2 = db.reopen();
  });
  afterAll(async () => db?.close());

  const admitted = async (store: PgAgentRegistryStore, events: string[] = ["agent.suspended", "agent.reinstated"]): Promise<string> => {
    const r = record(uid());
    await store.insert(r, key(r.agent_code, `k-${r.id}`));
    if (events.length > 0) expect(await store.setSubscription(r.agent_code, { url: "https://agent.example/pao/events", events: events as never })).toBe(true);
    return r.agent_code;
  };
  const eventsOf = async (agent_code: string) =>
    (
      await db.pool.query<{ seq: string; event_id: string; type: string; at: string; agent_status_version: string }>(
        "SELECT seq, event_id, type, at, agent_status_version FROM pao_events WHERE agent_code = $1 ORDER BY seq",
        [agent_code],
      )
    ).rows.map((x) => ({ seq: Number(x.seq), event_id: x.event_id, type: x.type, at: x.at, version: Number(x.agent_status_version) }));
  const pushRows = async (agent_code: string): Promise<number> =>
    (await db.pool.query("SELECT 1 FROM pao_event_deliveries WHERE agent_code = $1", [agent_code])).rows.length;

  it("приостановление и снятие: статус, событие и строка push — одной фиксацией; время — часы базы до миллисекунды; повтор — без второго события", async () => {
    const store = new PgAgentRegistryStore(db.pool);
    const code = await admitted(store);
    const before = Date.now();
    const s = await store.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    expect(s.written).toBe(true);
    expect(s.record).toMatchObject({ status: "SUSPENDED", status_ground: "KEY_COMPROMISE", row_version: 2 });
    // Часы базы, не метка записи допуска; одна метка на status_changed_at и suspended_at (РП64 п. 5).
    expect(s.record.suspended_at).toBe(s.record.status_changed_at);
    expect(Date.parse(s.record.status_changed_at)).toBeGreaterThan(Date.parse(T));
    expect(Math.abs(Date.parse(s.record.status_changed_at) - before)).toBeLessThan(60_000);
    expect(await store.get(code)).toEqual(s.record);
    expect(await eventsOf(code)).toEqual([
      { seq: 1, event_id: agentStatusEventIdFor(code, 2), type: "agent.suspended", at: s.record.status_changed_at, version: 2 },
    ]);
    // agent.suspended — push и при SUSPENDED (РП54 п. 9): статус прочитан в той же транзакции.
    expect(await pushRows(code)).toBe(1);

    const again = await store.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    expect(again).toEqual({ record: s.record, written: false });
    expect(await eventsOf(code)).toHaveLength(1);

    const r = await store.transitStatus(code, { to: "ACTIVE" });
    expect(r.written).toBe(true);
    expect(r.record).toMatchObject({ status: "ACTIVE", status_ground: null, row_version: 3, suspended_at: s.record.suspended_at });
    expect((await eventsOf(code)).map((e) => [e.type, e.version])).toEqual([
      ["agent.suspended", 2],
      ["agent.reinstated", 3],
    ]);
    expect(await pushRows(code)).toBe(2);
  });

  it("неделимость: до фиксации другой экземпляр не видит ни статуса, ни события; после — оба", async () => {
    const g = gate();
    const reached = gate();
    const store = new PgAgentRegistryStore(db.pool, {
      inStatusTx: async (step) => {
        if (step !== "updated") return;
        reached.open();
        await g.wait();
      },
    });
    const other = new PgAgentRegistryStore(pool2);
    const code = await admitted(other);
    const pending = store.transitStatus(code, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" });
    try {
      await reached.wait();
      expect((await other.get(code))?.status).toBe("ACTIVE");
      expect(await eventsOf(code)).toEqual([]);
    } finally {
      g.open();
    }
    await pending;
    expect((await other.get(code))?.status).toBe("SUSPENDED");
    expect((await eventsOf(code)).map((e) => e.type)).toEqual(["agent.suspended"]);
  });

  it("событие новой версии не вставилось — откат: статус прежний, ошибка вызывающему (РП64 п. 4)", async () => {
    const store = new PgAgentRegistryStore(db.pool);
    const code = await admitted(store, []);
    // Чужое событие на версию 2 уже стоит: вставка ON CONFLICT DO NOTHING ничего не даст.
    expect(
      await new PgConsentStore(db.pool).appendAgentStatusEvent(
        { agent_code: code, type: "agent.suspended", data: { agent_code: code }, version: 2, push: false },
        T,
      ),
    ).toBe(true);
    await expect(store.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" })).rejects.toBeInstanceOf(AgentStatusEventConflictError);
    expect(await store.get(code)).toMatchObject({ status: "ACTIVE", row_version: 1, suspended_at: null });
    expect(await eventsOf(code)).toHaveLength(1);
  });

  it("два экземпляра: приостановление держит строку, снятие ждёт и видит SUSPENDED — события в порядке версий (РП54 остаточный риск 8)", async () => {
    const g = gate();
    const reached = gate();
    const first = new PgAgentRegistryStore(db.pool, {
      inStatusTx: async (step) => {
        if (step !== "locked") return;
        reached.open();
        await g.wait();
      },
    });
    const second = new PgAgentRegistryStore(pool2);
    const code = await admitted(second);
    const suspend = first.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    await reached.wait();
    const reinstate = second.transitStatus(code, { to: "ACTIVE" });
    g.open();
    expect((await suspend).record.row_version).toBe(2);
    expect((await reinstate).record).toMatchObject({ status: "ACTIVE", row_version: 3 });
    expect((await eventsOf(code)).map((e) => [e.seq, e.type, e.version])).toEqual([
      [1, "agent.suspended", 2],
      [2, "agent.reinstated", 3],
    ]);
  });

  it("одновременное приостановление с двух экземпляров — одна смена и одно событие, второй — повтор", async () => {
    const [a, b] = [new PgAgentRegistryStore(db.pool), new PgAgentRegistryStore(pool2)];
    const code = await admitted(a);
    const out = await Promise.all([
      a.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" }),
      b.transitStatus(code, { to: "SUSPENDED", ground: "KEY_COMPROMISE" }),
    ]);
    expect(out.map((x) => x.written).sort()).toEqual([false, true]);
    expect(out.map((x) => x.record.row_version)).toEqual([2, 2]);
    expect(await eventsOf(code)).toHaveLength(1);
  });

  it("недопустимый переход и неизвестный агент — исключение, ничего не записано", async () => {
    const store = new PgAgentRegistryStore(db.pool);
    const code = await admitted(store);
    await expect(store.transitStatus(code, { to: "ACTIVE" })).rejects.toBeInstanceOf(StatusTransitionError);
    await expect(store.transitStatus(code, { to: "SUSPENDED", ground: "НЕТ_ТАКОГО" })).rejects.toBeInstanceOf(StatusTransitionError);
    await expect(store.transitStatus(`${code}-нет`, { to: "ACTIVE" })).rejects.toBeInstanceOf(AgentNotFoundError);
    expect(await store.get(code)).toMatchObject({ status: "ACTIVE", row_version: 1 });
    expect(await eventsOf(code)).toEqual([]);
  });

  it("служба приостановления с транзакцией реестра — events и pushFor не используются", async () => {
    const store = new PgAgentRegistryStore(db.pool);
    const code = await admitted(store);
    const unused = () => {
      throw new Error("не должно вызываться при tx");
    };
    const service = new AgentStatusService(new AgentRegistry(store, { keys: loadParams() }), {
      events: { appendAgentStatusEvent: unused },
      pushFor: unused,
      tx: store,
    });
    expect(await service.suspend(code, "KEY_COMPROMISE")).toMatchObject({ status: "SUSPENDED", row_version: 2 });
    expect(await service.reinstate(code)).toMatchObject({ status: "ACTIVE", row_version: 3 });
    expect((await eventsOf(code)).map((e) => e.type)).toEqual(["agent.suspended", "agent.reinstated"]);
  });
});
