// События agent.suspended / agent.reinstated на PostgreSQL (PS-17, РП54 п. 2, 8; sql/116): четвёртый источник ленты без
// записи журнала, CHECK «ровно один источник»; на смену статуса — одно событие (UNIQUE (agent_code, agent_status_version),
// повтор — ON CONFLICT без второй строки и без второй попытки push); номер — общий у агента с прочими событиями; из двух
// экземпляров одну смену пишет один.
// В CI (РП30 п. 7); локально без базы — пропуск.
import { canonicalJson } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgConsentStore } from "../../src/consent/store.js";
import { agentStatusEventIdFor, operationEventIdFor, type AgentStatusEventDraft } from "../../src/pao/events.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AGENT = "nspk:agent:status-pg:v1";
const AT = "2026-10-23T10:00:00.000Z";

const draft = (type: AgentStatusEventDraft["type"], version: number, push = false): AgentStatusEventDraft => ({
  agent_code: AGENT,
  type,
  data: { agent_code: AGENT },
  version,
  push,
});

const code = async (p: Promise<unknown>): Promise<string | undefined> =>
  p.then(
    () => undefined,
    (e: unknown) => (e as { code?: string }).code,
  );

describe.skipIf(!DATABASE_URL)("события статуса агента на PostgreSQL (РП54 п. 2, 8; sql/116)", () => {
  let db: TestDb;
  let pool2: pg.Pool;
  beforeAll(async () => {
    db = await openTestDb("agent_status");
    pool2 = db.reopen();
  });
  afterAll(async () => {
    await db?.close();
  });

  it("смена — одно событие с data {agent_code}; повтор той же версии — false, без второй строки и второй попытки push", async () => {
    const store = new PgConsentStore(db.pool);
    expect(await store.appendAgentStatusEvent(draft("agent.suspended", 2, true), AT)).toBe(true);
    expect(await store.appendAgentStatusEvent(draft("agent.suspended", 2, true), AT)).toBe(false);
    const events = await store.listEvents(AGENT, undefined, 10);
    expect(events).toEqual([
      expect.objectContaining({
        type: "agent.suspended",
        event_id: agentStatusEventIdFor(AGENT, 2),
        at: AT,
        data: { agent_code: AGENT },
        journal_chain: null,
        journal_seq: null,
      }),
    ]);
    const rows = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM pao_event_deliveries WHERE agent_code = $1", [AGENT]);
    expect(Number(rows.rows[0]!.n)).toBe(1);
  });

  it("номер общий с прочими событиями агента; снятие — следующая версия", async () => {
    const store = new PgConsentStore(db.pool);
    // Событие итога операции между сменами статуса — тот же счётчик seq (РП39 п. 2).
    await db.pool.query(
      `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, op_ref)
       SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, 'operation.declined', $3, $4, 'OPKC-STATUS-1' FROM pao_events WHERE agent_code = $1`,
      [AGENT, operationEventIdFor("OPKC-STATUS-1", "operation.declined"), AT, canonicalJson({ op_ref: "OPKC-STATUS-1" })],
    );
    expect(await store.appendAgentStatusEvent(draft("agent.reinstated", 3), AT)).toBe(true);
    const events = await store.listEvents(AGENT, undefined, 10);
    expect(events.map((e) => [e.seq, e.type])).toEqual([
      [1, "agent.suspended"],
      [2, "operation.declined"],
      [3, "agent.reinstated"],
    ]);
  });

  it("одна смена с двух экземпляров одновременно — одна строка", async () => {
    const a = new PgConsentStore(db.pool);
    const b = new PgConsentStore(pool2);
    const got = await Promise.all([a.appendAgentStatusEvent(draft("agent.suspended", 4), AT), b.appendAgentStatusEvent(draft("agent.suspended", 4), AT)]);
    expect(got.filter(Boolean)).toHaveLength(1);
    const n = await db.pool.query<{ n: string }>("SELECT count(*) AS n FROM pao_events WHERE agent_code = $1 AND agent_status_version = 4", [AGENT]);
    expect(Number(n.rows[0]!.n)).toBe(1);
  });

  it("CHECK «ровно один источник»: agent.* без версии, версия у чужого типа, версия вместе с op_ref — 23514", async () => {
    const insert = (type: string, version: number | null, op_ref: string | null, id: string) =>
      db.pool.query(
        `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, op_ref, agent_status_version)
         SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, $3, $4, '{}', $5, $6 FROM pao_events WHERE agent_code = $1`,
        [AGENT, id, type, AT, op_ref, version],
      );
    expect(await code(insert("agent.suspended", null, null, agentStatusEventIdFor(AGENT, 90)))).toBe("23514");
    expect(await code(insert("operation.declined", 91, null, agentStatusEventIdFor(AGENT, 91)))).toBe("23514");
    expect(await code(insert("agent.suspended", 92, "OPKC-X", agentStatusEventIdFor(AGENT, 92)))).toBe("23514");
    expect(await code(insert("agent.key_revoked", 93, null, agentStatusEventIdFor(AGENT, 93)))).toBe("23514");
    expect(await code(insert("agent.suspended", 1, null, agentStatusEventIdFor(AGENT, 94)))).toBe("23514");
  });
});
