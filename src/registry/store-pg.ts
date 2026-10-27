// П1 Реестр агентов на PostgreSQL (РП64 п. 1–3, PS-05в ч. 2а): тот же договор, что InMemoryAgentRegistryStore, за
// портом AgentRegistryStore. Чтение — из базы на каждом обращении, кэша нет (инвариант 8 между экземплярами). Статус и
// событие agent.* одной транзакцией, отсечка по часам базы — AgentStatusTx (РП64 п. 4–5, ч. 2б-2).
import type { SqlClient } from "@kuzin4u/agentic-core";
import { insertAgentStatusEventTx, type TxSqlPool } from "../consent/store.js";
import { pushAllowed } from "../pao/events.js";
import type { AgentKey } from "./keys.js";
import type { AgentRecord, AgentSubscription, Contour } from "./model.js";
import { AgentNotFoundError } from "./registry.js";
import { checkTransition } from "./status.js";
import { AgentCodeTakenError, KeyTakenError, type AgentRegistryStore, type StatusFields } from "./store.js";
import { AgentStatusEventConflictError, isStatusRepeat, type AgentStatusRequest, type AgentStatusTx } from "./suspension.js";

interface AgentRow extends Record<string, unknown> {
  agent_code: string;
  issuer: string;
  id: string;
  version: number;
  operator: string;
  class: AgentRecord["class"];
  level: number;
  status: AgentRecord["status"];
  status_ground: AgentRecord["status_ground"];
  model: string;
  runtime: string;
  contour: AgentRecord["contour"];
  conformance_run_ref: string | null;
  admitted_at: Date;
  status_changed_at: Date;
  suspended_at: Date | null;
  row_version: string;
}

interface KeyRow extends Record<string, unknown> {
  kid: string;
  agent_code: string;
  alg: string;
  public_key: string;
  valid_from: Date;
  valid_to: Date;
  revoked_at: Date | null;
  row_version: string;
}

const AGENT_COLUMNS = `agent_code, issuer, id, version, operator, class, level, status, status_ground, model, runtime, contour,
  conformance_run_ref, admitted_at, status_changed_at, suspended_at, row_version`;
const KEY_COLUMNS = "kid, agent_code, alg, public_key, valid_from, valid_to, revoked_at, row_version";

const iso = (d: Date): string => d.toISOString();

const toRecord = (r: AgentRow): AgentRecord =>
  Object.freeze({
    agent_code: r.agent_code,
    issuer: r.issuer,
    id: r.id,
    version: r.version,
    operator: r.operator,
    class: r.class,
    level: r.level,
    status: r.status,
    status_ground: r.status_ground,
    model: r.model,
    runtime: r.runtime,
    contour: r.contour,
    conformance_run_ref: r.conformance_run_ref,
    admitted_at: iso(r.admitted_at),
    status_changed_at: iso(r.status_changed_at),
    suspended_at: r.suspended_at && iso(r.suspended_at),
    row_version: Number(r.row_version),
  });

const toKey = (r: KeyRow): AgentKey =>
  Object.freeze({
    kid: r.kid,
    agent_code: r.agent_code,
    alg: r.alg,
    public_key: r.public_key,
    valid_from: iso(r.valid_from),
    valid_to: iso(r.valid_to),
    revoked_at: r.revoked_at && iso(r.revoked_at),
    row_version: Number(r.row_version),
  });

/** Нарушение уникальности (23505) или ссылки (23503) — с именем ограничения. */
const violated = (err: unknown, code: "23505" | "23503", constraint: string): boolean =>
  typeof err === "object" &&
  err !== null &&
  (err as { code?: unknown }).code === code &&
  (err as { constraint?: unknown }).constraint === constraint;

/**
 * Точки внутри транзакции addKey — только для тестов гонок (КТ1 ч. 2а № 3): "agent" — после FOR SHARE строки агента,
 * до проверки kid; "kid" — после проверки kid и версии агента, до блокировки ключей; "keys" — после второго чтения
 * ключей, до сокращения и вставки.
 */
export interface PgAgentRegistryStoreHooks {
  readonly inTx?: (step: "agent" | "kid" | "keys", key: AgentKey) => Promise<void>;
  /** Точки транзакции статуса (РП64 п. 4): "locked" — после FOR UPDATE строки агента; "updated" — после смены, до события. */
  readonly inStatusTx?: (step: "locked" | "updated", agent_code: string) => Promise<void>;
}

export class PgAgentRegistryStore implements AgentRegistryStore, AgentStatusTx {
  constructor(
    private readonly client: TxSqlPool,
    private readonly hooks: PgAgentRegistryStoreHooks = {},
  ) {}

  async get(agent_code: string): Promise<AgentRecord | undefined> {
    const r = await this.client.query<AgentRow>(`SELECT ${AGENT_COLUMNS} FROM agents WHERE agent_code = $1`, [agent_code]);
    return r.rows[0] && toRecord(r.rows[0]);
  }

  async agentCodes(): Promise<readonly string[]> {
    const r = await this.client.query<{ agent_code: string }>("SELECT agent_code FROM agents ORDER BY seq");
    return r.rows.map((x) => x.agent_code);
  }

  /** Каталог ключей одним запросом (КТ1 ч. 2а № 10): порядок — seq агента, затем как keysOf (created_at, kid). */
  async catalogKeys(contour: Contour): Promise<readonly AgentKey[]> {
    const r = await this.client.query<KeyRow>(
      `SELECT ${KEY_COLUMNS.split(", ").map((c) => `k.${c}`).join(", ")} FROM agent_keys k JOIN agents a ON a.agent_code = k.agent_code
        WHERE a.status = 'ACTIVE' AND a.contour = $1 ORDER BY a.seq, k.created_at, k.kid`,
      [contour],
    );
    return r.rows.map(toKey);
  }

  async ownerOf(issuer: string, id: string): Promise<string | undefined> {
    const r = await this.client.query<{ operator: string }>("SELECT operator FROM agent_ids WHERE issuer = $1 AND id = $2", [issuer, id]);
    return r.rows[0]?.operator;
  }

  /**
   * Владелец идентификатора, запись и первый ключ — одной транзакцией (РП23 п. 2): сбой любой вставки — ничего не
   * сохранено. Одновременная вставка того же «сторона : идентификатор» другим оператором ждёт фиксации первой
   * (уникальный ключ agent_ids) и видит чужого владельца — AgentCodeTakenError.
   */
  async insert(record: AgentRecord, firstKey: AgentKey): Promise<void> {
    if (firstKey.agent_code !== record.agent_code) throw new Error("Первый ключ не этого агента");
    await this.tx(async (tx) => {
      await tx.query("INSERT INTO agent_ids (issuer, id, operator) VALUES ($1, $2, $3) ON CONFLICT (issuer, id) DO NOTHING", [
        record.issuer,
        record.id,
        record.operator,
      ]);
      const owner = await tx.query<{ operator: string }>("SELECT operator FROM agent_ids WHERE issuer = $1 AND id = $2", [
        record.issuer,
        record.id,
      ]);
      if (owner.rows[0]?.operator !== record.operator) throw new AgentCodeTakenError(record.agent_code);
      try {
        await tx.query(
          `INSERT INTO agents (${AGENT_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
          [
            record.agent_code,
            record.issuer,
            record.id,
            record.version,
            record.operator,
            record.class,
            record.level,
            record.status,
            record.status_ground,
            record.model,
            record.runtime,
            record.contour,
            record.conformance_run_ref,
            record.admitted_at,
            record.status_changed_at,
            record.suspended_at,
            record.row_version,
          ],
        );
      } catch (err) {
        if (violated(err, "23505", "agents_pkey")) throw new AgentCodeTakenError(record.agent_code);
        throw err;
      }
      await this.insertKey(tx, firstKey);
    });
  }

  async updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): Promise<AgentRecord | undefined> {
    const r = await this.client.query<AgentRow>(
      `UPDATE agents SET status = $3, status_ground = $4, status_changed_at = $5, suspended_at = $6, row_version = row_version + 1
        WHERE agent_code = $1 AND row_version = $2 RETURNING ${AGENT_COLUMNS}`,
      [agent_code, expectedRowVersion, fields.status, fields.status_ground, fields.status_changed_at, fields.suspended_at],
    );
    return r.rows[0] && toRecord(r.rows[0]);
  }

  /**
   * Статус и событие agent.* одной транзакцией (РП64 п. 4; РП54 остаточные риски 2, 8): строка агента FOR UPDATE, повтор
   * или переход (РП21 п. 4), UPDATE, строка push на том же соединении, номер ленты, событие ON CONFLICT DO NOTHING.
   * Время — часы базы после блокировки, до миллисекунды (РП64 п. 5, дополнение «2б-2» п. 1): status_changed_at, при
   * приостановлении и suspended_at. Повтор — без изменений; недостающее событие дописывается, второго нет.
   */
  async transitStatus(agent_code: string, req: AgentStatusRequest): Promise<{ readonly record: AgentRecord; readonly written: boolean }> {
    const type = req.to === "SUSPENDED" ? "agent.suspended" : "agent.reinstated";
    return this.tx(async (tx) => {
      const cur = await tx.query<AgentRow>(`SELECT ${AGENT_COLUMNS} FROM agents WHERE agent_code = $1 FOR UPDATE`, [agent_code]);
      if (!cur.rows[0]) throw new AgentNotFoundError(agent_code);
      let record = toRecord(cur.rows[0]);
      await this.hooks.inStatusTx?.("locked", agent_code);
      const repeat = isStatusRepeat(record, req);
      if (!repeat) {
        const c = checkTransition(record.status, req);
        const r = await tx.query<AgentRow>(
          `UPDATE agents SET status = $2::text, status_ground = $3::text, status_changed_at = c.t,
             suspended_at = CASE WHEN $2::text = 'SUSPENDED' THEN c.t ELSE suspended_at END, row_version = row_version + 1
           FROM (SELECT date_trunc('milliseconds', clock_timestamp()) AS t) c
           WHERE agent_code = $1 RETURNING ${AGENT_COLUMNS}`,
          [agent_code, c.to, c.to === "ACTIVE" ? null : c.ground],
        );
        if (!r.rows[0]) throw new Error(`Строка агента не изменена под блокировкой: ${agent_code}`);
        record = toRecord(r.rows[0]);
      }
      await this.hooks.inStatusTx?.("updated", agent_code);
      // Push «на момент записи» (РП40 п. 5; нюанс 2б-1 К2 п. 10): статус — из этой транзакции, подписка — тем же соединением.
      const sub = await tx.query<{ events: string[] }>("SELECT events FROM agent_subscriptions WHERE agent_code = $1", [agent_code]);
      const push = pushAllowed(record.status, type) && (sub.rows[0]?.events.includes(type) ?? false);
      const draft = { agent_code, type, data: { agent_code }, version: record.row_version, push } as const;
      const written = await insertAgentStatusEventTx(tx, draft, record.status_changed_at);
      if (!written && !repeat) throw new AgentStatusEventConflictError(agent_code, record.row_version);
      return { record, written };
    });
  }

  async getKey(kid: string): Promise<AgentKey | undefined> {
    const r = await this.client.query<KeyRow>(`SELECT ${KEY_COLUMNS} FROM agent_keys WHERE kid = $1`, [kid]);
    return r.rows[0] && toKey(r.rows[0]);
  }

  async keysOf(agent_code: string): Promise<readonly AgentKey[]> {
    const r = await this.client.query<KeyRow>(`SELECT ${KEY_COLUMNS} FROM agent_keys WHERE agent_code = $1 ORDER BY created_at, kid`, [
      agent_code,
    ]);
    return r.rows.map(toKey);
  }

  /**
   * Новый ключ и сокращение valid_to — одной транзакцией (РП23 п. 4 и дополнения): строка агента FOR SHARE (версия, по
   * которой проверен статус), ключи агента FOR UPDATE (их версии); изменилось что-то — false. kid уже есть — KeyTakenError.
   * Ключи сверяются вторым чтением после блокировки (КТ1 № 1): в READ COMMITTED FOR UPDATE после ожидания перепроверяет
   * только строки своего снимка, ключ, вставленный транзакцией, которую ждали, в него не попал бы — при пустом shorten
   * оба одновременных вызова вставили бы ключ. Блокировать есть что: первый ключ — при допуске, ключи не удаляются.
   */
  async addKey(
    key: AgentKey,
    expected: ReadonlyMap<string, number>,
    shorten: ReadonlyMap<string, string>,
    agentRowVersion: number,
  ): Promise<boolean> {
    return this.tx(async (tx) => {
      const agent = await tx.query<{ row_version: string }>("SELECT row_version FROM agents WHERE agent_code = $1 FOR SHARE", [
        key.agent_code,
      ]);
      if (!agent.rows[0]) throw new Error(`Агента нет в реестре: ${key.agent_code}`);
      await this.hooks.inTx?.("agent", key);
      if ((await tx.query("SELECT 1 FROM agent_keys WHERE kid = $1", [key.kid])).rows.length > 0) throw new KeyTakenError(key.kid);
      if (Number(agent.rows[0].row_version) !== agentRowVersion) return false;
      await this.hooks.inTx?.("kid", key);
      await tx.query("SELECT 1 FROM agent_keys WHERE agent_code = $1 ORDER BY kid FOR UPDATE", [key.agent_code]);
      const cur = await tx.query<{ kid: string; row_version: string }>("SELECT kid, row_version FROM agent_keys WHERE agent_code = $1", [
        key.agent_code,
      ]);
      const same = cur.rows.length === expected.size && cur.rows.every((k) => Number(k.row_version) === expected.get(k.kid));
      if (!same || [...shorten.keys()].some((kid) => !expected.has(kid))) return false;
      await this.hooks.inTx?.("keys", key);
      for (const [kid, valid_to] of shorten) {
        await tx.query("UPDATE agent_keys SET valid_to = $2, row_version = row_version + 1 WHERE kid = $1", [kid, valid_to]);
      }
      await this.insertKey(tx, key);
      return true;
    });
  }

  async revokeKey(kid: string, expectedRowVersion: number, revoked_at: string): Promise<AgentKey | undefined> {
    const r = await this.client.query<KeyRow>(
      `UPDATE agent_keys SET revoked_at = $3, row_version = row_version + 1
        WHERE kid = $1 AND row_version = $2 AND revoked_at IS NULL RETURNING ${KEY_COLUMNS}`,
      [kid, expectedRowVersion, revoked_at],
    );
    return r.rows[0] && toKey(r.rows[0]);
  }

  async subscriptionOf(agent_code: string): Promise<AgentSubscription | undefined> {
    const r = await this.client.query<{ url: string; events: AgentSubscription["events"][number][] }>(
      "SELECT url, events FROM agent_subscriptions WHERE agent_code = $1",
      [agent_code],
    );
    const row = r.rows[0];
    return row && Object.freeze({ url: row.url, events: Object.freeze([...row.events]) });
  }

  /** Замена подписки целиком (РП40 п. 1); агента нет — false (ссылка на agents). */
  async setSubscription(agent_code: string, subscription: AgentSubscription): Promise<boolean> {
    try {
      await this.client.query(
        `INSERT INTO agent_subscriptions (agent_code, url, events) VALUES ($1, $2, $3)
         ON CONFLICT (agent_code) DO UPDATE SET url = EXCLUDED.url, events = EXCLUDED.events`,
        [agent_code, subscription.url, [...subscription.events]],
      );
    } catch (err) {
      if (violated(err, "23503", "agent_subscriptions_agent_code_fkey")) return false;
      throw err;
    }
    return true;
  }

  private async insertKey(tx: SqlClient, key: AgentKey): Promise<void> {
    try {
      await tx.query(`INSERT INTO agent_keys (${KEY_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
        key.kid,
        key.agent_code,
        key.alg,
        key.public_key,
        key.valid_from,
        key.valid_to,
        key.revoked_at,
        key.row_version,
      ]);
    } catch (err) {
      if (violated(err, "23505", "agent_keys_pkey")) throw new KeyTakenError(key.kid);
      throw err;
    }
  }

  /** Транзакция на своём соединении; соединение, на котором не прошёл ROLLBACK, в пул не возвращается (как П2). */
  private async tx<T>(fn: (tx: SqlClient) => Promise<T>): Promise<T> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        const out = await fn(tx);
        await tx.query("COMMIT");
        return out;
      } catch (err) {
        await tx.query("ROLLBACK").catch((rb: unknown) => {
          broken = rb instanceof Error ? rb : new Error(String(rb));
        });
        throw err;
      }
    } finally {
      tx.release(broken);
    }
  }
}
