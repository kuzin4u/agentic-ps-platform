// П2 Хранилище журнала согласий (PS-06 К1.2): PostgreSQL в sandbox, память ядра в dev и стенде (как РП30 п. 6).
// Записи — в core_journal ядра (PgJournalStore, цепочка на корневой мандат); индекс и предмет — sql/100_consent.sql.
// Ядро не открывает транзакций (каждая операция — одна команда), поэтому порядок записи такой: индекс, предмет,
// затем запись журнала. Запись журнала — источник истины: строка индекса без записи MANDATE_REQUESTED — мандата нет.
// Запись, у которой есть событие агенту, и само событие — одной транзакцией Платформы (РП39 п. 1, sql/101_events.sql).
import {
  AsyncMemoryJournalStore,
  canonicalJson,
  chainGenesis,
  PgJournalStore,
  type AsyncJournalStore,
  type JournalEntry,
  type SqlClient,
} from "@kuzin4u/agentic-core";
import type { DeliveryOutcome, DeliveryRow, DueDelivery, EventDeliveryStore } from "../pao/delivery.js";
import { EventCursorUnknown, eventIdFor, eventSeqLockKey, type EventDraft, type PaoEventType, type StoredEvent } from "../pao/events.js";

export interface MandateIndexRow {
  readonly id: string;
  readonly chain: string;
  readonly agent_code: string;
  readonly created_at: string;
  /** sha256(canonicalJson(реквизиты перечня)), hex: сверка прерванной записи с повтором (РП33 доп. п. 7). Предмета нет. */
  readonly terms_hash: string;
}

export interface MandateSubjectRow {
  readonly mandate_id: string;
  readonly salt: string;
  /** canonicalJson({subject, cart}). */
  readonly subject_json: string;
}

/** Повторная вставка того же id — ошибка, не перезапись (только вставка, инвариант 6). */
export class ConsentRowConflict extends Error {
  constructor(readonly id: string) {
    super(`CONSENT_ROW_CONFLICT: ${id}`);
  }
}

export interface ConsentStore extends EventDeliveryStore {
  insertMandate(row: MandateIndexRow): Promise<void>;
  getMandate(id: string): Promise<MandateIndexRow | undefined>;
  insertSubject(row: MandateSubjectRow): Promise<void>;
  getSubject(mandateId: string): Promise<MandateSubjectRow | undefined>;
  /** Хранилище записей одной цепочки; начало цепочки привязано к её имени (chainGenesis, К6 п. 8). */
  journal(chain: string): AsyncJournalStore;
  /**
   * То же хранилище, но каждая вставка записи пишет и событие агенту — атомарно (РП39 п. 1): записи без события и
   * события без записи нет. Повтор вставки ядром при гонке конца цепочки — новая попытка целиком. draft.push — и строка
   * попытки push-доставки в той же транзакции (РП40 п. 5).
   */
  journalWithEvent(chain: string, draft: EventDraft): AsyncJournalStore;
  /**
   * События агента после курсора after (event_id), по возрастанию номера, не больше limit; без after — с начала.
   * after — не событие этого агента: EventCursorUnknown (РП39 п. 7).
   */
  listEvents(agent_code: string, after: string | undefined, limit: number): Promise<readonly StoredEvent[]>;
}

/** Событие записи: номер у агента даёт хранилище, event_id и время — запись журнала (РП39 п. 2–4). */
const eventOf = (draft: EventDraft, chain: string, e: JournalEntry, seq: number): StoredEvent =>
  Object.freeze({
    agent_code: draft.agent_code,
    type: draft.type,
    data: Object.freeze({ ...draft.data }),
    seq,
    event_id: eventIdFor(chain, e.seq),
    at: e.at,
    journal_chain: chain,
    journal_seq: e.seq,
  });

export class MemoryConsentStore implements ConsentStore {
  private readonly mandates = new Map<string, MandateIndexRow>();
  private readonly subjects = new Map<string, MandateSubjectRow>();
  private readonly chains = new Map<string, AsyncJournalStore>();
  private readonly events = new Map<string, StoredEvent[]>();
  private readonly byEventId = new Map<string, StoredEvent>();
  private readonly deliveries = new Map<string, DeliveryRow>();

  async insertMandate(row: MandateIndexRow): Promise<void> {
    if (this.mandates.has(row.id)) throw new ConsentRowConflict(row.id);
    this.mandates.set(row.id, Object.freeze({ ...row }));
  }
  async getMandate(id: string): Promise<MandateIndexRow | undefined> {
    return this.mandates.get(id);
  }
  async insertSubject(row: MandateSubjectRow): Promise<void> {
    if (!this.mandates.has(row.mandate_id)) throw new Error(`CONSENT_SUBJECT_ORPHAN: ${row.mandate_id}`);
    if (this.subjects.has(row.mandate_id)) throw new ConsentRowConflict(row.mandate_id);
    this.subjects.set(row.mandate_id, Object.freeze({ ...row }));
  }
  async getSubject(mandateId: string): Promise<MandateSubjectRow | undefined> {
    return this.subjects.get(mandateId);
  }
  journal(chain: string): AsyncJournalStore {
    let s = this.chains.get(chain);
    if (!s) this.chains.set(chain, (s = new AsyncMemoryJournalStore(chainGenesis(chain))));
    return s;
  }
  journalWithEvent(chain: string, draft: EventDraft): AsyncJournalStore {
    const inner = this.journal(chain);
    return {
      ...(inner.genesis !== undefined ? { genesis: inner.genesis } : {}),
      last: () => inner.last(),
      all: () => inner.all(),
      append: async (e) => {
        await inner.append(e);
        // Без await между вставкой записи и события: в одном процессе другая запись между ними не встанет.
        const own = this.events.get(draft.agent_code) ?? [];
        const ev = eventOf(draft, chain, e, own.length + 1);
        own.push(ev);
        this.events.set(draft.agent_code, own);
        this.byEventId.set(ev.event_id, ev);
        if (draft.push) this.deliveries.set(ev.event_id, newDelivery(ev));
      },
    };
  }
  async claimDue(nowMs: number, leaseUntilMs: number, limit: number): Promise<readonly DueDelivery[]> {
    const due = [...this.deliveries.values()]
      .filter((d) => d.state === "PENDING" && d.next_at_ms <= nowMs)
      .sort((a, b) => a.next_at_ms - b.next_at_ms)
      .slice(0, limit);
    return due.map((d) => {
      const next = Object.freeze({ ...d, attempts: d.attempts + 1, claims: d.claims + 1, next_at_ms: leaseUntilMs });
      this.deliveries.set(d.event_id, next);
      return { event: this.byEventId.get(d.event_id) as StoredEvent, attempts: next.attempts, claim: next.claims };
    });
  }
  async finish(event_id: string, claim: number, outcome: DeliveryOutcome): Promise<void> {
    const cur = this.deliveries.get(event_id);
    if (!cur || cur.state !== "PENDING" || cur.claims !== claim) return;
    this.deliveries.set(event_id, finished(cur, outcome));
  }
  async delivery(event_id: string): Promise<DeliveryRow | undefined> {
    return this.deliveries.get(event_id);
  }
  async listEvents(agent_code: string, after: string | undefined, limit: number): Promise<readonly StoredEvent[]> {
    const own = this.events.get(agent_code) ?? [];
    const from = after === undefined ? 0 : own.findIndex((e) => e.event_id === after) + 1;
    if (from === 0 && after !== undefined) throw new EventCursorUnknown();
    return own.slice(from, from + limit);
  }
}

/** Пул соединений: транзакция записи с событием — на своём соединении (РП39 п. 1). pg.Pool подходит без обёртки. */
export interface TxSqlPool extends SqlClient {
  connect(): Promise<SqlClient & { release(err?: Error | boolean): void }>;
}

/**
 * Точки внутри транзакции записи с событием — только для тестов (сбой, гонка конца цепочки, барьер «номер выдан,
 * фиксация позже»): "journal" — после BEGIN, до записи журнала (у каждой попытки); "event" — после записи журнала и
 * блокировки агента, до вставки события; "commit" — после вставки события, до COMMIT.
 */
export interface PgConsentStoreHooks {
  readonly inTx?: (step: "journal" | "event" | "commit", draft: EventDraft) => Promise<void>;
}

const UNIQUE_VIOLATION = "23505";

export class PgConsentStore implements ConsentStore {
  constructor(
    private readonly client: TxSqlPool,
    private readonly hooks: PgConsentStoreHooks = {},
  ) {}

  async insertMandate(r: MandateIndexRow): Promise<void> {
    await this.insert(
      r.id,
      "INSERT INTO consent_mandates (id, chain, agent_code, created_at, terms_hash) VALUES ($1, $2, $3, $4, $5)",
      [r.id, r.chain, r.agent_code, r.created_at, r.terms_hash],
    );
  }
  async getMandate(id: string): Promise<MandateIndexRow | undefined> {
    const r = await this.client.query<MandateIndexRow & Record<string, unknown>>(
      "SELECT id, chain, agent_code, created_at, terms_hash FROM consent_mandates WHERE id = $1",
      [id],
    );
    return r.rows[0];
  }
  async insertSubject(r: MandateSubjectRow): Promise<void> {
    await this.insert(r.mandate_id, "INSERT INTO consent_subjects (mandate_id, salt, subject_json) VALUES ($1, $2, $3)", [
      r.mandate_id,
      r.salt,
      r.subject_json,
    ]);
  }
  async getSubject(mandateId: string): Promise<MandateSubjectRow | undefined> {
    const r = await this.client.query<{ mandate_id: string; salt: string; subject_json: string }>(
      "SELECT mandate_id, salt, subject_json FROM consent_subjects WHERE mandate_id = $1",
      [mandateId],
    );
    return r.rows[0];
  }
  journal(chain: string): AsyncJournalStore {
    return new PgJournalStore(this.client, chain);
  }
  journalWithEvent(chain: string, draft: EventDraft): AsyncJournalStore {
    const read = new PgJournalStore(this.client, chain);
    return {
      genesis: read.genesis,
      last: () => read.last(),
      all: () => read.all(),
      append: (e) => this.appendWithEvent(chain, e, draft),
    };
  }

  /**
   * Одна попытка — одна транзакция: запись журнала, блокировка агента, событие с номером max + 1, COMMIT (РП39 п. 1–2).
   * Блокировка держится до конца транзакции: номер N + 1 выдаётся только после фиксации N. Гонка конца цепочки —
   * ROLLBACK и JournalAppendConflict ядру, оно повторяет попытку целиком (поэтому без SAVEPOINT).
   */
  private async appendWithEvent(chain: string, e: JournalEntry, draft: EventDraft): Promise<void> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        await this.hooks.inTx?.("journal", draft);
        await new PgJournalStore(tx, chain).append(e);
        await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [eventSeqLockKey(draft.agent_code)]);
        await this.hooks.inTx?.("event", draft);
        const ev = eventOf(draft, chain, e, 0);
        await tx.query(
          `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, journal_chain, journal_seq)
           SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, $3, $4, $5, $6, $7 FROM pao_events WHERE agent_code = $1`,
          [ev.agent_code, ev.event_id, ev.type, ev.at, canonicalJson(ev.data), ev.journal_chain, ev.journal_seq],
        );
        if (draft.push) {
          await tx.query(
            "INSERT INTO pao_event_deliveries (event_id, agent_code, state, attempts, next_at_ms) VALUES ($1, $2, 'PENDING', 0, $3)",
            [ev.event_id, ev.agent_code, Date.parse(ev.at)],
          );
        }
        await this.hooks.inTx?.("commit", draft);
        await tx.query("COMMIT");
      } catch (err) {
        // Соединение, на котором не прошёл ROLLBACK, в пул не возвращается.
        await tx.query("ROLLBACK").catch((rb: unknown) => {
          broken = rb instanceof Error ? rb : new Error(String(rb));
        });
        throw err;
      }
    } finally {
      tx.release(broken);
    }
  }

  async listEvents(agent_code: string, after: string | undefined, limit: number): Promise<readonly StoredEvent[]> {
    let from = 0;
    if (after !== undefined) {
      const c = await this.client.query<{ seq: string }>("SELECT seq FROM pao_events WHERE agent_code = $1 AND event_id = $2", [
        agent_code,
        after,
      ]);
      if (!c.rows[0]) throw new EventCursorUnknown();
      from = Number(c.rows[0].seq);
    }
    const r = await this.client.query<EventRow>(
      `SELECT agent_code, seq, event_id, type, at, data, journal_chain, journal_seq FROM pao_events
       WHERE agent_code = $1 AND seq > $2 ORDER BY seq LIMIT $3`,
      [agent_code, from, limit],
    );
    return r.rows.map(eventFromRow);
  }

  /** Одна команда: выбор готовых строк FOR UPDATE SKIP LOCKED, attempts + 1 и аренда, событие из ленты (РП40 п. 5). */
  async claimDue(nowMs: number, leaseUntilMs: number, limit: number): Promise<readonly DueDelivery[]> {
    const r = await this.client.query<EventRow & { attempts: number }>(
      `WITH c AS (
         SELECT event_id FROM pao_event_deliveries
         WHERE state = 'PENDING' AND next_at_ms <= $1 ORDER BY next_at_ms LIMIT $3 FOR UPDATE SKIP LOCKED
       ), u AS (
         UPDATE pao_event_deliveries d SET attempts = d.attempts + 1, claims = d.claims + 1, next_at_ms = $2
         FROM c WHERE d.event_id = c.event_id RETURNING d.event_id, d.attempts, d.claims
       )
       SELECT e.agent_code, e.seq, e.event_id, e.type, e.at, e.data, e.journal_chain, e.journal_seq, u.attempts, u.claims
       FROM u JOIN pao_events e ON e.event_id = u.event_id`,
      [nowMs, leaseUntilMs, limit],
    );
    return r.rows.map((x) => ({ event: eventFromRow(x), attempts: Number(x.attempts), claim: Number(x.claims) }));
  }
  /**
   * Итог — одной командой при совпадении номера взятия и PENDING. Попытки: возврат (refund, SKIPPED) — attempts − 1;
   * срок следующей попытки — только у PENDING, у конечных состояний остаётся как был.
   */
  async finish(event_id: string, claim: number, outcome: DeliveryOutcome): Promise<void> {
    const refund = outcome.state === "SKIPPED" || (outcome.state === "PENDING" && outcome.refund === true);
    await this.client.query(
      `UPDATE pao_event_deliveries
       SET state = $3, attempts = GREATEST(0, attempts - $4), next_at_ms = COALESCE($5, next_at_ms), last_reason = $6
       WHERE event_id = $1 AND claims = $2 AND state = 'PENDING'`,
      [
        event_id,
        claim,
        outcome.state,
        refund ? 1 : 0,
        outcome.state === "PENDING" ? outcome.next_at_ms : null,
        outcome.state === "DELIVERED" ? null : outcome.reason,
      ],
    );
  }
  async delivery(event_id: string): Promise<DeliveryRow | undefined> {
    const r = await this.client.query<{
      event_id: string;
      agent_code: string;
      state: string;
      attempts: number;
      claims: number;
      next_at_ms: string;
      last_reason: string | null;
    }>(
      "SELECT event_id, agent_code, state, attempts, claims, next_at_ms, last_reason FROM pao_event_deliveries WHERE event_id = $1",
      [event_id],
    );
    const x = r.rows[0];
    return x
      ? {
          ...x,
          state: x.state as DeliveryRow["state"],
          attempts: Number(x.attempts),
          claims: Number(x.claims),
          next_at_ms: Number(x.next_at_ms),
        }
      : undefined;
  }

  private async insert(id: string, sql: string, params: unknown[]): Promise<void> {
    try {
      await this.client.query(sql, params);
    } catch (err) {
      if ((err as { code?: string }).code === UNIQUE_VIOLATION) throw new ConsentRowConflict(id);
      throw err;
    }
  }
}

/** bigint из pg — строкой. */
interface EventRow extends Record<string, unknown> {
  readonly agent_code: string;
  readonly seq: string;
  readonly event_id: string;
  readonly type: string;
  readonly at: string;
  readonly data: string;
  readonly journal_chain: string;
  readonly journal_seq: string;
}

const eventFromRow = (x: EventRow): StoredEvent =>
  Object.freeze({
    agent_code: x.agent_code,
    type: x.type as PaoEventType,
    data: Object.freeze(JSON.parse(x.data) as EventDraft["data"]),
    seq: Number(x.seq),
    event_id: x.event_id,
    at: x.at,
    journal_chain: x.journal_chain,
    journal_seq: Number(x.journal_seq),
  });

/** Новая строка попытки: можно брать с момента события. */
const newDelivery = (ev: StoredEvent): DeliveryRow =>
  Object.freeze({
    event_id: ev.event_id,
    agent_code: ev.agent_code,
    state: "PENDING",
    attempts: 0,
    claims: 0,
    next_at_ms: Date.parse(ev.at),
    last_reason: null,
  });

/** Строка после итога попытки (в памяти; PostgreSQL — то же правило одной командой в finish). refund — попытка не потрачена. */
function finished(cur: DeliveryRow, o: DeliveryOutcome): DeliveryRow {
  if (o.state === "DELIVERED") return Object.freeze({ ...cur, state: "DELIVERED", last_reason: null });
  if (o.state === "PENDING") {
    const attempts = o.refund ? Math.max(0, cur.attempts - 1) : cur.attempts;
    return Object.freeze({ ...cur, state: "PENDING", attempts, next_at_ms: o.next_at_ms, last_reason: o.reason });
  }
  // SKIPPED — без попытки (РП40 п. 6); EXHAUSTED — попытки исчерпаны, событие в ленте.
  const attempts = o.state === "SKIPPED" ? Math.max(0, cur.attempts - 1) : cur.attempts;
  return Object.freeze({ ...cur, state: o.state, attempts, last_reason: o.reason });
}
