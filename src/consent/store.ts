// П2 Хранилище журнала согласий (PS-06 К1.2): PostgreSQL в sandbox, память ядра в dev и стенде (как РП30 п. 6).
// Записи — в core_journal ядра (PgJournalStore, цепочка на корневой мандат); индекс и предмет — sql/100_consent.sql.
// Ядро не открывает транзакций (каждая операция — одна команда), поэтому порядок записи такой: индекс, предмет,
// затем запись журнала. Запись журнала — источник истины: строка индекса без записи MANDATE_REQUESTED — мандата нет.
// Запись, у которой есть событие агенту, и само событие — одной транзакцией Платформы (РП39 п. 1, sql/101_events.sql).
import { createHash } from "node:crypto";
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
import {
  confirmationEventIdFor,
  EventCursorUnknown,
  eventIdFor,
  eventSeqLockKey,
  operationEventIdFor,
  type ConfirmationEventDraft,
  type EventDraft,
  type OperationEventDraft,
  type PaoEventType,
  type StoredEvent,
} from "../pao/events.js";
import { insertNotificationsTx, type NotificationSink, type ParticipantNotice } from "../participants/notifications.js";

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

/** Клиент мандата — пара банка и principal_ref (РП45 п. 1). */
export interface PrincipalPair {
  readonly participant_code: string;
  readonly principal_ref: string;
}

/**
 * Подпись мандата в порядке пары (РП46 (а)): строка SIGN пишется под локом пары в той же транзакции, что MANDATE_SIGNED.
 * root_id ≠ mandate_id — CART: корень, отозванный меткой, CART подписать не даёт (PairRevoked).
 */
export interface PairSign {
  readonly pair: PrincipalPair;
  readonly mandate_id: string;
  readonly root_id: string;
  readonly at: string;
}

/** Номер SIGN мандата в паре и номер последней метки REVOKE_ALL пары; нет строки — undefined. */
export interface PairPosition {
  readonly sign: number | undefined;
  readonly mark: number | undefined;
}

/** Метка отзыва всех полномочий пары (РП45 п. 4, РП46 (а)): номер и запись банка с подписью (canonicalJson). */
export interface RevokeAllMark {
  readonly n: number;
  readonly revocation_ref: string;
  readonly record: string;
  readonly at: string;
}

/** Корень CART отозван меткой пары (РП46 (а) п. 2): подпись CART не пишется. */
export class PairRevoked extends Error {
  constructor(readonly mandateId: string) {
    super(`PAIR_REVOKED: ${mandateId}`);
  }
}

/**
 * Ключ pg_advisory_xact_lock пары: 64 бита SHA-256 со знаком (как eventSeqLockKey). Коллизия двух пар только
 * сериализует их подписи и метки, корректность не страдает (РП46 (а) п. 2).
 */
export function pairLockKey(p: PrincipalPair): string {
  return createHash("sha256").update(`pao:principal-order:v1\n${p.participant_code}\n${p.principal_ref}`, "utf8").digest().readBigInt64BE(0).toString();
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
   * попытки push-доставки в той же транзакции (РП40 п. 5). notice — уведомление клиента через банк в той же транзакции
   * (client.mandate_exhausted, РП46 (б) п. 2): лок участника — после лока агента (доп. п. 5).
   */
  journalWithEvent(chain: string, draft: EventDraft, sign?: PairSign, notice?: ParticipantNotice): AsyncJournalStore;
  /** Уведомление клиента через банк вне записи журнала (client.revoked_all): своя транзакция под локом участника. */
  appendNotice(notice: ParticipantNotice, at: string): Promise<void>;
  /** Номер SIGN мандата и последней метки пары — одно чтение (РП46 (а) п. 5). */
  pairPosition(pair: PrincipalPair, mandate_id: string): Promise<PairPosition>;
  /** Метка пары под локом пары; повтор revocation_ref — прежняя метка, без новой строки (РП46 (а) п. 4). */
  insertRevokeAll(pair: PrincipalPair, revocation_ref: string, record: string, at: string): Promise<RevokeAllMark>;
  /** Подписи пары с номером меньше before, по возрастанию номера (записи отзыва после метки, РП46 (а) п. 4 (iii)). */
  pairSigns(pair: PrincipalPair, before: number): Promise<readonly { readonly mandate_id: string; readonly n: number }[]>;
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

/** Событие перехода запроса подтверждения (РП51 п. 1–4): без записи журнала, at — момент перехода. */
const confirmationEventOf = (draft: ConfirmationEventDraft, at: string, seq: number): StoredEvent =>
  Object.freeze({
    agent_code: draft.agent_code,
    type: draft.type,
    data: Object.freeze({ confirmation_id: draft.data.confirmation_id }),
    seq,
    event_id: confirmationEventIdFor(draft.data.confirmation_id, draft.type),
    at,
    journal_chain: null,
    journal_seq: null,
  });

/** Событие итога операции (РП52 п. 7): без записи журнала, at — момент записи итога. */
const operationEventOf = (draft: OperationEventDraft, at: string, seq: number): StoredEvent =>
  Object.freeze({
    agent_code: draft.agent_code,
    type: draft.type,
    data: Object.freeze({ op_ref: draft.data.op_ref }),
    seq,
    event_id: operationEventIdFor(draft.data.op_ref, draft.type),
    at,
    journal_chain: null,
    journal_seq: null,
  });

export class MemoryConsentStore implements ConsentStore {
  /** notifications — Outbox участника в памяти (стенд); без него уведомления клиента через банк не пишутся (dev без базы). */
  constructor(private readonly opts: { readonly notifications?: NotificationSink } = {}) {}

  private readonly mandates = new Map<string, MandateIndexRow>();
  private readonly subjects = new Map<string, MandateSubjectRow>();
  private readonly chains = new Map<string, AsyncJournalStore>();
  private readonly events = new Map<string, StoredEvent[]>();
  private readonly byEventId = new Map<string, StoredEvent>();
  private readonly deliveries = new Map<string, DeliveryRow>();
  private readonly order = new Map<string, { n: number; kind: "SIGN" | "REVOKE_ALL"; ref: string; record: string | null; at: string }[]>();

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
  journalWithEvent(chain: string, draft: EventDraft, sign?: PairSign, notice?: ParticipantNotice): AsyncJournalStore {
    const inner = this.journal(chain);
    return {
      ...(inner.genesis !== undefined ? { genesis: inner.genesis } : {}),
      last: () => inner.last(),
      all: () => inner.all(),
      append: async (e) => {
        if (sign && sign.root_id !== sign.mandate_id && this.revokedByMark(sign.pair, sign.root_id)) throw new PairRevoked(sign.mandate_id);
        await inner.append(e);
        // Без await между вставкой записи, строки SIGN и события: в одном процессе другая запись между ними не встанет.
        // Метка, вставшая между проверкой корня и записью, получает меньший номер — CART отозван правилом (РП46 (а) п. 3).
        if (sign) this.pushOrder(sign.pair, "SIGN", sign.mandate_id, null, sign.at);
        this.pushEvent(eventOf(draft, chain, e, (this.events.get(draft.agent_code)?.length ?? 0) + 1), draft.push);
        if (notice) this.opts.notifications?.insertNow(notice.participant_code, notice.drafts, e.at);
      },
    };
  }
  /**
   * Событие перехода запроса подтверждения (РП51 п. 2–3): без await — вызывающий пишет его в том же синхронном шаге, что
   * переход П6. Второе событие на тот же переход — ошибка, как UNIQUE (confirmation_id, type) на PG.
   */
  appendConfirmationEventNow(draft: ConfirmationEventDraft, at: string): void {
    const ev = confirmationEventOf(draft, at, (this.events.get(draft.agent_code)?.length ?? 0) + 1);
    if (this.byEventId.has(ev.event_id)) throw new Error(`pao_events: событие ${draft.type} запроса уже записано`);
    this.pushEvent(ev, draft.push);
  }
  /**
   * Событие итога операции (РП52 п. 7–8): без await — вызывающий пишет его в том же синхронном шаге, что итог. Второе
   * событие того же типа по операции — ошибка, как UNIQUE (op_ref, type) на PG.
   */
  appendOperationEventNow(draft: OperationEventDraft, at: string): void {
    const ev = operationEventOf(draft, at, (this.events.get(draft.agent_code)?.length ?? 0) + 1);
    if (this.byEventId.has(ev.event_id)) throw new Error(`pao_events: событие ${draft.type} операции уже записано`);
    this.pushEvent(ev, draft.push);
  }
  private pushEvent(ev: StoredEvent, push: boolean | undefined): void {
    const own = this.events.get(ev.agent_code) ?? [];
    own.push(ev);
    this.events.set(ev.agent_code, own);
    this.byEventId.set(ev.event_id, ev);
    if (push) this.deliveries.set(ev.event_id, newDelivery(ev));
  }
  async pairPosition(pair: PrincipalPair, mandate_id: string): Promise<PairPosition> {
    return this.position(pair, mandate_id);
  }
  async appendNotice(notice: ParticipantNotice, at: string): Promise<void> {
    this.opts.notifications?.insertNow(notice.participant_code, notice.drafts, at);
  }
  async insertRevokeAll(pair: PrincipalPair, revocation_ref: string, record: string, at: string): Promise<RevokeAllMark> {
    const prior = (this.order.get(pairKey(pair)) ?? []).find((r) => r.kind === "REVOKE_ALL" && r.ref === revocation_ref);
    const row = prior ?? this.pushOrder(pair, "REVOKE_ALL", revocation_ref, record, at);
    return { n: row.n, revocation_ref, record: row.record as string, at: row.at };
  }
  async pairSigns(pair: PrincipalPair, before: number): Promise<readonly { readonly mandate_id: string; readonly n: number }[]> {
    return (this.order.get(pairKey(pair)) ?? []).filter((r) => r.kind === "SIGN" && r.n < before).map((r) => ({ mandate_id: r.ref, n: r.n }));
  }
  private position(pair: PrincipalPair, mandate_id: string): PairPosition {
    const rows = this.order.get(pairKey(pair)) ?? [];
    const marks = rows.filter((r) => r.kind === "REVOKE_ALL");
    return { sign: rows.find((r) => r.kind === "SIGN" && r.ref === mandate_id)?.n, mark: marks.length ? marks[marks.length - 1]!.n : undefined };
  }
  private revokedByMark(pair: PrincipalPair, root_id: string): boolean {
    const p = this.position(pair, root_id);
    return p.mark !== undefined && (p.sign === undefined || p.mark > p.sign);
  }
  /** Строка порядка пары с номером max + 1; повтор SIGN того же мандата — прежняя строка (дубль решения, РП36 доп. п. 4). */
  private pushOrder(pair: PrincipalPair, kind: "SIGN" | "REVOKE_ALL", ref: string, record: string | null, at: string) {
    const rows = this.order.get(pairKey(pair)) ?? [];
    const prior = rows.find((r) => r.kind === kind && r.ref === ref);
    if (prior) return prior;
    const row = Object.freeze({ n: rows.length + 1, kind, ref, record, at });
    rows.push(row);
    this.order.set(pairKey(pair), rows);
    return row;
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
 * блокировки агента, до вставки события; "commit" — после вставки события и строки SIGN пары, до COMMIT.
 */
export interface PgConsentStoreHooks {
  readonly inTx?: (step: "journal" | "event" | "commit", draft: EventDraft) => Promise<void>;
  /** Точка в транзакции метки revoke-all: "mark" — после лока пары, до вставки метки (РП46 (а), тест гонки). */
  readonly inMarkTx?: (pair: PrincipalPair) => Promise<void>;
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
  journalWithEvent(chain: string, draft: EventDraft, sign?: PairSign, notice?: ParticipantNotice): AsyncJournalStore {
    const read = new PgJournalStore(this.client, chain);
    return {
      genesis: read.genesis,
      last: () => read.last(),
      all: () => read.all(),
      append: (e) => this.appendWithEvent(chain, e, draft, sign, notice),
    };
  }

  async pairPosition(pair: PrincipalPair, mandate_id: string): Promise<PairPosition> {
    return position(this.client, pair, mandate_id);
  }

  async appendNotice(notice: ParticipantNotice, at: string): Promise<void> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        await insertNotificationsTx(tx, notice.participant_code, notice.drafts, at);
        await tx.query("COMMIT");
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

  /** Одна транзакция: лок пары, прежняя метка с тем же revocation_ref или новая с номером max + 1, COMMIT. */
  async insertRevokeAll(pair: PrincipalPair, revocation_ref: string, record: string, at: string): Promise<RevokeAllMark> {
    return this.tx(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [pairLockKey(pair)]);
      await this.hooks.inMarkTx?.(pair);
      await tx.query(
        `INSERT INTO principal_order (participant_code, principal_ref, n, kind, ref, at, record)
         SELECT $1, $2, COALESCE(MAX(n), 0) + 1, 'REVOKE_ALL', $3, $4, $5 FROM principal_order
         WHERE participant_code = $1 AND principal_ref = $2
         ON CONFLICT (participant_code, principal_ref, kind, ref) DO NOTHING`,
        [pair.participant_code, pair.principal_ref, revocation_ref, at, record],
      );
      const r = await tx.query<{ n: string; record: string; at: string }>(
        "SELECT n, record, at FROM principal_order WHERE participant_code = $1 AND principal_ref = $2 AND kind = 'REVOKE_ALL' AND ref = $3",
        [pair.participant_code, pair.principal_ref, revocation_ref],
      );
      const x = r.rows[0];
      if (!x) throw new Error("principal_order: метка после вставки не читается");
      return { n: Number(x.n), revocation_ref, record: x.record, at: x.at };
    });
  }

  async pairSigns(pair: PrincipalPair, before: number): Promise<readonly { readonly mandate_id: string; readonly n: number }[]> {
    const r = await this.client.query<{ ref: string; n: string }>(
      `SELECT ref, n FROM principal_order WHERE participant_code = $1 AND principal_ref = $2 AND kind = 'SIGN' AND n < $3 ORDER BY n`,
      [pair.participant_code, pair.principal_ref, before],
    );
    return r.rows.map((x) => ({ mandate_id: x.ref, n: Number(x.n) }));
  }

  /** Транзакция на своём соединении; соединение, на котором не прошёл ROLLBACK, в пул не возвращается. */
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

  /**
   * Одна попытка — одна транзакция: запись журнала, блокировка агента, событие с номером max + 1, COMMIT (РП39 п. 1–2).
   * Блокировка держится до конца транзакции: номер N + 1 выдаётся только после фиксации N. Гонка конца цепочки —
   * ROLLBACK и JournalAppendConflict ядру, оно повторяет попытку целиком (поэтому без SAVEPOINT).
   * sign — подпись мандата (РП46 (а) п. 2): первым — лок пары (метка revoke-all ждёт фиксации подписи, и наоборот),
   * у CART — проверка корня по метке, строка SIGN с номером max + 1 — до COMMIT.
   */
  private async appendWithEvent(chain: string, e: JournalEntry, draft: EventDraft, sign?: PairSign, notice?: ParticipantNotice): Promise<void> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        if (sign) {
          await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [pairLockKey(sign.pair)]);
          if (sign.root_id !== sign.mandate_id) {
            const p = await position(tx, sign.pair, sign.root_id);
            if (p.mark !== undefined && (p.sign === undefined || p.mark > p.sign)) throw new PairRevoked(sign.mandate_id);
          }
        }
        await this.hooks.inTx?.("journal", draft);
        await new PgJournalStore(tx, chain).append(e);
        await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [eventSeqLockKey(draft.agent_code)]);
        await this.hooks.inTx?.("event", draft);
        await insertEventTx(tx, eventOf(draft, chain, e, 0), draft.push);
        if (sign) {
          // Дубль решения с другого экземпляра (РП36 доп. п. 4) — прежняя строка, номер не меняется.
          await tx.query(
            `INSERT INTO principal_order (participant_code, principal_ref, n, kind, ref, at, record)
             SELECT $1, $2, COALESCE(MAX(n), 0) + 1, 'SIGN', $3, $4, NULL FROM principal_order
             WHERE participant_code = $1 AND principal_ref = $2
             ON CONFLICT (participant_code, principal_ref, kind, ref) DO NOTHING`,
            [sign.pair.participant_code, sign.pair.principal_ref, sign.mandate_id, sign.at],
          );
        }
        // Уведомление клиента через банк — в той же транзакции, лок участника последним: «пара → агент → участник».
        if (notice) await insertNotificationsTx(tx, notice.participant_code, notice.drafts, e.at);
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

const pairKey = (p: PrincipalPair): string => `${p.participant_code}\n${p.principal_ref}`;

/** Номер SIGN мандата и последней метки пары — одна команда. */
async function position(client: SqlClient, pair: PrincipalPair, mandate_id: string): Promise<PairPosition> {
  const r = await client.query<{ sign: string | null; mark: string | null }>(
    `SELECT MAX(n) FILTER (WHERE kind = 'SIGN' AND ref = $3) AS sign, MAX(n) FILTER (WHERE kind = 'REVOKE_ALL') AS mark
     FROM principal_order WHERE participant_code = $1 AND principal_ref = $2`,
    [pair.participant_code, pair.principal_ref, mandate_id],
  );
  const x = r.rows[0];
  return { sign: x?.sign == null ? undefined : Number(x.sign), mark: x?.mark == null ? undefined : Number(x.mark) };
}

/**
 * Вставка события с номером max + 1 у агента и строки попытки push (РП39 п. 2, РП40 п. 5) — внутри транзакции вызывающего,
 * под уже взятой блокировкой агента. ev.seq не используется: номер даёт база.
 */
async function insertEventTx(tx: SqlClient, ev: StoredEvent, push: boolean | undefined): Promise<void> {
  const confirmation_id = "confirmation_id" in ev.data ? ev.data.confirmation_id : null;
  const op_ref = "op_ref" in ev.data ? ev.data.op_ref : null;
  await tx.query(
    `INSERT INTO pao_events (agent_code, seq, event_id, type, at, data, journal_chain, journal_seq, confirmation_id, op_ref)
     SELECT $1, COALESCE(MAX(seq), 0) + 1, $2, $3, $4, $5, $6, $7, $8, $9 FROM pao_events WHERE agent_code = $1`,
    [ev.agent_code, ev.event_id, ev.type, ev.at, canonicalJson(ev.data), ev.journal_chain, ev.journal_seq, confirmation_id, op_ref],
  );
  if (push) {
    await tx.query(
      "INSERT INTO pao_event_deliveries (event_id, agent_code, state, attempts, next_at_ms) VALUES ($1, $2, 'PENDING', 0, $3)",
      [ev.event_id, ev.agent_code, Date.parse(ev.at)],
    );
  }
}

/**
 * Событие перехода запроса подтверждения в транзакции перехода П6 (РП51 п. 3): блокировка агента до фиксации — номер
 * общий с событиями мандатов (РП39 п. 2), затем вставка. Сбой — исключение, вызывающий откатывает переход вместе с событием.
 */
export async function insertConfirmationEventTx(tx: SqlClient, draft: ConfirmationEventDraft, at: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [eventSeqLockKey(draft.agent_code)]);
  await insertEventTx(tx, confirmationEventOf(draft, at, 0), draft.push);
}

/** Событие итога операции в транзакции итога (РП52 п. 7–8): блокировка агента до фиксации, затем вставка (как РП51 п. 3). */
export async function insertOperationEventTx(tx: SqlClient, draft: OperationEventDraft, at: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [eventSeqLockKey(draft.agent_code)]);
  await insertEventTx(tx, operationEventOf(draft, at, 0), draft.push);
}

/** bigint из pg — строкой. */
interface EventRow extends Record<string, unknown> {
  readonly agent_code: string;
  readonly seq: string;
  readonly event_id: string;
  readonly type: string;
  readonly at: string;
  readonly data: string;
  readonly journal_chain: string | null;
  readonly journal_seq: string | null;
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
    journal_seq: x.journal_seq === null ? null : Number(x.journal_seq),
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
