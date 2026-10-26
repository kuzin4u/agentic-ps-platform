// Хранилище П6 (РП50): запросы подтверждения. В памяти (dev без базы, стенд) и на PostgreSQL (sql/111_confirmations.sql).
// Переходы — условной записью: из одновременных проходит ровно одна (п. 5, 10). Переход, кроме USED, — событие
// confirmation.* агенту записи в той же транзакции (РП51 п. 2–3): перехода без события и события без перехода нет.
import type { SqlClient } from "@kuzin4u/agentic-core";
import { insertConfirmationEventTx, type MemoryConsentStore, type TxSqlPool } from "../consent/store.js";
import type { ConfirmationEventDraft, PaoEventType } from "../pao/events.js";
import type { ConfirmationDecision, ConfirmationRecord, ConfirmationStatus, ConfirmationTotals } from "./model.js";

/** Ключ запроса (РП50 п. 2): мандат, продавец, заказ, сумма, валюта. */
export type ConfirmationKey = Pick<ConfirmationTotals, "mandate_id" | "merchant_id" | "order_ref" | "amount" | "currency">;

/** Сбой любого метода — исключение (→ STATE_UNAVAILABLE). Время `now` — ISO-строка часов Платформы. */
export interface ConfirmationStore {
  /** Запрос по ключу: на ключ — одна запись за всё время (Дополнения РП50 п. 1); нет — пусто. */
  byKey(key: ConfirmationKey): Promise<ConfirmationRecord[]>;
  /**
   * Атомарно: записи по ключу нет — записать PENDING; есть (другой экземпляр успел первым, или заказ уже закрыт) —
   * вернуть записанную в любом статусе.
   */
  create(rec: ConfirmationRecord): Promise<ConfirmationRecord>;
  get(confirmation_id: string): Promise<ConfirmationRecord | undefined>;
  byRef(confirmation_ref: string): Promise<ConfirmationRecord | undefined>;
  /** PENDING с expires_at ≤ now → EXPIRED; true — перевёл этот вызов. */
  expire(confirmation_id: string, now: string): Promise<boolean>;
  /**
   * PENDING и now < expires_at → APPROVED (со ссылкой) или REJECTED (без неё); иначе — undefined, запись не меняется.
   */
  decide(confirmation_id: string, d: ConfirmationDecision, confirmation_ref: string | null, now: string): Promise<ConfirmationRecord | undefined>;
  /** APPROVED и now < expires_at → USED с op_ref (п. 10): true — погасил этот вызов. */
  consume(confirmation_ref: string, op_ref: string, now: string): Promise<boolean>;
}

/**
 * Строка попытки push в транзакции события (РП40 п. 5): агент ACTIVE и подписан на тип — на момент записи. Чтение реестра
 * (РП64 п. 3): сбой — отклонённое обещание, переход и событие не записываются.
 */
export type PushFor = (agent_code: string, type: PaoEventType) => Promise<boolean>;

type ConfirmationEventType = ConfirmationEventDraft["type"];

const pushOf = async (pushFor: PushFor | undefined, agent_code: string, type: ConfirmationEventType): Promise<boolean> =>
  (await pushFor?.(agent_code, type)) ?? false;

const draftOf = (r: ConfirmationRecord, type: ConfirmationEventType, push: boolean): ConfirmationEventDraft => ({
  agent_code: r.agent_code,
  type,
  data: { confirmation_id: r.confirmation_id },
  push,
});

const keyOf = (k: ConfirmationKey): string => JSON.stringify([k.mandate_id, k.merchant_id, k.order_ref, k.amount, k.currency]);

export interface MemoryConfirmationStoreOptions {
  /** Лента агента в памяти (РП51 п. 3); без неё (тесты П6 без ленты) события не пишутся. */
  readonly events?: Pick<MemoryConsentStore, "appendConfirmationEventNow">;
  readonly pushFor?: PushFor;
}

export class MemoryConfirmationStore implements ConfirmationStore {
  readonly #rows = new Map<string, ConfirmationRecord>();

  constructor(private readonly opts: MemoryConfirmationStoreOptions = {}) {}

  /**
   * Событие до записи строки, без await между ними: сбой события оставляет запрос без перехода (РП51 п. 2). Строка push
   * читается до проверки состояния (РП64 п. 3): между проверкой и записью await нет.
   */
  #transit(next: ConfirmationRecord, type: ConfirmationEventType, at: string, push: boolean): void {
    this.opts.events?.appendConfirmationEventNow(draftOf(next, type, push), at);
    this.#rows.set(next.confirmation_id, structuredClone(next));
  }

  async byKey(key: ConfirmationKey): Promise<ConfirmationRecord[]> {
    const k = keyOf(key);
    return [...this.#rows.values()].filter((r) => keyOf(r) === k).map((r) => structuredClone(r));
  }

  /** Проверка и запись без await между ними: один процесс — одна очередь. */
  async create(rec: ConfirmationRecord): Promise<ConfirmationRecord> {
    if (rec.status !== "PENDING") throw new Error("confirmations: вставка — только PENDING");
    const push = await pushOf(this.opts.pushFor, rec.agent_code, "confirmation.required");
    const k = keyOf(rec);
    const prior = [...this.#rows.values()].find((r) => keyOf(r) === k);
    if (prior) return structuredClone(prior);
    if (this.#rows.has(rec.confirmation_id)) throw new Error("confirmations: confirmation_id уже записан");
    this.#transit(rec, "confirmation.required", rec.created_at, push);
    return structuredClone(rec);
  }

  async get(confirmation_id: string): Promise<ConfirmationRecord | undefined> {
    const r = this.#rows.get(confirmation_id);
    return r && structuredClone(r);
  }

  async byRef(confirmation_ref: string): Promise<ConfirmationRecord | undefined> {
    const r = [...this.#rows.values()].find((x) => x.confirmation_ref === confirmation_ref);
    return r && structuredClone(r);
  }

  async expire(confirmation_id: string, now: string): Promise<boolean> {
    // agent_code запроса не меняется: строка push — по нему, до проверки состояния.
    const agent_code = this.#rows.get(confirmation_id)?.agent_code;
    if (agent_code === undefined) return false;
    const push = await pushOf(this.opts.pushFor, agent_code, "confirmation.expired");
    const r = this.#rows.get(confirmation_id);
    if (!r || r.status !== "PENDING" || r.expires_at > now) return false;
    this.#transit({ ...r, status: "EXPIRED" }, "confirmation.expired", now, push);
    return true;
  }

  async decide(confirmation_id: string, d: ConfirmationDecision, confirmation_ref: string | null, now: string): Promise<ConfirmationRecord | undefined> {
    const agent_code = this.#rows.get(confirmation_id)?.agent_code;
    if (agent_code === undefined) return undefined;
    const type = d.decision === "APPROVE" ? "confirmation.approved" : "confirmation.rejected";
    const push = await pushOf(this.opts.pushFor, agent_code, type);
    const r = this.#rows.get(confirmation_id);
    if (!r || r.status !== "PENDING" || !(r.expires_at > now)) return undefined;
    // Одобрение без ссылки — ошибка вызывающего, как CHECK на PG (Дополнения РП50 п. 6).
    if (d.decision === "APPROVE" && confirmation_ref === null) throw new Error("confirmations: APPROVE без confirmation_ref");
    const status: ConfirmationStatus = d.decision === "APPROVE" ? "APPROVED" : "REJECTED";
    const next: ConfirmationRecord = { ...r, status, decision: { ...d }, confirmation_ref: status === "APPROVED" ? confirmation_ref : null };
    this.#transit(next, type, now, push);
    return structuredClone(next);
  }

  async consume(confirmation_ref: string, op_ref: string, now: string): Promise<boolean> {
    const r = [...this.#rows.values()].find((x) => x.confirmation_ref === confirmation_ref);
    if (!r || r.status !== "APPROVED" || !(r.expires_at > now)) return false;
    this.#rows.set(r.confirmation_id, { ...r, status: "USED", op_ref });
    return true;
  }
}

interface Row extends Record<string, unknown> {
  confirmation_id: string;
  agent_code: string;
  mandate_id: string;
  merchant_id: string;
  amount: string;
  currency: string;
  order_ref: string;
  split_detected: boolean;
  status: ConfirmationStatus;
  created_at: string;
  expires_at: string;
  confirmation_ref: string | null;
  participant_code: string | null;
  kid: string | null;
  decision: "APPROVE" | "REJECT" | null;
  totals_hash: string | null;
  decided_at: string | null;
  signature: string | null;
  op_ref: string | null;
  instrument_chosen: "CARD" | "SBP" | null;
}

const COLS =
  "confirmation_id, agent_code, mandate_id, merchant_id, amount, currency, order_ref, split_detected, status, created_at, " +
  "expires_at, confirmation_ref, participant_code, kid, decision, totals_hash, decided_at, signature, op_ref, instrument_chosen";

/** bigint приходит строкой: вне точного диапазона — не подтверждено (инвариант 3), а не округление. */
function recordOf(row: Row): ConfirmationRecord {
  const amount = Number(row.amount);
  if (!Number.isSafeInteger(amount)) throw new Error("confirmations: amount вне точного диапазона");
  const decision: ConfirmationDecision | null =
    row.decision === null
      ? null
      : {
          participant_code: row.participant_code as string,
          kid: row.kid as string,
          decision: row.decision,
          totals_hash: (row.totals_hash as string).trim(),
          decided_at: row.decided_at as string,
          signature: row.signature as string,
          ...(row.instrument_chosen === null ? {} : { instrument_chosen: row.instrument_chosen }),
        };
  return {
    confirmation_id: row.confirmation_id,
    agent_code: row.agent_code,
    mandate_id: row.mandate_id,
    merchant_id: row.merchant_id,
    amount,
    currency: row.currency.trim(),
    order_ref: row.order_ref,
    split_detected: row.split_detected,
    status: row.status,
    created_at: row.created_at,
    expires_at: row.expires_at,
    confirmation_ref: row.confirmation_ref,
    decision,
    op_ref: row.op_ref,
  };
}

/**
 * Хранилище П6 на PostgreSQL (sql/111_confirmations.sql). Запрос — INSERT … ON CONFLICT DO NOTHING по уникальному
 * индексу ключа (одна запись на ключ за всё время), затем чтение записанного; решение, истечение и погашение — один условный
 * UPDATE; триггер не даёт перехода вне РП50 п. 5 и изменения итоговых значений. Вставка запроса, решение и истечение —
 * транзакция вместе с событием (sql/112, РП51 п. 3); погашение события не даёт.
 */
export class PgConfirmationStore implements ConfirmationStore {
  private readonly lockTimeoutMs: number;

  /** lockTimeoutMs — предел ожидания блокировки при создании запроса в пути ADP: adp_timeout_ms (Дополнения РП51 п. 1). */
  constructor(
    private readonly client: TxSqlPool,
    private readonly opts: { readonly lockTimeoutMs: number; readonly pushFor?: PushFor },
  ) {
    if (!Number.isSafeInteger(opts.lockTimeoutMs) || opts.lockTimeoutMs < 1) throw new Error("PgConfirmationStore: lockTimeoutMs — целое ≥ 1");
    this.lockTimeoutMs = opts.lockTimeoutMs;
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

  async byKey(key: ConfirmationKey): Promise<ConfirmationRecord[]> {
    const r = await this.client.query<Row>(
      `SELECT ${COLS} FROM confirmations
       WHERE mandate_id = $1 AND merchant_id = $2 AND order_ref = $3 AND amount = $4 AND currency = $5 ORDER BY created_at, confirmation_id`,
      [key.mandate_id, key.merchant_id, key.order_ref, key.amount, key.currency],
    );
    return r.rows.map(recordOf);
  }

  async create(rec: ConfirmationRecord): Promise<ConfirmationRecord> {
    // Событие — только у вставившего: при конфликте ключа запрос и его событие уже записаны другим (РП51 п. 2).
    // Путь авторизации: ожидание блокировок (строка ключа, блокировка агента) — не дольше lockTimeoutMs, иначе исключение
    // (→ STATE_UNAVAILABLE) и откат без запроса и события (Дополнения РП51 п. 1; как окно дробления, доп. РП44 п. 2).
    await this.tx(async (tx) => {
      await tx.query("SELECT set_config('lock_timeout', $1, true)", [`${this.lockTimeoutMs}ms`]);
      const ins = await tx.query(
        `INSERT INTO confirmations (confirmation_id, agent_code, mandate_id, merchant_id, amount, currency, order_ref, split_detected,
           status, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING', $9, $10)
         ON CONFLICT (mandate_id, merchant_id, order_ref, amount, currency) DO NOTHING RETURNING confirmation_id`,
        [rec.confirmation_id, rec.agent_code, rec.mandate_id, rec.merchant_id, rec.amount, rec.currency, rec.order_ref, rec.split_detected,
          rec.created_at, rec.expires_at],
      );
      if (ins.rows.length === 1) {
        const push = await pushOf(this.opts.pushFor, rec.agent_code, "confirmation.required");
        await insertConfirmationEventTx(tx, draftOf(rec, "confirmation.required", push), rec.created_at);
      }
    });
    const [row] = await this.byKey(rec);
    if (!row) throw new Error("confirmations: запрос не найден после вставки");
    return row;
  }

  async get(confirmation_id: string): Promise<ConfirmationRecord | undefined> {
    const r = await this.client.query<Row>(`SELECT ${COLS} FROM confirmations WHERE confirmation_id = $1`, [confirmation_id]);
    return r.rows[0] && recordOf(r.rows[0]);
  }

  async byRef(confirmation_ref: string): Promise<ConfirmationRecord | undefined> {
    const r = await this.client.query<Row>(`SELECT ${COLS} FROM confirmations WHERE confirmation_ref = $1`, [confirmation_ref]);
    return r.rows[0] && recordOf(r.rows[0]);
  }

  async expire(confirmation_id: string, now: string): Promise<boolean> {
    return this.tx(async (tx) => {
      const r = await tx.query<Row>(
        `UPDATE confirmations SET status = 'EXPIRED' WHERE confirmation_id = $1 AND status = 'PENDING' AND expires_at <= $2 RETURNING ${COLS}`,
        [confirmation_id, now],
      );
      if (!r.rows[0]) return false;
      const rec = recordOf(r.rows[0]);
      await insertConfirmationEventTx(tx, draftOf(rec, "confirmation.expired", await pushOf(this.opts.pushFor, rec.agent_code, "confirmation.expired")), now);
      return true;
    });
  }

  async decide(confirmation_id: string, d: ConfirmationDecision, confirmation_ref: string | null, now: string): Promise<ConfirmationRecord | undefined> {
    const approve = d.decision === "APPROVE";
    return this.tx(async (tx) => {
      const r = await tx.query<Row>(
        `UPDATE confirmations SET status = $2, confirmation_ref = $3, participant_code = $4, kid = $5, decision = $6, totals_hash = $7,
           decided_at = $8, signature = $9, instrument_chosen = $11
         WHERE confirmation_id = $1 AND status = 'PENDING' AND expires_at > $10 RETURNING ${COLS}`,
        [confirmation_id, approve ? "APPROVED" : "REJECTED", approve ? confirmation_ref : null, d.participant_code, d.kid, d.decision,
          d.totals_hash, d.decided_at, d.signature, now, d.instrument_chosen ?? null],
      );
      if (!r.rows[0]) return undefined;
      const next = recordOf(r.rows[0]);
      const type = approve ? "confirmation.approved" : "confirmation.rejected";
      await insertConfirmationEventTx(tx, draftOf(next, type, await pushOf(this.opts.pushFor, next.agent_code, type)), now);
      return next;
    });
  }

  async consume(confirmation_ref: string, op_ref: string, now: string): Promise<boolean> {
    const r = await this.client.query(
      `UPDATE confirmations SET status = 'USED', op_ref = $2
       WHERE confirmation_ref = $1 AND status = 'APPROVED' AND expires_at > $3 RETURNING confirmation_id`,
      [confirmation_ref, op_ref, now],
    );
    return r.rows.length === 1;
  }
}
