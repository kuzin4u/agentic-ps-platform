// П10 Знак готовности продавца (A5 п. 5, РП22 п. 7, РП57 п. 2–3): записи эквайрера (подать — ACTIVE, снять — WITHDRAWN,
// подписанной записью ПИ-8) и оператора (SUSPENDED с причиной, REINSTATED), только вставкой; порядок — номер записи
// (bigserial в базе, порядок вставки в памяти), не issued_at и не часы сервера. Статус — в два шага: последняя запись
// оператора SUSPENDED → SUSPENDED, какие бы записи эквайрера ни шли после; иначе по последней записи эквайрера.
// В памяти (dev без базы, стенд) и на PostgreSQL (sql/118_merchant_readiness.sql). Номера карты нет (инвариант 1).
import type { SqlClient } from "@kuzin4u/agentic-core";
import { parseRfc3339 } from "../consent/model.js";
import { isMerchantId, type ReadinessSignedRecord } from "./trusted.js";

/** Причины приостановления знака оператором (A5 п. 5.3, РП57 п. 2). */
export const READINESS_SUSPEND_REASONS = ["DISCREPANCY", "AGENT_REFUSALS", "SYSTEMATIC_CANCELLATION"] as const;
export type ReadinessSuspendReason = (typeof READINESS_SUSPEND_REASONS)[number];

/** Статус знака для продавца, эквайрера и агента (РП57 п. 3). */
export type ReadinessStatus = "ACTIVE" | "SUSPENDED" | "NONE";

/** Ссылка записи эквайрера — как в processing-interface.yaml. */
export const READINESS_REF = /^[A-Za-z0-9_-]{1,64}$/;

/** Запись эквайрера в хранилище: подпись — доказательство, received_at — часы Платформы. */
export interface StoredAcquirerReadiness extends ReadinessSignedRecord {
  readonly signature: string;
  readonly received_at: string;
}

/** Запись оператора (A5 п. 5.3): приостановление с причиной или снятие. */
export interface OperatorReadiness {
  readonly merchant_id: string;
  readonly action: "SUSPENDED" | "REINSTATED";
  readonly reason: ReadinessSuspendReason | null;
  readonly received_at: string;
}

/** Статус знака; reason — только при SUSPENDED и только эквайреру (РП57 п. 3). */
export interface ReadinessView {
  readonly merchant_id: string;
  readonly status: ReadinessStatus;
  /** Время записи, от которой действует статус; записей нет — null. */
  readonly since: string | null;
  readonly reason?: ReadinessSuspendReason;
}

/**
 * Итог вставки записи эквайрера: inserted; replayed — та же запись (статус не меняется); conflict — тот же readiness_ref с
 * другой записью; suspended — знак приостановлен оператором, записи нет (409 READINESS_SUSPENDED).
 */
export type ReadinessPut = "inserted" | "replayed" | "conflict" | "suspended";

/** Хранилище записей знака; сбой — исключение (→ 503). */
export interface ReadinessStore {
  /** Повтор проверяется до приостановления: повтор той же записи — replayed и при SUSPENDED. */
  putAcquirer(rec: StoredAcquirerReadiness): Promise<ReadinessPut>;
  /** Действие оператора — всегда новая запись. */
  putOperator(rec: OperatorReadiness): Promise<void>;
  /** Статус знака; неизвестный продавец — NONE с since: null. */
  current(merchant_id: string): Promise<ReadinessView>;
}

/** Последняя запись источника для расчёта статуса. */
export interface Last {
  readonly seq: number;
  readonly status: string;
  readonly reason: ReadinessSuspendReason | null;
  readonly received_at: string;
}

/** Статус в два шага (РП57 п. 2): не зависит от взаимного порядка записей эквайрера и оператора. */
export function readinessOf(merchant_id: string, acquirer: Last | undefined, operator: Last | undefined): ReadinessView {
  if (operator?.status === "SUSPENDED") {
    return { merchant_id, status: "SUSPENDED", since: operator.received_at, ...(operator.reason ? { reason: operator.reason } : {}) };
  }
  const status: ReadinessStatus = acquirer?.status === "ACTIVE" ? "ACTIVE" : "NONE";
  const latest = [acquirer, operator].filter((r): r is Last => r !== undefined).sort((a, b) => b.seq - a.seq)[0];
  return { merchant_id, status, since: latest?.received_at ?? null };
}

/** Ответ продавцу и агенту — без причины приостановления (РП57 п. 3). */
export const publicReadiness = (v: ReadinessView): ReadinessView => ({ merchant_id: v.merchant_id, status: v.status, since: v.since });

const BODY_FIELDS = ["issued_at", "kid", "participant_code", "readiness_ref", "signature", "status"].join(",");

/**
 * Тело POST /participants/v1/merchants/{id}/readiness: ровно поля записи без merchant_id (он в пути) и подпись; лишнее
 * поле не подписано — отказ, а не пропуск. Разбор — новый объект (снимок, Р-205).
 */
export function readinessBody(merchant_id: string, v: unknown): { record: ReadinessSignedRecord; signature: string } | undefined {
  if (!isMerchantId(merchant_id) || typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== BODY_FIELDS) return undefined;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "issued_at"].every(str)) return undefined;
  if (typeof o.readiness_ref !== "string" || !READINESS_REF.test(o.readiness_ref)) return undefined;
  if (o.status !== "ACTIVE" && o.status !== "WITHDRAWN") return undefined;
  if (typeof o.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(o.signature) || Number.isNaN(parseRfc3339(o.issued_at))) return undefined;
  return {
    record: {
      participant_code: o.participant_code as string,
      kid: o.kid as string,
      merchant_id,
      readiness_ref: o.readiness_ref,
      status: o.status,
      issued_at: o.issued_at as string,
    },
    signature: o.signature,
  };
}

/** Та же запись: реквизиты и подпись (Ed25519 детерминирована — повтор эквайрера даёт ту же подпись). */
const sameRecord = (a: StoredAcquirerReadiness, b: StoredAcquirerReadiness): boolean =>
  a.participant_code === b.participant_code &&
  a.kid === b.kid &&
  a.merchant_id === b.merchant_id &&
  a.readiness_ref === b.readiness_ref &&
  a.status === b.status &&
  a.issued_at === b.issued_at &&
  a.signature === b.signature;

type MemoryRow =
  | { readonly seq: number; readonly source: "ACQUIRER"; readonly rec: StoredAcquirerReadiness }
  | { readonly seq: number; readonly source: "OPERATOR"; readonly rec: OperatorReadiness };

export class MemoryReadinessStore implements ReadinessStore {
  readonly #rows: MemoryRow[] = [];

  async putAcquirer(rec: StoredAcquirerReadiness): Promise<ReadinessPut> {
    const same = this.#rows.find(
      (r) => r.source === "ACQUIRER" && r.rec.participant_code === rec.participant_code && r.rec.readiness_ref === rec.readiness_ref,
    );
    if (same) return sameRecord(same.rec as StoredAcquirerReadiness, rec) ? "replayed" : "conflict";
    if (this.#last(rec.merchant_id, "OPERATOR")?.status === "SUSPENDED") return "suspended";
    this.#rows.push({ seq: this.#rows.length + 1, source: "ACQUIRER", rec: structuredClone(rec) });
    return "inserted";
  }

  async putOperator(rec: OperatorReadiness): Promise<void> {
    this.#rows.push({ seq: this.#rows.length + 1, source: "OPERATOR", rec: structuredClone(rec) });
  }

  async current(merchant_id: string): Promise<ReadinessView> {
    return readinessOf(merchant_id, this.#last(merchant_id, "ACQUIRER"), this.#last(merchant_id, "OPERATOR"));
  }

  #last(merchant_id: string, source: MemoryRow["source"]): Last | undefined {
    for (let i = this.#rows.length - 1; i >= 0; i--) {
      const r = this.#rows[i]!;
      if (r.source !== source || r.rec.merchant_id !== merchant_id) continue;
      return r.source === "ACQUIRER"
        ? { seq: r.seq, status: r.rec.status, reason: null, received_at: r.rec.received_at }
        : { seq: r.seq, status: r.rec.action, reason: r.rec.reason, received_at: r.rec.received_at };
    }
    return undefined;
  }
}

interface LastRow extends Record<string, unknown> {
  seq: string;
  source: "ACQUIRER" | "OPERATOR";
  status: string;
  reason: ReadinessSuspendReason | null;
  received_at: string;
}

interface AcquirerRow extends Record<string, unknown> {
  participant_code: string;
  kid: string;
  merchant_id: string;
  readiness_ref: string;
  status: "ACTIVE" | "WITHDRAWN";
  issued_at: string;
  signature: string;
  received_at: string;
}

/**
 * Записи знака на PostgreSQL. Вставка эквайрера — одним оператором: только если последняя запись оператора не
 * SUSPENDED; ON CONFLICT по (participant_code, readiness_ref) — сверка с записанной. Запись эквайрера, легшая в гонке с
 * приостановлением на другом экземпляре, статус не меняет: статус считается в два шага (РП57 п. 2, остаточный риск 5).
 */
export class PgReadinessStore implements ReadinessStore {
  constructor(private readonly client: SqlClient) {}

  async putAcquirer(rec: StoredAcquirerReadiness): Promise<ReadinessPut> {
    const ins = await this.client.query(
      `INSERT INTO merchant_readiness (merchant_id, source, status, participant_code, kid, readiness_ref, issued_at, signature, received_at)
       SELECT $1, 'ACQUIRER', $2, $3, $4, $5, $6, $7, $8
        WHERE (SELECT status FROM merchant_readiness WHERE merchant_id = $1 AND source = 'OPERATOR' ORDER BY seq DESC LIMIT 1)
              IS DISTINCT FROM 'SUSPENDED'
       ON CONFLICT (participant_code, readiness_ref) DO NOTHING
       RETURNING seq`,
      [rec.merchant_id, rec.status, rec.participant_code, rec.kid, rec.readiness_ref, rec.issued_at, rec.signature, rec.received_at],
    );
    if (ins.rows.length === 1) return "inserted";
    const r = await this.client.query<AcquirerRow>(
      `SELECT participant_code, kid, merchant_id, readiness_ref, status, issued_at, signature, received_at
         FROM merchant_readiness WHERE source = 'ACQUIRER' AND participant_code = $1 AND readiness_ref = $2`,
      [rec.participant_code, rec.readiness_ref],
    );
    const same = r.rows[0];
    if (!same) return "suspended";
    return sameRecord(same, rec) ? "replayed" : "conflict";
  }

  async putOperator(rec: OperatorReadiness): Promise<void> {
    await this.client.query(
      `INSERT INTO merchant_readiness (merchant_id, source, status, reason, received_at) VALUES ($1, 'OPERATOR', $2, $3, $4)`,
      [rec.merchant_id, rec.action, rec.reason, rec.received_at],
    );
  }

  async current(merchant_id: string): Promise<ReadinessView> {
    const r = await this.client.query<LastRow>(
      `SELECT DISTINCT ON (source) seq, source, status, reason, received_at
         FROM merchant_readiness WHERE merchant_id = $1 ORDER BY source, seq DESC`,
      [merchant_id],
    );
    const last = (source: LastRow["source"]): Last | undefined => {
      const row = r.rows.find((x) => x.source === source);
      return row && { seq: Number(row.seq), status: row.status, reason: row.reason, received_at: row.received_at };
    };
    return readinessOf(merchant_id, last("ACQUIRER"), last("OPERATOR"));
  }
}
