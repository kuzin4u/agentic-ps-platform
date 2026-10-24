// П10 Метаданные пакета агентской оплаты и сверка credential_ref → op_ref (РП22 п. 6, РП57 п. 5): эквайрер за своего
// продавца присылает подписанную запись (ПИ-8), только вставкой; ответ — сверка по записи реквизита П5, op_ref — результат,
// а не вход. Решение ADP от метаданных не зависит. В памяти (стенд, тесты) и на PostgreSQL (sql/119_payment_metadata.sql).
// Номера карты, суммы и криптограммы нет (инварианты 1, 5).
import type { SqlClient } from "@kuzin4u/agentic-core";
import { issuedBeforeSuspension } from "../adp/decide.js";
import { parseRfc3339 } from "../consent/model.js";
import type { CredentialRecord } from "../credentials/model.js";
import { isMerchantId, type PaymentMetadataSignedRecord } from "./trusted.js";

/** Ссылка записи эквайрера — как в processing-interface.yaml. */
export const METADATA_REF = /^[A-Za-z0-9_-]{1,64}$/;
/** credential_ref и order_ref — до 128 знаков (как в ПАО, processing-interface.yaml). */
export const PAYMENT_REF_MAX = 128;
export const isPaymentRef = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= PAYMENT_REF_MAX;

/**
 * Маска credential_ref для журнала процесса (РП57 доп. 5 (г)): первые и последние 4 знака и длина; короче 12 — только
 * длина. Полная ссылка в журнал не попадает: по ней продавец опознаёт заказ.
 */
export const maskRef = (ref: string): string => (ref.length < 12 ? `…(${ref.length})` : `${ref.slice(0, 4)}…${ref.slice(-4)}(${ref.length})`);

/** Запись в хранилище: подпись — доказательство, received_at — часы Платформы. */
export interface StoredPaymentMetadata extends PaymentMetadataSignedRecord {
  readonly signature: string;
  readonly received_at: string;
}

export type ReconciliationResult = "MATCHED" | "MISMATCH" | "PENDING" | "NOT_USED";
export type NotUsedReason = "EXPIRED" | "MANDATE_REVOKED" | "AGENT_SUSPENDED";
export type MismatchField = "order_ref" | "aoi.agent_code" | "aoi.mandate_id";

/** Ответ сверки (PaymentReconciliation, РП57 п. 5). */
export interface PaymentReconciliation {
  readonly credential_ref: string;
  readonly result: ReconciliationResult;
  readonly aoi_checked: boolean;
  readonly op_ref?: string;
  readonly fields?: readonly MismatchField[];
  readonly reason?: NotUsedReason;
}

export interface ReconcileDeps {
  readonly credentials: { credentialForMerchant(credential_ref: string, merchant_id: string): Promise<CredentialRecord | undefined> };
  /** Статус мандата реквизита по свёртке журнала (в том числе метка revoke-all); нет — undefined. */
  readonly mandateStatus: (mandate_id: string, agent_code: string) => Promise<string | undefined>;
  /** Последнее приостановление агента из реестра (РП54 п. 5); не приостанавливался — null. */
  readonly suspendedAt: (agent_code: string) => string | null | undefined;
  readonly now: () => Date;
}

/**
 * Сверка метаданных с записью реквизита. Реквизита нет или он другого продавца — undefined (404 CREDENTIAL_NOT_FOUND).
 * Порядок: несовпадение сравниваемых полей — MISMATCH при любом статусе реквизита (метаданные расходятся с записью
 * Платформы); погашен — MATCHED с op_ref; не погашен — NOT_USED (MANDATE_REVOKED → AGENT_SUSPENDED → EXPIRED) или PENDING.
 * Состояние операции (реверсал, возврат) в ответ не входит: сверка отвечает, какой операцией погашен реквизит.
 */
export async function reconcile(deps: ReconcileDeps, rec: PaymentMetadataSignedRecord): Promise<PaymentReconciliation | undefined> {
  const cred = await deps.credentials.credentialForMerchant(rec.credential_ref, rec.merchant_id);
  if (!cred) return undefined;
  const aoi_checked = rec.aoi !== undefined;
  const base = { credential_ref: rec.credential_ref, aoi_checked };
  const fields: MismatchField[] = [];
  if (rec.order_ref !== cred.order_ref) fields.push("order_ref");
  if (rec.aoi && rec.aoi.agent_code !== cred.agent_code) fields.push("aoi.agent_code");
  if (rec.aoi && rec.aoi.mandate_id !== cred.mandate_id) fields.push("aoi.mandate_id");
  if (fields.length > 0) return { ...base, result: "MISMATCH", fields };
  if (cred.status === "USED" && cred.op_ref) return { ...base, result: "MATCHED", op_ref: cred.op_ref };
  // ISSUED: погашения ещё не было. Не будет — NOT_USED с настоящей причиной (РП57 доп. 5 (б), решение владельца):
  // отзыв мандата → приостановление агента → истечение срока; иначе PENDING (не дольше valid_to — «вечного» нет).
  const status = await deps.mandateStatus(cred.mandate_id, cred.agent_code);
  if (status === undefined) throw new Error(`сверка: мандат ${cred.mandate_id} реквизита ${cred.credential_ref} не найден`);
  if (status === "REVOKED") return { ...base, result: "NOT_USED", reason: "MANDATE_REVOKED" };
  if (issuedBeforeSuspension(cred.created_at, deps.suspendedAt(cred.agent_code))) {
    return { ...base, result: "NOT_USED", reason: "AGENT_SUSPENDED" };
  }
  if (!(deps.now().getTime() < parseRfc3339(cred.valid_to))) return { ...base, result: "NOT_USED", reason: "EXPIRED" };
  return { ...base, result: "PENDING" };
}

const BODY_FIELDS = ["credential_ref", "kid", "metadata_ref", "order_ref", "participant_code", "signature", "submitted_at"];

/**
 * Тело POST /participants/v1/merchants/{id}/payments: ровно поля записи без merchant_id (он в пути), подпись и
 * необязательный aoi — ровно {agent_code, mandate_id}; лишнее поле не подписано — отказ. Разбор — новый объект (Р-205).
 */
export function paymentMetadataBody(merchant_id: string, v: unknown): { record: PaymentMetadataSignedRecord; signature: string } | undefined {
  if (!isMerchantId(merchant_id) || typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  const withAoi = [...BODY_FIELDS, "aoi"].sort().join(",");
  if (keys !== BODY_FIELDS.join(",") && keys !== withAoi) return undefined;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "submitted_at"].every(str)) return undefined;
  if (typeof o.metadata_ref !== "string" || !METADATA_REF.test(o.metadata_ref)) return undefined;
  if (!isPaymentRef(o.credential_ref) || !isPaymentRef(o.order_ref)) return undefined;
  if (typeof o.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(o.signature) || Number.isNaN(parseRfc3339(o.submitted_at))) return undefined;
  let aoi: PaymentMetadataSignedRecord["aoi"];
  if (o.aoi !== undefined) {
    const a = o.aoi;
    if (typeof a !== "object" || a === null || Array.isArray(a)) return undefined;
    const ao = a as Record<string, unknown>;
    if (Object.keys(ao).sort().join(",") !== "agent_code,mandate_id") return undefined;
    if (!isPaymentRef(ao.agent_code) || !isPaymentRef(ao.mandate_id)) return undefined;
    aoi = { agent_code: ao.agent_code, mandate_id: ao.mandate_id };
  }
  return {
    record: {
      participant_code: o.participant_code as string,
      kid: o.kid as string,
      merchant_id,
      metadata_ref: o.metadata_ref,
      credential_ref: o.credential_ref,
      order_ref: o.order_ref,
      ...(aoi ? { aoi } : {}),
      submitted_at: o.submitted_at as string,
    },
    signature: o.signature,
  };
}

export type MetadataPut = "inserted" | "replayed" | "conflict";

/** Хранилище метаданных; сбой — исключение (→ 503). */
export interface PaymentMetadataStore {
  /** Только вставка: та же запись — replayed; тот же metadata_ref с другой записью — conflict. */
  put(rec: StoredPaymentMetadata): Promise<MetadataPut>;
  /** Последняя по порядку записи запись метаданных реквизита у продавца; нет — undefined. */
  latest(merchant_id: string, credential_ref: string): Promise<StoredPaymentMetadata | undefined>;
}

const sameAoi = (a: PaymentMetadataSignedRecord["aoi"], b: PaymentMetadataSignedRecord["aoi"]): boolean =>
  a === undefined || b === undefined ? a === b : a.agent_code === b.agent_code && a.mandate_id === b.mandate_id;

/** Та же запись: реквизиты и подпись (Ed25519 детерминирована — повтор даёт ту же подпись). */
const sameRecord = (a: StoredPaymentMetadata, b: StoredPaymentMetadata): boolean =>
  a.participant_code === b.participant_code &&
  a.kid === b.kid &&
  a.merchant_id === b.merchant_id &&
  a.metadata_ref === b.metadata_ref &&
  a.credential_ref === b.credential_ref &&
  a.order_ref === b.order_ref &&
  sameAoi(a.aoi, b.aoi) &&
  a.submitted_at === b.submitted_at &&
  a.signature === b.signature;

export class MemoryPaymentMetadataStore implements PaymentMetadataStore {
  readonly #rows: StoredPaymentMetadata[] = [];

  async put(rec: StoredPaymentMetadata): Promise<MetadataPut> {
    const same = this.#rows.find((r) => r.participant_code === rec.participant_code && r.metadata_ref === rec.metadata_ref);
    if (same) return sameRecord(same, rec) ? "replayed" : "conflict";
    this.#rows.push(structuredClone(rec));
    return "inserted";
  }

  async latest(merchant_id: string, credential_ref: string): Promise<StoredPaymentMetadata | undefined> {
    for (let i = this.#rows.length - 1; i >= 0; i--) {
      const r = this.#rows[i]!;
      if (r.merchant_id === merchant_id && r.credential_ref === credential_ref) return structuredClone(r);
    }
    return undefined;
  }
}

interface MetadataRow extends Record<string, unknown> {
  participant_code: string;
  kid: string;
  merchant_id: string;
  metadata_ref: string;
  credential_ref: string;
  order_ref: string;
  aoi: { agent_code: string; mandate_id: string } | null;
  submitted_at: string;
  signature: string;
  received_at: string;
}

const COLS = "participant_code, kid, merchant_id, metadata_ref, credential_ref, order_ref, aoi, submitted_at, signature, received_at";

const fromRow = (r: MetadataRow): StoredPaymentMetadata => ({
  participant_code: r.participant_code,
  kid: r.kid,
  merchant_id: r.merchant_id,
  metadata_ref: r.metadata_ref,
  credential_ref: r.credential_ref,
  order_ref: r.order_ref,
  ...(r.aoi ? { aoi: { agent_code: r.aoi.agent_code, mandate_id: r.aoi.mandate_id } } : {}),
  submitted_at: r.submitted_at,
  signature: r.signature,
  received_at: r.received_at,
});

/** Метаданные на PostgreSQL: вставка ON CONFLICT по (participant_code, metadata_ref) — затем сверка с записанной. */
export class PgPaymentMetadataStore implements PaymentMetadataStore {
  constructor(private readonly client: SqlClient) {}

  async put(rec: StoredPaymentMetadata): Promise<MetadataPut> {
    const ins = await this.client.query(
      `INSERT INTO payment_metadata (${COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
       ON CONFLICT (participant_code, metadata_ref) DO NOTHING RETURNING seq`,
      [
        rec.participant_code,
        rec.kid,
        rec.merchant_id,
        rec.metadata_ref,
        rec.credential_ref,
        rec.order_ref,
        rec.aoi ? JSON.stringify({ agent_code: rec.aoi.agent_code, mandate_id: rec.aoi.mandate_id }) : null,
        rec.submitted_at,
        rec.signature,
        rec.received_at,
      ],
    );
    if (ins.rows.length === 1) return "inserted";
    const r = await this.client.query<MetadataRow>(`SELECT ${COLS} FROM payment_metadata WHERE participant_code = $1 AND metadata_ref = $2`, [
      rec.participant_code,
      rec.metadata_ref,
    ]);
    const same = r.rows[0];
    return same && sameRecord(fromRow(same), rec) ? "replayed" : "conflict";
  }

  async latest(merchant_id: string, credential_ref: string): Promise<StoredPaymentMetadata | undefined> {
    const r = await this.client.query<MetadataRow>(
      `SELECT ${COLS} FROM payment_metadata WHERE merchant_id = $1 AND credential_ref = $2 ORDER BY seq DESC LIMIT 1`,
      [merchant_id, credential_ref],
    );
    return r.rows[0] && fromRow(r.rows[0]);
  }
}
