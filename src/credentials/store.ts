// Хранилище П5 (РП47 п. 10): записи токенов и реквизитов. В памяти (dev без базы, стенд) и на PostgreSQL
// (sql/108_agent_credentials.sql). Значения криптограммы и номера карты нет (инвариант 1).
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { CredentialRecord, TokenRecord } from "./model.js";

/** Сбой любого метода — исключение (→ STATE_UNAVAILABLE). */
export interface CredentialStore {
  /** Токен мандата CART; нет — undefined. */
  tokenByMandate(mandate_id: string): Promise<TokenRecord | undefined>;
  tokenByRef(token_ref: string): Promise<TokenRecord | undefined>;
  /** Атомарно: токена у мандата нет — записать; есть — вернуть записанный (одновременный выпуск с другого экземпляра). */
  putToken(rec: TokenRecord): Promise<TokenRecord>;
  /** Реквизит заказа (РП47 п. 5): ключ — агент, CART, order_ref. */
  credentialByOrder(agent_code: string, mandate_id: string, order_ref: string): Promise<CredentialRecord | undefined>;
  /** Атомарно: реквизита заказа нет — записать; есть — вернуть записанный. */
  putCredential(rec: CredentialRecord): Promise<CredentialRecord>;
  /**
   * Реквизит агента по credential_ref (GET /pao/v1/credentials/{ref}, РП49 (г)) — одним запросом по паре: чужой для
   * хранилища — «не найдено», как неизвестный (тот же путь и то же время ответа); нет — undefined.
   */
  credentialByRef(credential_ref: string, agent_code: string): Promise<CredentialRecord | undefined>;
  /** Реквизит по токену и SHA-256 криптограммы (ADP п. 4); нет — undefined. */
  credentialByCryptogram(token_ref: string, cryptogram_sha256: string): Promise<CredentialRecord | undefined>;
  /**
   * Погашение ISSUED → USED с op_ref условной записью (РП47 п. 8): true — погасил этот вызов; false — уже погашен.
   * Из одновременных погашений (в том числе с разных экземпляров) проходит ровно одно (A3 п. 4.4).
   */
  consume(credential_ref: string, op_ref: string): Promise<boolean>;
}

const orderKey = (agent_code: string, mandate_id: string, order_ref: string): string =>
  JSON.stringify([agent_code, mandate_id, order_ref]);

export class MemoryCredentialStore implements CredentialStore {
  readonly #tokens = new Map<string, TokenRecord>();
  readonly #tokenByMandate = new Map<string, string>();
  readonly #credentials = new Map<string, CredentialRecord>();
  readonly #byOrder = new Map<string, string>();
  readonly #byCryptogram = new Map<string, string>();

  async tokenByMandate(mandate_id: string): Promise<TokenRecord | undefined> {
    const ref = this.#tokenByMandate.get(mandate_id);
    return ref === undefined ? undefined : this.tokenByRef(ref);
  }

  async tokenByRef(token_ref: string): Promise<TokenRecord | undefined> {
    const t = this.#tokens.get(token_ref);
    return t && structuredClone(t);
  }

  async putToken(rec: TokenRecord): Promise<TokenRecord> {
    const prior = this.#tokenByMandate.get(rec.mandate_id);
    if (prior !== undefined) return structuredClone(this.#tokens.get(prior) as TokenRecord);
    if (this.#tokens.has(rec.token_ref)) throw new Error("agent_tokens: token_ref уже записан");
    this.#tokens.set(rec.token_ref, structuredClone(rec));
    this.#tokenByMandate.set(rec.mandate_id, rec.token_ref);
    return structuredClone(rec);
  }

  async credentialByOrder(agent_code: string, mandate_id: string, order_ref: string): Promise<CredentialRecord | undefined> {
    const ref = this.#byOrder.get(orderKey(agent_code, mandate_id, order_ref));
    const c = ref === undefined ? undefined : this.#credentials.get(ref);
    return c && structuredClone(c);
  }

  async putCredential(rec: CredentialRecord): Promise<CredentialRecord> {
    const key = orderKey(rec.agent_code, rec.mandate_id, rec.order_ref);
    const prior = this.#byOrder.get(key);
    if (prior !== undefined) return structuredClone(this.#credentials.get(prior) as CredentialRecord);
    const ck = JSON.stringify([rec.token_ref, rec.cryptogram_sha256]);
    if (this.#credentials.has(rec.credential_ref) || this.#byCryptogram.has(ck)) {
      throw new Error("agent_credentials: credential_ref или криптограмма уже записаны");
    }
    this.#credentials.set(rec.credential_ref, structuredClone(rec));
    this.#byOrder.set(key, rec.credential_ref);
    this.#byCryptogram.set(ck, rec.credential_ref);
    return structuredClone(rec);
  }

  async credentialByRef(credential_ref: string, agent_code: string): Promise<CredentialRecord | undefined> {
    const c = this.#credentials.get(credential_ref);
    return c && c.agent_code === agent_code ? structuredClone(c) : undefined;
  }

  async credentialByCryptogram(token_ref: string, cryptogram_sha256: string): Promise<CredentialRecord | undefined> {
    const ref = this.#byCryptogram.get(JSON.stringify([token_ref, cryptogram_sha256]));
    const c = ref === undefined ? undefined : this.#credentials.get(ref);
    return c && structuredClone(c);
  }

  /** Проверка и запись без await между ними: один процесс — одна очередь. */
  async consume(credential_ref: string, op_ref: string): Promise<boolean> {
    const c = this.#credentials.get(credential_ref);
    if (!c || c.status !== "ISSUED") return false;
    this.#credentials.set(credential_ref, { ...c, status: "USED", op_ref });
    return true;
  }
}

interface TokenRow extends Record<string, unknown> {
  token_ref: string;
  agent_code: string;
  mandate_id: string;
  merchant_scope: string[];
  valid_to: string;
  funding_ref: string;
  created_at: string;
}

interface CredentialRow extends Record<string, unknown> {
  credential_ref: string;
  agent_code: string;
  mandate_id: string;
  token_ref: string;
  order_ref: string;
  merchant_id: string;
  amount_max: string;
  currency: string;
  valid_to: string;
  cryptogram_sha256: string;
  status: CredentialRecord["status"];
  op_ref: string | null;
  created_at: string;
}

const TOKEN_COLS = "token_ref, agent_code, mandate_id, merchant_scope, valid_to, funding_ref, created_at";
const CREDENTIAL_COLS =
  "credential_ref, agent_code, mandate_id, token_ref, order_ref, merchant_id, amount_max, currency, valid_to, cryptogram_sha256, status, op_ref, created_at";

/** bigint приходит строкой: вне точного диапазона — не подтверждено (инвариант 3), а не округление. */
function credentialOf(row: CredentialRow): CredentialRecord {
  const amount_max = Number(row.amount_max);
  if (!Number.isSafeInteger(amount_max)) throw new Error("agent_credentials: amount_max вне точного диапазона");
  return { ...row, amount_max, currency: row.currency.trim(), cryptogram_sha256: row.cryptogram_sha256.trim() };
}

/**
 * Хранилище П5 на PostgreSQL (sql/108_agent_credentials.sql). Запись токена и реквизита — INSERT … ON CONFLICT DO NOTHING
 * по уникальным ключам, затем чтение записанного: одновременная выдача с двух экземпляров даёт одну строку. Погашение —
 * один условный UPDATE … WHERE status = 'ISSUED': из одновременных проходит ровно один (РП47 п. 8); триггер не даёт
 * вернуть USED в ISSUED и изменить ключевые поля.
 */
export class PgCredentialStore implements CredentialStore {
  constructor(private readonly client: SqlClient) {}

  async tokenByMandate(mandate_id: string): Promise<TokenRecord | undefined> {
    const r = await this.client.query<TokenRow>(`SELECT ${TOKEN_COLS} FROM agent_tokens WHERE mandate_id = $1`, [mandate_id]);
    return r.rows[0];
  }

  async tokenByRef(token_ref: string): Promise<TokenRecord | undefined> {
    const r = await this.client.query<TokenRow>(`SELECT ${TOKEN_COLS} FROM agent_tokens WHERE token_ref = $1`, [token_ref]);
    return r.rows[0];
  }

  async putToken(rec: TokenRecord): Promise<TokenRecord> {
    await this.client.query(
      `INSERT INTO agent_tokens (${TOKEN_COLS}) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ON CONFLICT (mandate_id) DO NOTHING`,
      [rec.token_ref, rec.agent_code, rec.mandate_id, JSON.stringify(rec.merchant_scope), rec.valid_to, rec.funding_ref, rec.created_at],
    );
    const t = await this.tokenByMandate(rec.mandate_id);
    if (!t) throw new Error("agent_tokens: токен мандата не найден после вставки");
    return t;
  }

  async credentialByOrder(agent_code: string, mandate_id: string, order_ref: string): Promise<CredentialRecord | undefined> {
    const r = await this.client.query<CredentialRow>(
      `SELECT ${CREDENTIAL_COLS} FROM agent_credentials WHERE agent_code = $1 AND mandate_id = $2 AND order_ref = $3`,
      [agent_code, mandate_id, order_ref],
    );
    return r.rows[0] && credentialOf(r.rows[0]);
  }

  async putCredential(rec: CredentialRecord): Promise<CredentialRecord> {
    await this.client.query(
      `INSERT INTO agent_credentials (${CREDENTIAL_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (agent_code, mandate_id, order_ref) DO NOTHING`,
      [
        rec.credential_ref,
        rec.agent_code,
        rec.mandate_id,
        rec.token_ref,
        rec.order_ref,
        rec.merchant_id,
        rec.amount_max,
        rec.currency,
        rec.valid_to,
        rec.cryptogram_sha256,
        rec.status,
        rec.op_ref,
        rec.created_at,
      ],
    );
    const c = await this.credentialByOrder(rec.agent_code, rec.mandate_id, rec.order_ref);
    if (!c) throw new Error("agent_credentials: реквизит заказа не найден после вставки");
    return c;
  }

  async credentialByRef(credential_ref: string, agent_code: string): Promise<CredentialRecord | undefined> {
    const r = await this.client.query<CredentialRow>(
      `SELECT ${CREDENTIAL_COLS} FROM agent_credentials WHERE credential_ref = $1 AND agent_code = $2`,
      [credential_ref, agent_code],
    );
    return r.rows[0] && credentialOf(r.rows[0]);
  }

  async credentialByCryptogram(token_ref: string, cryptogram_sha256: string): Promise<CredentialRecord | undefined> {
    const r = await this.client.query<CredentialRow>(
      `SELECT ${CREDENTIAL_COLS} FROM agent_credentials WHERE token_ref = $1 AND cryptogram_sha256 = $2`,
      [token_ref, cryptogram_sha256],
    );
    return r.rows[0] && credentialOf(r.rows[0]);
  }

  async consume(credential_ref: string, op_ref: string): Promise<boolean> {
    const r = await this.client.query(
      "UPDATE agent_credentials SET status = 'USED', op_ref = $2 WHERE credential_ref = $1 AND status = 'ISSUED' RETURNING credential_ref",
      [credential_ref, op_ref],
    );
    return r.rows.length === 1;
  }
}
