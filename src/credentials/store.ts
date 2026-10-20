// Хранилище П5 (РП47 п. 10): записи токенов и реквизитов. В памяти (dev без базы, стенд) и на PostgreSQL
// (sql/108_agent_credentials.sql). Значения криптограммы и номера карты нет (инвариант 1).
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
