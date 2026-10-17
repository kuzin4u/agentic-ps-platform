// П2 Хранилище журнала согласий (PS-06 К1.2): PostgreSQL в sandbox, память ядра в dev и стенде (как РП30 п. 6).
// Записи — в core_journal ядра (PgJournalStore, цепочка на корневой мандат); индекс и предмет — sql/100_consent.sql.
// Ядро не открывает транзакций (каждая операция — одна команда), поэтому порядок записи такой: индекс, предмет,
// затем запись журнала. Запись журнала — источник истины: строка индекса без записи MANDATE_REQUESTED — мандата нет.
import {
  AsyncMemoryJournalStore,
  chainGenesis,
  PgJournalStore,
  type AsyncJournalStore,
  type SqlClient,
} from "@kuzin4u/agentic-core";

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

export interface ConsentStore {
  insertMandate(row: MandateIndexRow): Promise<void>;
  getMandate(id: string): Promise<MandateIndexRow | undefined>;
  insertSubject(row: MandateSubjectRow): Promise<void>;
  getSubject(mandateId: string): Promise<MandateSubjectRow | undefined>;
  /** Хранилище записей одной цепочки; начало цепочки привязано к её имени (chainGenesis, К6 п. 8). */
  journal(chain: string): AsyncJournalStore;
}

export class MemoryConsentStore implements ConsentStore {
  private readonly mandates = new Map<string, MandateIndexRow>();
  private readonly subjects = new Map<string, MandateSubjectRow>();
  private readonly chains = new Map<string, AsyncJournalStore>();

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
}

const UNIQUE_VIOLATION = "23505";

export class PgConsentStore implements ConsentStore {
  constructor(private readonly client: SqlClient) {}

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

  private async insert(id: string, sql: string, params: unknown[]): Promise<void> {
    try {
      await this.client.query(sql, params);
    } catch (err) {
      if ((err as { code?: string }).code === UNIQUE_VIOLATION) throw new ConsentRowConflict(id);
      throw err;
    }
  }
}
