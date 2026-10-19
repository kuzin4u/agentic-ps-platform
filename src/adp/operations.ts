// Запись операции ADP (РП43 п. 5): op_ref → решение и удержания. По ней — идемпотентность ПИ-1 и закрепление и
// освобождение по событиям ПИ-3 (PS-16). В памяти (dev без базы, стенд) и на PostgreSQL (sql/103_adp_operations.sql).
// BYPASS не пишется.
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { Decision } from "../shared/canonical.generated.js";

export interface OperationRecord {
  readonly op_ref: string;
  /** SHA-256 канонической записи сообщения: повтор с другим телом — инцидент (РП43 п. 5). */
  readonly msg_hash: string;
  /** null — операция в работе: запись создана до резерва, решения ещё нет (или его не удалось сохранить). */
  readonly decision: Decision | null;
  readonly mandate_id: string | null;
  /** hold.id по каждому счёту в порядке резерва: CART, затем родитель (РП43 п. 6). */
  readonly holds: readonly string[];
  readonly at: string;
}

/** Хранилище записей операций; сбой — исключение (→ STATE_UNAVAILABLE до резерва, после — журнал процесса). */
export interface OperationStore {
  /**
   * Атомарно: записи по op_ref нет — создать «в работе» и вернуть undefined; есть — вернуть её, не меняя. Только первый
   * из одновременных запросов (в том числе на разных экземплярах — условная вставка на PG, часть 2) проходит к резерву.
   */
  begin(op_ref: string, msg_hash: string, at: string): Promise<OperationRecord | undefined>;
  /** Решение по записи «в работе». */
  finish(rec: OperationRecord): Promise<void>;
}

export class MemoryOperationStore implements OperationStore {
  readonly #map = new Map<string, OperationRecord>();

  async begin(op_ref: string, msg_hash: string, at: string): Promise<OperationRecord | undefined> {
    const prior = this.#map.get(op_ref);
    if (prior) return structuredClone(prior);
    this.#map.set(op_ref, { op_ref, msg_hash, decision: null, mandate_id: null, holds: [], at });
    return undefined;
  }

  async finish(rec: OperationRecord): Promise<void> {
    const prior = this.#map.get(rec.op_ref);
    if (prior && prior.decision === null && prior.msg_hash === rec.msg_hash) this.#map.set(rec.op_ref, structuredClone(rec));
  }
}

interface OperationRow extends Record<string, unknown> {
  op_ref: string;
  msg_hash: string;
  decision: Decision | null;
  mandate_id: string | null;
  holds: string[];
  at: string;
}

/**
 * Записи операций на PostgreSQL (доп. РП43 п. 16): «в работе» — INSERT … ON CONFLICT DO NOTHING, один оператор, поэтому
 * из одновременных запросов с разных экземпляров к резерву проходит один. Решение — UPDATE только строки «в работе» с тем
 * же хэшем; решённую строку триггер не даёт изменить или удалить.
 */
export class PgOperationStore implements OperationStore {
  constructor(private readonly client: SqlClient) {}

  async begin(op_ref: string, msg_hash: string, at: string): Promise<OperationRecord | undefined> {
    const ins = await this.client.query(
      "INSERT INTO adp_operations (op_ref, msg_hash, at) VALUES ($1, $2, $3) ON CONFLICT (op_ref) DO NOTHING RETURNING op_ref",
      [op_ref, msg_hash, at],
    );
    if (ins.rows.length === 1) return undefined;
    const r = await this.client.query<OperationRow>(
      "SELECT op_ref, msg_hash, decision, mandate_id, holds, at FROM adp_operations WHERE op_ref = $1",
      [op_ref],
    );
    const row = r.rows[0];
    // Вставки не было, а строки нет — её быть не может (удаление запрещено): не подтверждено, без догадки.
    if (!row) throw new Error("adp_operations: запись по op_ref не найдена после конфликта вставки");
    return { ...row, msg_hash: row.msg_hash.trim() };
  }

  async finish(rec: OperationRecord): Promise<void> {
    await this.client.query(
      "UPDATE adp_operations SET decision = $2::jsonb, mandate_id = $3, holds = $4::jsonb WHERE op_ref = $1 AND decision IS NULL AND msg_hash = $5",
      [rec.op_ref, JSON.stringify(rec.decision), rec.mandate_id, JSON.stringify(rec.holds), rec.msg_hash],
    );
  }
}
