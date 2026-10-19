// Запись операции ADP (РП43 п. 5): op_ref → решение и удержания. По ней — идемпотентность ПИ-1 и закрепление и
// освобождение по событиям ПИ-3 (PS-16). В части 1 — в памяти, на PostgreSQL — PS-10 часть 2. BYPASS не пишется.
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
