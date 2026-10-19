// Запись операции ADP (РП43 п. 5): op_ref → решение и удержания. По ней — идемпотентность ПИ-1 и закрепление и
// освобождение по событиям ПИ-3 (PS-16). В памяти (dev без базы, стенд) и на PostgreSQL (sql/103_adp_operations.sql).
// BYPASS не пишется. Окно дробления (РП44 п. 4) — столбцы той же записи (sql/104_adp_split_window.sql).
import { createHash } from "node:crypto";
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

/** Вход операции в окно дробления (РП44 п. 4): ключ — корневой INTENT, сумма парой с валютой, время — часы Платформы. */
export interface WindowEntry {
  readonly key: string;
  readonly amount: number;
  readonly currency: string;
  readonly at_ms: number;
}

/** Правило доли (РП44 п. 1): в окне после since_ms вместе с операцией ≥ min_ops и сумма > threshold. */
export interface WindowRule {
  readonly since_ms: number;
  readonly threshold: number;
  readonly min_ops: number;
}

/** Итог входа: entered = false — доля, в окно не вошла; ops и sum — вместе с операцией. */
export interface WindowResult {
  readonly entered: boolean;
  readonly ops: number;
  readonly sum: number;
}

/** В окне — одобрения и записи «в работе», вошедшие в окно; отказ решением убирает запись фильтром (РП44 п. 2). */
const counts = (decision: Decision | null): boolean => decision === null || decision.decision === "APPROVE";

const isSplit = (ops: number, sum: number, rule: WindowRule): boolean => ops >= rule.min_ops && sum > rule.threshold;

/** Хранилище записей операций; сбой — исключение (→ STATE_UNAVAILABLE до резерва, после — журнал процесса). */
export interface OperationStore {
  /**
   * Атомарно: записи по op_ref нет — создать «в работе» и вернуть undefined; есть — вернуть её, не меняя. Только первый
   * из одновременных запросов (в том числе на разных экземплярах — условная вставка на PG, часть 2) проходит к резерву.
   */
  begin(op_ref: string, msg_hash: string, at: string): Promise<OperationRecord | undefined>;
  /** Решение по записи «в работе». */
  finish(rec: OperationRecord): Promise<void>;
  /**
   * Атомарно по ключу окна: прочитать число и сумму окна; не доля — записать вход своей записи «в работе» (один раз).
   * Одновременные входы по одному ключу — по очереди, в том числе с разных экземпляров (РП44 п. 4). Сбой — исключение.
   */
  enterWindow(op_ref: string, entry: WindowEntry, rule: WindowRule): Promise<WindowResult>;
}

export class MemoryOperationStore implements OperationStore {
  readonly #map = new Map<string, OperationRecord>();
  /** Входы окна по op_ref: заполняются один раз, решение их не меняет (как столбцы окна на PG). */
  readonly #window = new Map<string, WindowEntry>();

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

  /** Проверка и запись без await между ними: один процесс — одна очередь (РП44 п. 4). */
  async enterWindow(op_ref: string, entry: WindowEntry, rule: WindowRule): Promise<WindowResult> {
    const own = this.#map.get(op_ref);
    if (!own || own.decision !== null || this.#window.has(op_ref)) throw new Error("adp_operations: вход в окно не у записи «в работе»");
    let ops = 1;
    let sum = entry.amount;
    for (const [ref, w] of this.#window) {
      if (w.key !== entry.key || w.at_ms <= rule.since_ms || !counts(this.#map.get(ref)?.decision ?? null)) continue;
      if (w.currency !== entry.currency) throw new Error("adp_operations: окно в разных валютах");
      ops++;
      sum += w.amount;
    }
    const entered = !isSplit(ops, sum, rule);
    if (entered) this.#window.set(op_ref, { ...entry });
    return { entered, ops, sum };
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
  constructor(
    private readonly client: TxSqlClient,
    private readonly hooks: PgOperationHooks = {},
  ) {}

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

  /**
   * Транзакция (РП44 п. 4): блокировка ключа окна, чтение окна — уже после неё (снимок READ COMMITTED берётся на
   * каждый оператор), запись своей строки «в работе», COMMIT. Резерв ядра — после COMMIT: блокировка через вызов ядра
   * не держится.
   */
  async enterWindow(op_ref: string, entry: WindowEntry, rule: WindowRule): Promise<WindowResult> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      await tx.query("BEGIN");
      try {
        const r = await tx.query<{ ops: string; sum: string | null; currencies: string }>(
          `SELECT count(*) AS ops, sum(amount) AS sum, count(*) FILTER (WHERE currency <> $3) AS currencies
             FROM adp_operations
            WHERE window_key = $1 AND window_at_ms > $2 AND op_ref <> $4
              AND (decision IS NULL OR decision->>'decision' = 'APPROVE')`,
          [entry.key, rule.since_ms, entry.currency, op_ref],
        );
        const row = r.rows[0];
        if (!row) throw new Error("adp_operations: окно не прочитано");
        if (Number(row.currencies) !== 0) throw new Error("adp_operations: окно в разных валютах");
        const ops = Number(row.ops) + 1;
        const sum = Number(row.sum ?? 0) + entry.amount;
        if (!Number.isSafeInteger(sum)) throw new Error("adp_operations: сумма окна вне точного диапазона");
        await this.hooks.windowRead?.(op_ref);
        const entered = !isSplit(ops, sum, rule);
        if (entered) {
          const u = await tx.query(
            `UPDATE adp_operations SET window_key = $2, amount = $3, currency = $4, window_at_ms = $5
              WHERE op_ref = $1 AND decision IS NULL AND window_key IS NULL RETURNING op_ref`,
            [op_ref, entry.key, entry.amount, entry.currency, entry.at_ms],
          );
          if (u.rows.length !== 1) throw new Error("adp_operations: вход в окно не у записи «в работе»");
        }
        await tx.query("COMMIT");
        return { entered, ops, sum };
      } catch (err) {
        // Соединение, на котором не прошёл ROLLBACK, в пул не возвращается (как запись журнала с событием, РП39).
        await tx.query("ROLLBACK").catch((rb: unknown) => {
          broken = rb instanceof Error ? rb : new Error(String(rb));
        });
        throw err;
      }
    } finally {
      tx.release(broken);
    }
  }
}

/** Пул: транзакция окна — на своём соединении. pg.Pool подходит без обёртки. */
export interface TxSqlClient extends SqlClient {
  connect(): Promise<SqlClient & { release(err?: Error | boolean): void }>;
}

/** Точка внутри транзакции окна — только для тестов: после чтения окна, до записи входа (гонка двух экземпляров). */
export interface PgOperationHooks {
  readonly windowRead?: (op_ref: string) => Promise<void>;
}

const SPLIT_WINDOW_LOCK_DOMAIN = "adp:split-window-lock:v1";

/** Ключ pg_advisory_xact_lock окна: 64 бита SHA-256 со знаком, десятичной строкой (как ключ ленты событий, РП39 п. 2). */
export function splitWindowLockKey(window_key: string): string {
  return createHash("sha256").update(`${SPLIT_WINDOW_LOCK_DOMAIN}\n${window_key}`, "utf8").digest().readBigInt64BE(0).toString();
}
