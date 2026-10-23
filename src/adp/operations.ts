// Запись операции ADP (РП43 п. 5): op_ref → решение и удержания. По ней — идемпотентность ПИ-1 и закрепление и
// освобождение по событиям ПИ-3 (PS-16). В памяти (dev без базы, стенд) и на PostgreSQL (sql/103_adp_operations.sql).
// BYPASS не пишется. Окно дробления (РП44 п. 4) — столбцы той же записи (sql/104_adp_split_window.sql).
import { createHash } from "node:crypto";
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { Aoi, Decision } from "../shared/canonical.generated.js";

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
  /** Признаки для уведомителя участника (РП46 доп. п. 9 (о1)): пишутся тем же обновлением, что решение. */
  readonly notify?: OperationNotify;
  /** Факты операции для итога П8 (РП52 п. 9): тем же обновлением, что решение. */
  readonly facts?: OperationFacts;
}

/**
 * Факты операции из сообщения процессинга (инвариант 5) и агент по домену токена (РП52 п. 5, 9): только ссылки и коды,
 * сумма — парой с валютой; token_ref и криптограммы нет (инвариант 1).
 */
export interface OperationFacts {
  /** Агент по домену токена (запись Платформы), не из aoi; null — агент не установлен: итог без события. */
  readonly agent_code: string | null;
  readonly order_ref: string | null;
  /** null — канал не из перечня ПИ: не догадка (инвариант 3). */
  readonly channel: "CARD" | "SBP" | null;
  readonly merchant_id: string | null;
  readonly amount: number;
  readonly currency: string;
  /** Признак сообщения как пришёл (A1 п. 5.1); null — без признака. */
  readonly aoi: Aoi | null;
}

/**
 * Признаки записи операции для уведомлений клиента через банк (РП46 доп. п. 7, 9): клиент мандата, агент, чей предел у
 * LIMIT_EXCEEDED, счёт периода клиента и остаток после резерва. Только коды и ссылки (инвариант 1).
 */
export interface OperationNotify {
  readonly participant_code: string;
  readonly principal_ref: string;
  readonly agent_code: string;
  readonly limit_source?: LimitSource;
  readonly client_account?: string;
  readonly client_left_after?: number;
}

/**
 * Чей предел сработал у LIMIT_EXCEEDED: мандата (в том числе родителя CART), лимита клиента или инструмента — amount_max
 * реквизита (РП49 (е)).
 */
export type LimitSource = "MANDATE" | "CLIENT" | "INSTRUMENT";

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

/** Чтение записи операции по op_ref — для ПИ-3 и GET операции (РП52 п. 8, 10); нет — undefined, сбой — исключение. */
export interface OperationReader {
  get(op_ref: string): Promise<OperationRecord | undefined> | OperationRecord | undefined;
}

/**
 * Записи операций по мандату — для GET /pao/v1/operations?mandate_id (РП55 п. 6): mandate_id записи равен запрошенному,
 * по времени записи (at, затем op_ref), не больше limit; сбой — исключение.
 */
export interface OperationsByMandate {
  byMandate(mandate_id: string, limit: number): Promise<readonly OperationRecord[]>;
}

const byTime = (a: OperationRecord, b: OperationRecord): number => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.op_ref < b.op_ref ? -1 : a.op_ref > b.op_ref ? 1 : 0);

export class MemoryOperationStore implements OperationStore, OperationsByMandate {
  readonly #map = new Map<string, OperationRecord>();
  /** Входы окна по op_ref: заполняются один раз, решение их не меняет (как столбцы окна на PG). */
  readonly #window = new Map<string, WindowEntry>();

  async begin(op_ref: string, msg_hash: string, at: string): Promise<OperationRecord | undefined> {
    const prior = this.#map.get(op_ref);
    if (prior) return structuredClone(prior);
    this.#map.set(op_ref, { op_ref, msg_hash, decision: null, mandate_id: null, holds: [], at });
    return undefined;
  }

  /** Все записи — источник уведомителя в памяти (РП46 доп. п. 7); копии, хранилище не меняется. */
  *records(): Iterable<OperationRecord> {
    for (const r of this.#map.values()) yield structuredClone(r);
  }

  /** Запись по op_ref — для уведомителя в памяти, ПИ-3, GET операции и тестов; нет — undefined. */
  get(op_ref: string): OperationRecord | undefined {
    const r = this.#map.get(op_ref);
    return r && structuredClone(r);
  }

  async byMandate(mandate_id: string, limit: number): Promise<readonly OperationRecord[]> {
    return [...this.#map.values()]
      .filter((r) => r.mandate_id === mandate_id)
      .sort(byTime)
      .slice(0, limit)
      .map((r) => structuredClone(r));
  }

  async finish(rec: OperationRecord): Promise<void> {
    const prior = this.#map.get(rec.op_ref);
    if (prior && prior.decision === null && prior.msg_hash === rec.msg_hash) this.#map.set(rec.op_ref, structuredClone(rec));
  }

  /**
   * Проверка и запись без await между ними: один процесс — одна очередь (РП44 п. 4). Входы старше окна удаляются по
   * пути (длина окна — один параметр на процесс, доп. РП44 п. 2): перебор не растёт со временем работы стенда.
   */
  async enterWindow(op_ref: string, entry: WindowEntry, rule: WindowRule): Promise<WindowResult> {
    const own = this.#map.get(op_ref);
    if (!own || own.decision !== null || this.#window.has(op_ref)) throw new Error("adp_operations: вход в окно не у записи «в работе»");
    let ops = 1;
    let sum = entry.amount;
    for (const [ref, w] of this.#window) {
      if (w.at_ms <= rule.since_ms) {
        this.#window.delete(ref);
        continue;
      }
      if (w.key !== entry.key || !counts(this.#map.get(ref)?.decision ?? null)) continue;
      if (w.currency !== entry.currency) throw new Error("adp_operations: окно в разных валютах");
      ops++;
      sum += w.amount;
    }
    // Как на PG: сумма вне точного диапазона — не подтверждено, не догадка.
    if (!Number.isSafeInteger(sum)) throw new Error("adp_operations: сумма окна вне точного диапазона");
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

interface FactsRow extends OperationRow {
  agent_code: string | null;
  order_ref: string | null;
  channel: "CARD" | "SBP" | null;
  merchant_id: string | null;
  msg_amount: string | null;
  msg_currency: string | null;
  aoi: Aoi | null;
}

/**
 * Записи операций на PostgreSQL (доп. РП43 п. 16): «в работе» — INSERT … ON CONFLICT DO NOTHING, один оператор, поэтому
 * из одновременных запросов с разных экземпляров к резерву проходит один. Решение — UPDATE только строки «в работе» с тем
 * же хэшем; решённую строку триггер не даёт изменить или удалить.
 */
const FACTS_COLUMNS = "op_ref, msg_hash, decision, mandate_id, holds, at, agent_code, order_ref, channel, merchant_id, msg_amount, msg_currency, aoi";

/** Строка adp_operations → запись; у записей до sql/114 (нет суммы) фактов нет. */
function recordOf(x: FactsRow): OperationRecord {
  const base: OperationRecord = { op_ref: x.op_ref, msg_hash: x.msg_hash.trim(), decision: x.decision, mandate_id: x.mandate_id, holds: x.holds, at: x.at };
  if (x.msg_amount === null || x.msg_currency === null) return base;
  return {
    ...base,
    facts: {
      agent_code: x.agent_code,
      order_ref: x.order_ref,
      channel: x.channel,
      merchant_id: x.merchant_id,
      amount: Number(x.msg_amount),
      currency: x.msg_currency.trim(),
      aoi: x.aoi,
    },
  };
}

export class PgOperationStore implements OperationStore, OperationsByMandate {
  private readonly hooks: PgOperationHooks;
  private readonly lockTimeoutMs: number;

  /** lockTimeoutMs — предел ожидания блокировки окна: adp_timeout_ms (доп. РП44 п. 2). */
  constructor(
    private readonly client: TxSqlClient,
    opts: { readonly lockTimeoutMs: number; readonly hooks?: PgOperationHooks },
  ) {
    if (!Number.isSafeInteger(opts.lockTimeoutMs) || opts.lockTimeoutMs < 1) throw new Error("PgOperationStore: lockTimeoutMs — целое ≥ 1");
    this.lockTimeoutMs = opts.lockTimeoutMs;
    this.hooks = opts.hooks ?? {};
  }

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

  /**
   * Запись с фактами итога (РП52 п. 9). У записей до sql/114 фактов нет — запись без facts: агент итога по ПИ-3 у них не
   * установлен («Нюансы реализации» п. 4).
   */
  async get(op_ref: string): Promise<OperationRecord | undefined> {
    const r = await this.client.query<FactsRow>(`SELECT ${FACTS_COLUMNS} FROM adp_operations WHERE op_ref = $1`, [op_ref]);
    const x = r.rows[0];
    return x && recordOf(x);
  }

  /** По индексу adp_operations_mandate (sql/117, РП55 п. 6). */
  async byMandate(mandate_id: string, limit: number): Promise<readonly OperationRecord[]> {
    const r = await this.client.query<FactsRow>(
      `SELECT ${FACTS_COLUMNS} FROM adp_operations WHERE mandate_id = $1 ORDER BY at, op_ref LIMIT $2`,
      [mandate_id, limit],
    );
    return r.rows.map(recordOf);
  }

  async finish(rec: OperationRecord): Promise<void> {
    // Признаки уведомителя и факты итога — тем же оператором (РП46 доп. п. 9 (о1), РП52 п. 9): новых обращений к базе в
    // пути ADP нет. Агент — по домену токена: у уведомителя он тот же (клиент мандата известен только после домена).
    const n = rec.notify;
    const f = rec.facts;
    await this.client.query(
      `UPDATE adp_operations SET decision = $2::jsonb, mandate_id = $3, holds = $4::jsonb,
              participant_code = $6, principal_ref = $7, agent_code = $8, limit_source = $9, client_account = $10, client_left_after = $11,
              order_ref = $12, channel = $13, merchant_id = $14, msg_amount = $15, msg_currency = $16, aoi = $17::jsonb
        WHERE op_ref = $1 AND decision IS NULL AND msg_hash = $5`,
      [
        rec.op_ref,
        JSON.stringify(rec.decision),
        rec.mandate_id,
        JSON.stringify(rec.holds),
        rec.msg_hash,
        n?.participant_code ?? null,
        n?.principal_ref ?? null,
        n?.agent_code ?? f?.agent_code ?? null,
        n?.limit_source ?? null,
        n?.client_account ?? null,
        n?.client_left_after ?? null,
        f?.order_ref ?? null,
        f?.channel ?? null,
        f?.merchant_id ?? null,
        f?.amount ?? null,
        f?.currency ?? null,
        f?.aoi ? JSON.stringify(f.aoi) : null,
      ],
    );
  }

  /**
   * Транзакция (РП44 п. 4): блокировка ключа окна, чтение окна — уже после неё (снимок READ COMMITTED берётся на
   * каждый оператор), запись своей строки «в работе», COMMIT. Резерв ядра — после COMMIT: блокировка через вызов ядра
   * не держится. Ожидание блокировки — не дольше lockTimeoutMs (lock_timeout транзакции): процессинг ответа уже не ждёт,
   * поэтому превышение — исключение (→ STATE_UNAVAILABLE) без входа в окно и без резерва (доп. РП44 п. 2).
   */
  async enterWindow(op_ref: string, entry: WindowEntry, rule: WindowRule): Promise<WindowResult> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        await tx.query("SELECT set_config('lock_timeout', $1, true)", [`${this.lockTimeoutMs}ms`]);
        await this.hooks.beforeLock?.(op_ref);
        await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [splitWindowLockKey(entry.key)]);
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
        // Соединение, на котором не прошёл ROLLBACK (в том числе после сбоя BEGIN), в пул не возвращается (как РП39).
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

/**
 * Точки внутри транзакции окна — только для тестов (гонка двух экземпляров): beforeLock — после BEGIN, до блокировки
 * ключа окна; windowRead — после чтения окна, до записи входа.
 */
export interface PgOperationHooks {
  readonly beforeLock?: (op_ref: string) => Promise<void>;
  readonly windowRead?: (op_ref: string) => Promise<void>;
}

const SPLIT_WINDOW_LOCK_DOMAIN = "adp:split-window-lock:v1";

/** Ключ pg_advisory_xact_lock окна: 64 бита SHA-256 со знаком, десятичной строкой (как ключ ленты событий, РП39 п. 2). */
export function splitWindowLockKey(window_key: string): string {
  return createHash("sha256").update(`${SPLIT_WINDOW_LOCK_DOMAIN}\n${window_key}`, "utf8").digest().readBigInt64BE(0).toString();
}
