// П8 Очередь обработчиков ПИ-3 по op_ref (РП55 «Дополнения КТ1» п. 1): ISSUER_RESPONSE, PRESENTMENT, REVERSAL /
// AUTH_EXPIRED и REFUND одной операции выполняются по одному. Без неё реверсал мог освободить удержание, пока клиринг
// закреплял соседнее (инвариант 4). PostgreSQL — сеансовая pg_advisory_lock на отдельном соединении на время обработки:
// транзакционная не подходит, ядро ходит своими соединениями (autocommit, как окно РП44 п. 4). Память — цепочка обещаний.
import { createHash } from "node:crypto";
import type { TxSqlPool } from "../consent/store.js";

/** Сбой или превышение ожидания — исключение (ПИ-3 → 503, процессинг повторит). */
export interface OpLock {
  run<T>(op_ref: string, fn: () => Promise<T>): Promise<T>;
}

/** В памяти (dev, стенд): один процесс — очередь на op_ref; запись очереди снимается за последним. */
export class MemoryOpLock implements OpLock {
  readonly #tails = new Map<string, Promise<unknown>>();

  async run<T>(op_ref: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.#tails.get(op_ref) ?? Promise.resolve();
    const mine = prev.then(fn, fn);
    const tail = mine.then(
      () => undefined,
      () => undefined,
    );
    this.#tails.set(op_ref, tail);
    try {
      return await mine;
    } finally {
      if (this.#tails.get(op_ref) === tail) this.#tails.delete(op_ref);
    }
  }
}

const PI3_LOCK_DOMAIN = "adp:pi3-op-lock:v1";

/** Ключ pg_advisory_lock операции: 64 бита SHA-256 со знаком, десятичной строкой (как ключ окна, РП44 п. 4). */
export function pi3LockKey(op_ref: string): string {
  return createHash("sha256").update(`${PI3_LOCK_DOMAIN}\n${op_ref}`, "utf8").digest().readBigInt64BE(0).toString();
}

/**
 * На PostgreSQL: блокировка сеанса по ключу op_ref на своём соединении пула; ожидание — не дольше timeoutMs (lock_timeout
 * сеанса, adp_timeout_ms). После обработки — снятие; не снялась — соединение в пул не возвращается (закрытие сеанса
 * снимает блокировку).
 */
export class PgOpLock implements OpLock {
  constructor(
    private readonly pool: TxSqlPool,
    private readonly opts: { readonly timeoutMs: number },
  ) {}

  async run<T>(op_ref: string, fn: () => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    const key = pi3LockKey(op_ref);
    let broken: Error | undefined;
    let locked = false;
    try {
      await c.query("SELECT set_config('lock_timeout', $1, false)", [`${this.opts.timeoutMs}ms`]);
      await c.query("SELECT pg_advisory_lock($1::bigint)", [key]);
      locked = true;
      return await fn();
    } catch (err) {
      if (!locked) broken = err instanceof Error ? err : new Error(String(err));
      throw err;
    } finally {
      if (locked) {
        // lock_timeout сеанса не уходит в общий пул вместе с соединением.
        await c.query("SELECT pg_advisory_unlock($1::bigint)", [key]).then(() => c.query("RESET lock_timeout")).catch((e: unknown) => {
          broken = e instanceof Error ? e : new Error(String(e));
        });
      }
      c.release(broken);
    }
  }
}
