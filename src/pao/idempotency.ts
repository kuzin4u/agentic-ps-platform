// П9 Идемпотентность изменяющих методов ПАО (РП30 п. 3, Ш16): хранилища agentic-core, PostgreSQL или память по среде.
// Область — по агенту, ключ в хранилище — SHA-256 от Idempotency-Key (дополнение к РП30 п. 3): длина ключа агента
// на первичный ключ таблицы ядра не влияет.
import { createHash } from "node:crypto";
import {
  AsyncMemoryIdempotencyStore,
  canonicalJson,
  PgIdempotencyStore,
  sha256Hex,
  type AsyncIdempotencyStore,
  type SqlClient,
} from "@kuzin4u/agentic-core";

/** Ответ обработчика под ключом идемпотентности: статус и тело ПАО (2xx и 4xx, РП30 п. 3). */
export interface PaoReply {
  readonly status: number;
  readonly body: unknown;
}

export type PaoIdempotency = (agent_code: string) => AsyncIdempotencyStore<PaoReply>;

/**
 * Аренда захвата — значение ядра по умолчанию, константой кода (РП30 п. 3): больше самой долгой операции под ключом.
 * Обработчики шлюза — запись в реестр без внешних вызовов; обработчик с внешним вызовом — пересмотреть в его задаче.
 */
export const PAO_IDEMPOTENCY_LEASE_MS = 60_000;

/**
 * Предел времени обработчика под ключом (РП33 доп. п. 8, В2): обработчик проверяет его перед каждой командой записи
 * в хранилище, в том числе перед каждой попыткой вставки в журнал, и после него не пишет. Команда ограничена
 * соединением и исполнением по PAO_DB_TIMEOUT_MS (stores.ts, statement_timeout — и на сервере), поэтому последняя
 * запись — не позже предела + 2 × таймаут базы, раньше конца аренды: второй обработчик того же ключа не начнёт ту же
 * запись, пока первый может писать. Константа кода, как аренда и таймаут базы: граница отказа, а не настройка
 * поведения для агента. Остаток риска (процесс, вставший дольше аренды между проверкой и записью) — условная вставка
 * журнала в ядре (п. 9).
 */
export const PAO_HANDLER_BUDGET_MS = 30_000;

/** Предел + худшая команда записи (соединение и исполнение) — меньше аренды ключа; иначе шлюз не запускается. */
export function assertHandlerBudget(budgetMs: number, dbTimeoutMs: number, leaseMs: number): void {
  if (budgetMs + 2 * dbTimeoutMs >= leaseMs) throw new Error("ПАО: предел обработчика с таймаутом базы ≥ аренды ключа");
}

/** Предел времени обработчика исчерпан до записи: исключение снимает захват ключа, повтор исполняется заново. */
export class PaoHandlerDeadline extends Error {
  constructor(readonly budgetMs: number) {
    super(`ПАО: обработчик дольше ${budgetMs} мс — запись не начата`);
  }
}

/** Проверка предела: вызывать перед каждой записью; now — монотонные миллисекунды. */
export function handlerDeadline(budgetMs: number, now: () => number): () => void {
  const end = now() + budgetMs;
  return () => {
    if (now() > end) throw new PaoHandlerDeadline(budgetMs);
  };
}

/** Область «агент + ключ» (Ш16): тот же Idempotency-Key у другого агента — другая строка таблицы. */
export const idempotencyScope = (agent_code: string): string => `pao:${agent_code}`;

/** Ключ в хранилище — SHA-256 (hex) от Idempotency-Key как пришёл. */
export const idempotencyKeyHash = (key: string): string => createHash("sha256").update(key, "utf8").digest("hex");

export interface PaoIdempotencyOptions {
  /** PostgreSQL — `pg.Pool`; без клиента — память ядра (только dev и стенд, РП30 п. 6). */
  readonly client?: SqlClient;
  readonly ttlSec: number;
  readonly now?: () => number;
}

export function paoIdempotency(o: PaoIdempotencyOptions): PaoIdempotency {
  const opts = { ttlMs: o.ttlSec * 1000, leaseMs: PAO_IDEMPOTENCY_LEASE_MS, ...(o.now ? { now: o.now } : {}) };
  const client = o.client;
  // ВРЕМЕННАЯ ПОЛОМКА К3.2а (откатывается следующим коммитом): проверка и захват ключа — двумя командами.
  if (client) {
    return (agent_code) => {
      const scope = idempotencyScope(agent_code);
      const real = new PgIdempotencyStore<PaoReply>(client, scope, opts);
      const now = o.now ?? Date.now;
      return {
        async run(key, body, fn) {
          const r = await client.query("SELECT 1 AS x FROM core_idempotency WHERE scope = $1 AND key = $2", [scope, key]);
          if (r.rows.length > 0) return real.run(key, body, fn);
          const bodyHash = sha256Hex(canonicalJson(body));
          await client.query(
            "INSERT INTO core_idempotency (scope, key, body_hash, state, token, at) VALUES ($1, $2, $3, 'RUNNING', 'broken', $4::bigint) ON CONFLICT (scope, key) DO NOTHING",
            [scope, key, bodyHash, now()],
          );
          const result = await fn();
          await client.query("UPDATE core_idempotency SET state = 'DONE', result = $3 WHERE scope = $1 AND key = $2", [
            scope,
            key,
            canonicalJson(result ?? null),
          ]);
          return { result, replayed: false };
        },
      };
    };
  }
  // Память: одно хранилище на область, живёт с процессом.
  const stores = new Map<string, AsyncIdempotencyStore<PaoReply>>();
  return (agent_code) => {
    const scope = idempotencyScope(agent_code);
    let s = stores.get(scope);
    if (!s) stores.set(scope, (s = new AsyncMemoryIdempotencyStore<PaoReply>(opts)));
    return s;
  };
}
