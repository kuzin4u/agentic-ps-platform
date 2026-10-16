// П9 Идемпотентность изменяющих методов ПАО (РП30 п. 3, Ш16): хранилища agentic-core, PostgreSQL или память по среде.
// Область — по агенту, ключ в хранилище — SHA-256 от Idempotency-Key (дополнение к РП30 п. 3): длина ключа агента
// на первичный ключ таблицы ядра не влияет.
import { createHash } from "node:crypto";
import {
  AsyncMemoryIdempotencyStore,
  PgIdempotencyStore,
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
  if (client) return (agent_code) => new PgIdempotencyStore<PaoReply>(client, idempotencyScope(agent_code), opts);
  // Память: одно хранилище на область, живёт с процессом.
  const stores = new Map<string, AsyncIdempotencyStore<PaoReply>>();
  return (agent_code) => {
    const scope = idempotencyScope(agent_code);
    let s = stores.get(scope);
    if (!s) stores.set(scope, (s = new AsyncMemoryIdempotencyStore<PaoReply>(opts)));
    return s;
  };
}
