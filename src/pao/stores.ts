// П9 Хранилища шлюза ПАО (РП30): nonce — хранилища agentic-core, PostgreSQL или память по среде (п. 6).
// Своей реализации хранилищ нет: проверка и запись nonce — одна команда ядра (Ш3а).
import { AsyncMemoryNonceStore, PgNonceStore, type AsyncNonceStore, type SqlClient } from "@kuzin4u/agentic-core";
import type { PoolConfig } from "pg";
import type { PlatformEnv } from "../server.js";

/** Одна область nonce на всех агентов (РП30 п. 2): одна purge(), агент различается значением. */
export const PAO_NONCE_SCOPE = "pao";

/** Срок хранения nonce — 2 × signature_skew_sec (РП23 п. 6): обращение с меткой на краю окна годно ещё skew после записи. */
export const nonceRetainMs = (skewSec: number): number => 2 * skewSec * 1000;

export interface PaoNonceStoreOptions {
  /** PostgreSQL — `pg.Pool`; без клиента — память ядра (только dev и стенд, РП30 п. 6). */
  readonly client?: SqlClient;
  readonly skewSec: number;
  readonly now?: () => number;
}

/** skewSec передаётся ядру: срок меньше 2 × skew ядро отвергает при создании (RangeError). */
export function paoNonceStore(o: PaoNonceStoreOptions): AsyncNonceStore {
  const opts = { retainMs: nonceRetainMs(o.skewSec), skewSec: o.skewSec, ...(o.now ? { now: o.now } : {}) };
  return o.client ? new PgNonceStore(o.client, PAO_NONCE_SCOPE, opts) : new AsyncMemoryNonceStore(opts);
}

/**
 * Предел ожидания базы шлюзом, мс (аудит К2.3 №1; инвариант 3 «таймаут — отказ»): без него зависшая база держала бы
 * обращение бесконечно вместо 503 UPSTREAM_UNAVAILABLE и исчерпала бы пул. Константа кода, не стендовый параметр:
 * это граница отказа, а не настройка поведения для агента.
 */
export const PAO_DB_TIMEOUT_MS = 2000;

/** Пул рабочих обращений: таймаут соединения и запроса на стороне клиента pg. Миграции — отдельным пулом без них. */
export const paoPoolConfig = (connectionString: string, timeoutMs: number = PAO_DB_TIMEOUT_MS): PoolConfig => ({
  connectionString,
  connectionTimeoutMillis: timeoutMs,
  query_timeout: timeoutMs,
});

/**
 * Очистка nonce раз в everyMs (РП30 п. 2: раз в signature_skew_sec). Сбой — только в журнал процесса: на приём
 * не влияет, окно проверяется по x-timestamp. Таймер не держит процесс. stop() снимает таймер и дожидается идущей
 * purge(), чтобы она не писала ложный сбой после закрытия пула (аудит К2.3 №5).
 */
export function startNoncePurge(
  store: AsyncNonceStore,
  everyMs: number,
  onError: (err: unknown) => void,
): () => Promise<void> {
  let running: Promise<void> = Promise.resolve();
  const timer = setInterval(() => {
    running = store.purge().then(
      () => undefined,
      (err: unknown) => onError(err),
    );
  }, everyMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await running;
  };
}

/** Без базы запускается только dev (РП30 п. 6): sandbox без DATABASE_URL — отказ запуска (fail-closed). */
export function requireDatabaseUrl(env: PlatformEnv, url: string | undefined): string | undefined {
  if (url) return url;
  if (env === "dev") return undefined;
  throw new Error(`Среда ${env} без DATABASE_URL не запускается: хранилища шлюза ПАО — только PostgreSQL (РП30 п. 6)`);
}
