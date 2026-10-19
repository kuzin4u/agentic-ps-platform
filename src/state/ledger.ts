// П3 Хранилище удержаний и проход срока (РП41 п. 2, 6). PostgreSQL — PgHoldLedger ядра на пуле в autocommit (не клиент
// внутри транзакции: так требует договор ядра); без базы (dev, стенд) — AsyncMemoryHoldLedger ядра, один процесс (РП30 п. 6).
import { AsyncMemoryHoldLedger, PgHoldLedger, type AsyncHoldLedger, type SqlClient } from "@kuzin4u/agentic-core";
import type { StateService } from "./service.js";

export function holdLedger(client?: SqlClient): AsyncHoldLedger {
  return client ? new PgHoldLedger(client) : new AsyncMemoryHoldLedger();
}

/** Проход expire раз в 60 с на каждом экземпляре — константа кода, не параметр (РП41 п. 6). */
export const RESERVATION_EXPIRE_EVERY_MS = 60_000;

/** Таймер прохода срока; проходы не накладываются, сбой StateService.expire пишет в журнал процесса сам. */
export function startReservationExpiry(state: StateService, everyMs: number): () => Promise<void> {
  let running: Promise<void> | undefined;
  const timer = setInterval(() => {
    if (running) return;
    running = state
      .expire()
      .then(() => undefined)
      .finally(() => (running = undefined));
  }, everyMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await running;
  };
}
