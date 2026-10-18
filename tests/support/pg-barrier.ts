// Барьер ответов базы (№ 21 ядра): помощник тестов одновременности на PostgreSQL по образцу tests/pg-barrier.ts
// agentic-core. Ядро не экспортирует свои тестовые помощники — копия с той же логикой.
import type { SqlClient } from "@kuzin4u/agentic-core";

/**
 * Первые n ответов базы отдаются вызывающим только когда пришли все n. Если проверка и захват — две команды
 * (SELECT, затем INSERT), все проверки увидят пустую таблицу раньше любой записи, и «новым» окажется каждый вызов.
 * Тест на пуле этого не ловит: соединения открываются по одному, и первый вызов успевает обе команды.
 * Предохранитель: если вызовов меньше n, барьер откроется по таймеру и тест упадёт на `left() === 0`, а не зависнет.
 */
export function barrierClient(db: SqlClient, n: number, fuseMs = 3_000): { client: SqlClient; left: () => number; close: () => void } {
  let left = n;
  let open!: () => void;
  const gate = new Promise<void>((r) => (open = r));
  const fuse = setTimeout(() => open(), fuseMs);
  const client: SqlClient = {
    async query<R extends Record<string, unknown>>(text: string, params?: unknown[]) {
      const r = await db.query<R>(text, params);
      if (left > 0 && --left === 0) open();
      await gate;
      return r;
    },
  };
  return { client, left: () => left, close: () => clearTimeout(fuse) };
}
