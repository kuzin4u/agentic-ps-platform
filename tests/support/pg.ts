// PostgreSQL для тестов (РП30 п. 7): своя схема на файл тестов, миграции ядра — applyMigrations.
// Без DATABASE_URL PG-тесты пропускаются (локально базы нет — решение владельца 15.10.2026); в CI пропуск ловит
// страж в tests/unit/pg.test.ts.
import { applyMigrations } from "@kuzin4u/agentic-core";
import pg from "pg";

export const DATABASE_URL = process.env.DATABASE_URL;

export interface TestDb {
  /** Пул в своей схеме; max — как у ядра, для одновременных обращений. */
  readonly pool: pg.Pool;
  /** Новый пул на той же схеме — «перезапуск» процесса Платформы на той же базе. */
  reopen(): pg.Pool;
  /** Параметр `options` пула для своей схемы — для пула со своими настройками (таймауты). */
  readonly searchPathOption: string;
  close(): Promise<void>;
}

/** Схема `t_<pid>_<время>_<метка>` с миграциями 001–004 ядра; close() удаляет её. */
export async function openTestDb(label: string): Promise<TestDb> {
  if (!DATABASE_URL) throw new Error("нет DATABASE_URL");
  const schema = `t_${process.pid}_${Date.now()}_${label.replace(/[^a-z0-9_]/g, "")}`;
  const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pools: pg.Pool[] = [];
  const searchPathOption = `-c search_path=${schema}`;
  const open = (): pg.Pool => {
    const p = new pg.Pool({ connectionString: DATABASE_URL, options: searchPathOption, max: 20 });
    pools.push(p);
    return p;
  };
  const pool = open();
  await applyMigrations(pool);
  return {
    pool,
    reopen: open,
    searchPathOption,
    async close() {
      await Promise.all(pools.map((p) => p.end()));
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    },
  };
}
