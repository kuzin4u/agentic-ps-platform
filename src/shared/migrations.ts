// Миграции PostgreSQL: сначала ядра (001–099), затем Платформы (`sql/`, с 100). Учёт — общий, core_migrations, по имени
// файла: совпадение имён молча пропустило бы один из файлов, поэтому разделение номеров проверяется до применения.
import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyMigrations, migrationsDir, type SqlClient } from "@kuzin4u/agentic-core";

/** Каталог `sql/` Платформы: `src/shared/` и `dist/shared/` — на два уровня ниже корня. */
export function platformMigrationsDir(): string {
  const d = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "sql");
  if (!existsSync(d)) throw new Error(`каталог миграций Платформы не найден: ${d}`);
  return d;
}

const sqlFiles = (dir: string): string[] => readdirSync(dir).filter((f) => f.endsWith(".sql"));
const num = (f: string): number => Number(f.slice(0, 3));

/** Ядро — номера < 100, Платформа — ≥ 100; иначе отказ (запуска или теста). */
export function assertMigrationRanges(coreDir: string, platformDir: string): void {
  const core = sqlFiles(coreDir).filter((f) => !(num(f) < 100));
  const platform = sqlFiles(platformDir).filter((f) => !(num(f) >= 100));
  if (core.length || platform.length) {
    throw new Error(`миграции вне своих номеров: ядро ${core.join(", ") || "—"}; Платформа ${platform.join(", ") || "—"}`);
  }
}

/** Применить миграции ядра и Платформы; возвращает имена применённых файлов. */
export async function applyPlatformMigrations(client: SqlClient): Promise<string[]> {
  assertMigrationRanges(migrationsDir(), platformMigrationsDir());
  return [...(await applyMigrations(client, migrationsDir())), ...(await applyMigrations(client, platformMigrationsDir()))];
}
