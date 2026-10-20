// PostgreSQL в CI (РП30 п. 7, PS-05 К2.2): страж и миграции ядра на настоящей базе.
// Страж — как в agentic-core (К2.4 ядра): в CI PG-тесты не пропускаются молча — без DATABASE_URL падает этот тест.
// Локально без базы — пропуск (PostgreSQL только в CI, решение владельца 15.10.2026).
import { applyMigrations, migrationsDir, type SqlClient } from "@kuzin4u/agentic-core";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyPlatformMigrations } from "../../src/shared/migrations.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

// pg.Pool подходит как SqlClient ядра без обёртки (РП30 п. 4) — проверка типов.
const _pool: (p: pg.Pool) => SqlClient = (p) => p;
void _pool;

describe("страж PG-тестов", () => {
  it.runIf(process.env.CI)("в CI задан DATABASE_URL — PG-тесты выполняются, а не пропускаются", () => {
    expect(DATABASE_URL, "в CI нет DATABASE_URL: PG-тесты были бы пропущены").toBeTruthy();
  });
});

describe.skipIf(!DATABASE_URL)("PostgreSQL: миграции ядра 001–004 и Платформы 100 (РП30 п. 5, PS-06)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("migr");
  });
  afterAll(async () => {
    await db?.close();
  });

  it("применены 001–004, 100_consent, 101_events, 102_event_deliveries, 103_adp_operations, 104_adp_split_window, 105_participant_limits, 106_principal_order и 107_participant_notifications, таблицы nonce, идемпотентности и согласий есть; повторный запуск ничего не применяет", async () => {
    const applied = (await db.pool.query<{ name: string }>("SELECT name FROM core_migrations ORDER BY name")).rows;
    expect(applied.map((r) => r.name)).toEqual([
      "001_journal.sql",
      "002_holds.sql",
      "003_idempotency.sql",
      "004_nonces.sql",
      "100_consent.sql",
      "101_events.sql",
      "102_event_deliveries.sql",
      "103_adp_operations.sql",
      "104_adp_split_window.sql",
      "105_participant_limits.sql",
      "106_principal_order.sql",
      "107_participant_notifications.sql",
    ]);
    const tables = (
      await db.pool.query<{ t: string }>(
        "SELECT table_name AS t FROM information_schema.tables WHERE table_schema = current_schema() ORDER BY 1",
      )
    ).rows.map((r) => r.t);
    expect(tables).toEqual(expect.arrayContaining(["core_idempotency", "core_nonces", "consent_mandates", "consent_subjects", "pao_events", "pao_event_deliveries", "adp_operations", "participant_limits", "principal_order", "participant_notifications", "participant_notify_seen", "participant_notification_deliveries"]));
    expect(await applyMigrations(db.pool, migrationsDir())).toEqual([]);
    expect(await applyPlatformMigrations(db.pool)).toEqual([]);
  });
});
