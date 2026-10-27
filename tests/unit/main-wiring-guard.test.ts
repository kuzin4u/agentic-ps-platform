// Страж подключений src/main.ts до РП64 п. 6 (PS-05в ч. 3; условия владельца 27.10 — РП64 дополнение «2б-2» п. 3):
// (1) PgCredentialStore / PgConfirmationStore не подключаются: до п. 6 их запись не проверяет статус агента в своей
// транзакции (РП54 остаточный риск 3 на PG); (2) служба приостановления с транзакцией реестра не подключается: до п. 6
// created_at — по часам Платформы, suspended_at — по часам базы (часы двух источников, КТ1 ч. 2б-2 № 1).
// Снимается в ч. 3 вместе с п. 6. Там же — п. 7: с DATABASE_URL реестр агентов только на PG, без — память.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Текст main.ts без комментариев: упоминание в пояснении — не подключение. «//» после «:» (адрес в строке) не трогается. */
const code = (): string =>
  readFileSync(join(import.meta.dirname, "..", "..", "src", "main.ts"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|\s)\/\/.*$/gm, "$1");

describe("страж: src/main.ts до РП64 п. 6 (ч. 3)", () => {
  it("хранилища реквизита и подтверждения на PG не подключены (РП54 остаточный риск 3, жёсткое условие владельца)", () => {
    const text = code();
    for (const name of ["PgCredentialStore", "PgConfirmationStore"]) expect(text, name).not.toContain(name);
  });

  it("служба приостановления с транзакцией реестра не подключена (часы двух источников, КТ1 ч. 2б-2 № 1)", () => {
    const text = code();
    for (const name of ["AgentStatusService", "AgentStatusTx", "transitStatus"]) expect(text, name).not.toContain(name);
  });

  it("РП64 п. 7: с DATABASE_URL — реестр агентов только на PG, без — память", () => {
    expect(code()).toMatch(/pool \? new PgAgentRegistryStore\(pool\) : new InMemoryAgentRegistryStore\(\)/);
  });
});
