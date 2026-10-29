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

// Подключение sandbox (РП66 п. 3, 7; SEC-1-код ч. 2б-2 К3.1): поведение — дымовой тест на PG с рукопожатием
// (main-process-pg, только CI); здесь — что нужные значения переданы и dev их не получает (УЦ только в sandbox).
describe("страж: src/main.ts sandbox — TLS, ступень 0, обязательный CSR (РП66 п. 3, 7)", () => {
  it("УЦ загружается только в sandbox; TLS, ступень 0 и выпуск сертификатов — только при загруженном УЦ", () => {
    const text = code();
    expect(text).toMatch(/if \(env !== "sandbox"\) return "skip";\s*ca = loadCaFile\(process\.env\.PLATFORM_CA_KEY_PATH/);
    expect(text).toMatch(/\.\.\.\(ca\s*\?\s*\{\s*certificates:/);
    expect(text).toMatch(/\.\.\.\(ca\s*\?\s*\{\s*mtls:/);
    expect(text).toMatch(/ca && serverCert\s*\?/);
  });

  it("реестр sandbox — CSR обязателен (required: true), вид причины CSR — в журнал через onRejected", () => {
    const text = code();
    expect(text).toMatch(/certificates: \{[^}]*required: true,[^}]*onRejected:/);
    expect(text).not.toMatch(/required: false/);
  });

  it("ступень 0: корень — УЦ из файла, запись сертификата — из реестра, ticketMaxAgeMs = revocation_propagation_max_ms", () => {
    const text = code();
    expect(text).toMatch(/mtls: \{\s*ca: new X509Certificate\(ca\.certificateDer\),/);
    expect(text).toMatch(/getCertificate: \(serial: string\) => registry\.getCertificate\(serial\)/);
    expect(text).toMatch(/ticketMaxAgeMs: params\.revocation_propagation_max_ms/);
  });

  it("сертификат сервера — на имена PLATFORM_TLS_HOSTNAMES, срок и запас — из стендовых параметров; доверенный TLS — корень УЦ из файла; TLS передан в buildServer", () => {
    const text = code();
    // Выпуск — в проверке ca.key, сразу после загрузки УЦ: сбой — STARTUP_CA_KEY_INVALID до отчёта (КТ1 К3.1 № 4);
    // без имён (params отказала) — skip, а не второй отказ (КТ1 сессии 57 № 1).
    expect(text).toMatch(
      /ca = loadCaFile\([^;]*\);\s*if \(tlsHostnames === undefined\) return "skip";\s*serverCert = ca\.issueServerCertificate\(tlsHostnames, new Date\(\), params\.agent_cert_ttl_days, params\.cert_not_before_backdate_sec\);/,
    );
    expect(text).toMatch(/certificateDer: serverCert\.certificateDer, caDer: ca\.certificateDer \}/);
    expect(text).toMatch(/buildServer\(\{[\s\S]*?\.\.\.\(tls \? \{ tls \} : \{\}\)/);
  });

  it("вне dev без TLS — исключение до buildServer (КТ1 К3.1 № 5, РП67 п. 8)", () => {
    expect(code()).toMatch(/if \(env !== "dev" && !tls\) throw new Error\(".*?"\);[\s\S]*?buildServer\(\{/);
  });

  it("срок сертификата сервера — в журнал запуска (КТ1 К3.1 № 1: продления без перезапуска нет)", () => {
    expect(code()).toMatch(/server_cert_not_after: serverCert\?\.notAfter\.toISOString\(\)/);
  });
});
