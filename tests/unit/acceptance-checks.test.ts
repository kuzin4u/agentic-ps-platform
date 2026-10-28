// Проверки приёмки песочницы (SANDBOX-ACC К1.2): runAcceptance против сервера Платформы в процессе — TLS 1.3 с сертификатом
// от УЦ, ступень 0, реестр в памяти, маршрут банка и API продавцов; порт оператора — реестр напрямую, журнал — строка
// запуска как у main.ts, перезапуск — новый сервер на том же порту (новый сертификат сервера). Процесс main.ts на
// PostgreSQL и operator.mjs — в tests/unit/acceptance.test.ts (CI).
import { X509Certificate } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { accepted, normFingerprint, report, runAcceptance, startupEntry, type CheckResult } from "../../scripts/acceptance/checks.js";
import type { OperatorPort } from "../../scripts/acceptance/operator.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryParticipantNotificationStore } from "../../src/participants/notifications.js";
import { MemoryReadinessStore } from "../../src/participants/readiness.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import { ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { PaoRequestVerifier, paoIdempotency } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore, SandboxCa } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { memoryConsent } from "../support/consent.js";

const params = loadParams();
const HOST = "127.0.0.1";

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

/** Песочница в процессе: УЦ и реестр переживают «перезапуск», сервер и его сертификат — новые. */
async function sandbox() {
  const ca = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: params.sandbox_ca_ttl_days });
  const store = new InMemoryAgentRegistryStore();
  const certificates = { ca, ttlDays: params.agent_cert_ttl_days, backdateSec: params.cert_not_before_backdate_sec, required: true };
  const registry = new AgentRegistry(store, { keys: params, certificates });
  const keys = new AgentKeys(store, { keys: params });
  const trusted = new TrustedParticipants([], { stand: false });
  let journal = "";
  let port = 0;

  const listen = async () => {
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      {
        skewSec: params.signature_skew_sec,
        mtls: { ca: new X509Certificate(ca.certificateDer), getCertificate: (s) => registry.getCertificate(s), ticketMaxAgeMs: params.revocation_propagation_max_ms },
      },
    );
    const server = ca.issueServerCertificate([HOST, "localhost"], new Date(), params.agent_cert_ttl_days, params.cert_not_before_backdate_sec);
    const readiness = new MemoryReadinessStore();
    app = buildServer({
      env: "sandbox",
      tls: { key: server.privateKey, certificateDer: server.certificateDer, caDer: ca.certificateDer },
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
      paoConfiguration: { contour: "sandbox", params },
      participants: {
        trusted,
        consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => trusted.revocationOrder() }),
        params,
        requests: new ParticipantRequestVerifier(trusted, { skewSec: params.signature_skew_sec }),
        // Без Outbox участника маршрута ленты нет (404) — проверка 11 это ловит.
        notifications: new MemoryParticipantNotificationStore(new MemoryOperationStore()),
      },
      merchants: { registry, keys, contour: "sandbox", params, readiness },
    });
    await app.listen({ host: HOST, port });
    port = (app.server.address() as AddressInfo).port;
    // Строка запуска — как у main.ts (РП66 п. 6, КТ1 К3.1 № 1).
    journal = `не JSON\n${JSON.stringify({ level: 30, msg: "УЦ песочницы загружен", ca_fingerprint: ca.fingerprint, server_cert_not_after: server.notAfter.toISOString() })}\n`;
  };
  await listen();

  const calls: string[] = [];
  const op: OperatorPort = {
    admit: async (application) => {
      calls.push("admit");
      const d = await registry.admit(application, { contour: "sandbox", operator: "op-acceptance" });
      if (!d.admitted) return { admitted: false, reasons: d.reasons };
      return {
        admitted: true,
        agent_code: d.record.agent_code,
        ...(d.certificate ? { certificate: { serial: d.certificate.serial, der: d.certificate.der, not_after: d.certificate.not_after } } : {}),
      };
    },
    revoke: async (serial) => {
      calls.push("revoke");
      return (await registry.revokeCertificate(serial))?.revoked_at != null;
    },
    journal: async () => {
      calls.push("journal");
      return journal;
    },
    restart: async () => {
      calls.push("restart");
      await app?.close();
      await listen();
    },
    close: async () => {
      calls.push("close");
    },
  };
  return { ca, port, op, calls, rootPem: new X509Certificate(ca.certificateDer).toString() };
}

const byId = (rs: readonly CheckResult[]) => Object.fromEntries(rs.map((r) => [r.id, r]));

describe("runAcceptance против песочницы в процессе", () => {
  it("13 проверок и повтор после перезапуска — все пройдены, итог «принято»; порт оператора закрыт", async () => {
    const s = await sandbox();
    const rs = await runAcceptance({ host: HOST, port: s.port, caPem: s.rootPem, fingerprint: s.ca.fingerprint }, s.op, { ticketWaitMs: 300 });
    expect(rs.map((r) => r.id)).toEqual(["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "13.1", "13.5", "13.12"]);
    expect(rs.filter((r) => !r.ok), report(rs)).toEqual([]);
    expect(accepted(rs)).toBe(true);
    expect(report(rs)).toContain("Итог: принято (16 из 16)");
    const r = byId(rs);
    expect(r["2"]?.actual).toMatch(/^отказ: /);
    // TLS 1.3 с SSL_OP_NO_TICKET: OpenSSL выдаёт билет с состоянием на сервере, а кэша сессий у сервера Node нет —
    // повтор с билетом идёт полным рукопожатием (К2.2): проверка действительно пробует возобновление.
    expect(r["3"]?.actual).toBe("билет выдан, но полное рукопожатие");
    expect(r["6"]?.actual).toBe("401 AGENT_UNKNOWN");
    expect(r["8"]?.actual).toBe("отказ: APPLICATION_INCOMPLETE");
    expect(r["11"]?.actual).toBe("401 SIGNATURE_INVALID");
    expect(s.calls).toEqual(["admit", "admit", "revoke", "journal", "restart", "journal", "close"]);
  }, 60_000);

  it("ожидаемый отпечаток не тот (отпечаток с двоеточиями в верхнем регистре) — 1, 12 и повторы не пройдены, итог «не принято»", async () => {
    const s = await sandbox();
    const other = SandboxCa.generate({ now: new Date(), ttlDays: 1 }).fingerprint.toUpperCase().match(/../g)?.join(":") as string;
    const rs = await runAcceptance({ host: HOST, port: s.port, caPem: s.rootPem, fingerprint: other }, s.op, { ticketWaitMs: 100 });
    expect(rs.filter((r) => !r.ok).map((r) => r.id)).toEqual(["1", "12", "13.1", "13.12"]);
    expect(byId(rs)["1"]?.actual).toContain("корень ≠ ожидаемому");
    expect(byId(rs)["12"]?.actual).toContain("ca_fingerprint ≠ ожидаемому");
    expect(report(rs)).toContain("Итог: не принято (12 из 16)");
  }, 60_000);

  it("корень не тот (чужой УЦ) — сервер не проверен, но остальные проверки выполняются; ошибка шага — «не пройдена», а не пропуск", async () => {
    const s = await sandbox();
    const foreign = SandboxCa.generate({ now: new Date(), ttlDays: 1 });
    const rs = await runAcceptance(
      { host: HOST, port: s.port, caPem: new X509Certificate(foreign.certificateDer).toString(), fingerprint: foreign.fingerprint },
      { ...s.op, journal: async () => Promise.reject(Object.assign(new Error("x"), { code: "INVOCATION_UNKNOWN" })) },
      { ticketWaitMs: 100, readyTimeoutMs: 2_000 },
    );
    const r = byId(rs);
    expect(r["1"]?.ok).toBe(false);
    expect(r["2"]?.ok, "отказ TLS 1.2 из-за корня — тоже отказ").toBe(true);
    expect(r["5"]?.actual).toMatch(/^ошибка: /);
    expect(r["12"]?.actual).toBe("ошибка: INVOCATION_UNKNOWN");
    expect(r["13"]?.ok).toBe(false);
    expect(r["13.1"]?.actual).toBe("не выполнялся");
    expect(accepted(rs)).toBe(false);
  }, 60_000);
});

describe("разбор и итог", () => {
  it("startupEntry — последняя строка «УЦ песочницы загружен», не JSON — пропуск; отпечаток — без двоеточий и регистра", () => {
    const j = ['{"msg":"УЦ песочницы загружен","ca_fingerprint":"a"}', "{oops", '{"msg":"УЦ песочницы загружен","ca_fingerprint":"b"}', ""].join("\n");
    expect(startupEntry(j)?.ca_fingerprint).toBe("b");
    expect(startupEntry("{}\n")).toBeUndefined();
    expect(normFingerprint(" AB:cd:EF ")).toBe("abcdef");
  });

  it("пустой список — «не принято»", () => {
    expect(accepted([])).toBe(false);
    expect(report([])).toContain("Итог: не принято (0 из 0)");
  });
});
