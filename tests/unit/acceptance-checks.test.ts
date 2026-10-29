// Проверки приёмки песочницы (SANDBOX-ACC К1.2): runAcceptance против сервера Платформы в процессе — TLS 1.3 с сертификатом
// от УЦ, ступень 0, реестр в памяти, маршрут банка и API продавцов; порт оператора — реестр напрямую, журнал — строка
// запуска как у main.ts, перезапуск — новый сервер на том же порту (новый сертификат сервера). Процесс main.ts на
// PostgreSQL и operator.mjs — в tests/unit/acceptance.test.ts (CI).
import { X509Certificate } from "node:crypto";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { accepted, CHECK_IDS, normFingerprint, report, runAcceptance, startupEntry, type CheckResult } from "../../scripts/acceptance/checks.js";
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
    expect(r["1"]?.actual).toMatch(/^проверен, TLSv1\.3, /);
    expect(r["2"]?.actual).toMatch(/^отказ: .*PROTOCOL_VERSION/);
    // TLS 1.3 с SSL_OP_NO_TICKET: OpenSSL выдаёт билет с состоянием на сервере, а кэша сессий у сервера Node нет —
    // повтор с билетом идёт полным рукопожатием (К2.2): проверка действительно пробует возобновление.
    expect(r["3"]?.actual).toBe("билет выдан, но полное рукопожатие");
    expect(r["6"]?.actual).toBe("401 AGENT_UNKNOWN");
    expect(r["8"]?.actual).toBe("отказ: APPLICATION_INCOMPLETE");
    expect(r["11"]?.actual).toBe("401 SIGNATURE_INVALID");
    expect(r["12"]?.actual).toContain("= сроку сертификата сервера");
    expect(r["13.1"]?.actual).toContain("сертификат новый");
    expect(s.calls).toEqual(["admit", "admit", "revoke", "journal", "restart", "journal", "close"]);
  }, 60_000);

  it("перезапуска не было (restart ничего не сделал) — 13.1 не пройдена: сертификат сервера прежний (КТ1 № 4)", async () => {
    const s = await sandbox();
    const rs = await runAcceptance({ host: HOST, port: s.port, caPem: s.rootPem, fingerprint: s.ca.fingerprint }, { ...s.op, restart: async () => {} }, { ticketWaitMs: 100 });
    expect(rs.filter((r) => !r.ok).map((r) => r.id)).toEqual(["13.1"]);
    expect(byId(rs)["13.1"]?.actual).toContain("сертификат прежний");
  }, 60_000);

  it("журнал другого экземпляра с тем же УЦ — 12 и 13.12 не пройдены: срок не равен сертификату по TLS (КТ1 № 11)", async () => {
    const s = await sandbox();
    const other = `${JSON.stringify({ msg: "УЦ песочницы загружен", ca_fingerprint: s.ca.fingerprint, server_cert_not_after: "2030-01-01T00:00:00.000Z" })}\n`;
    const rs = await runAcceptance({ host: HOST, port: s.port, caPem: s.rootPem, fingerprint: s.ca.fingerprint }, { ...s.op, journal: async () => other }, { ticketWaitMs: 100 });
    expect(rs.filter((r) => !r.ok).map((r) => r.id)).toEqual(["12", "13.12"]);
    expect(byId(rs)["12"]?.actual).toContain("≠ сроку сертификата сервера");
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
    expect(r["2"]?.ok, "сервер отказывает по версии раньше проверки корня клиентом").toBe(true);
    expect(r["5"]?.actual).toMatch(/^ошибка: /);
    expect(r["12"]?.actual).toBe("ошибка: INVOCATION_UNKNOWN");
    expect(r["13"]?.ok).toBe(false);
    expect(r["13.1"]?.actual).toBe("не выполнялся");
    expect(accepted(rs)).toBe(false);
  }, 60_000);

  it("порт закрыт — TLS 1.2 не засчитан: ECONNREFUSED — не отказ по версии (КТ1 № 2)", async () => {
    const s = await sandbox();
    await app?.close();
    app = undefined;
    const rs = await runAcceptance({ host: HOST, port: s.port, caPem: s.rootPem, fingerprint: s.ca.fingerprint }, s.op, {
      ticketWaitMs: 100,
      readyTimeoutMs: 1_000,
    });
    expect(byId(rs)["2"]).toMatchObject({ ok: false, actual: "отказ: ECONNREFUSED" });
    expect(accepted(rs)).toBe(false);
  }, 60_000);
});

// Контрольный сервер (КТ1 № 1–3): обычный https.createServer от того же УЦ — TLS 1.2 принимает, сессии возобновляет
// (билеты по умолчанию), сертификат клиента не запрашивает (requestCert: false — без отключения проверки, CodeQL; К2.0):
// /pao/v1/agent с кодом агента — 200, без кода — 401 AGENT_UNKNOWN. Проверки 2, 3, 6 и 9 должны это поймать.
async function control(maxVersion: "TLSv1.2" | "TLSv1.3"): Promise<CheckResult[]> {
  const ca = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 1 });
  const cert = ca.issueServerCertificate([HOST], new Date(), 1, 300);
  const server = createHttpsServer(
    {
      key: cert.privateKey.export({ format: "pem", type: "pkcs8" }),
      cert: new X509Certificate(cert.certificateDer).toString(),
      requestCert: false,
      minVersion: "TLSv1.2",
      maxVersion,
    },
    (req, res) => {
      const code = req.headers["x-agent-code"];
      res.setHeader("content-type", "application/json");
      if (req.url === "/pao/v1/agent" && typeof code === "string") res.end(JSON.stringify({ agent_code: code }));
      else if (req.url === "/pao/v1/agent") res.writeHead(401).end(JSON.stringify({ code: "AGENT_UNKNOWN" }));
      else res.end("{}");
    },
  );
  await new Promise<void>((resolve) => server.listen(0, HOST, resolve));
  const port = (server.address() as AddressInfo).port;
  // Допуск — выпуск сертификата тем же УЦ по CSR заявления, как реестр.
  const op: OperatorPort = {
    admit: async (application) => {
      if (typeof application.csr !== "string") return { admitted: false, reasons: ["APPLICATION_INCOMPLETE"] };
      const issued = ca.issueAgentCertificate(application.csr, String(application.agent_code), new Date(), 1, 300);
      if (!issued.ok) return { admitted: false, reasons: ["KEY_INVALID"] };
      return { admitted: true, agent_code: String(application.agent_code), certificate: { serial: issued.certificate.serial, der: issued.certificate.der, not_after: issued.certificate.not_after } };
    },
    revoke: async () => true,
    journal: async () => "",
    restart: async () => {},
    close: async () => {},
  };
  try {
    return await runAcceptance({ host: HOST, port, caPem: new X509Certificate(ca.certificateDer).toString(), fingerprint: ca.fingerprint }, op, {
      ticketWaitMs: 1_000,
      readyTimeoutMs: 1_000,
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// Второй контрольный сервер (сессия 57 К4.1, вариант (А) владельца): сертификат клиента проверяется честно
// (requestCert: true, rejectUnauthorized: true), но доверенный корень — чужой УЦ проверки 9 (foreignCa). Проверка 9 должна
// провалиться потому, что принят сертификат чужого УЦ, а не потому, что сертификат не нужен (как у первого сервера).
async function controlForeign(): Promise<{ rs: CheckResult[]; authorized: boolean[] }> {
  const own = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 1 });
  const foreign = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 1 });
  const cert = own.issueServerCertificate([HOST], new Date(), 1, 300);
  const authorized: boolean[] = [];
  const server = createHttpsServer(
    {
      key: cert.privateKey.export({ format: "pem", type: "pkcs8" }),
      cert: new X509Certificate(cert.certificateDer).toString(),
      ca: [new X509Certificate(foreign.certificateDer).toString()],
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    },
    (req, res) => {
      const code = req.headers["x-agent-code"];
      res.setHeader("content-type", "application/json");
      if (req.url === "/pao/v1/agent" && typeof code === "string") {
        authorized.push((req.socket as TLSSocket).authorized);
        res.end(JSON.stringify({ agent_code: code }));
      } else res.writeHead(401).end(JSON.stringify({ code: "AGENT_UNKNOWN" }));
    },
  );
  await new Promise<void>((resolve) => server.listen(0, HOST, resolve));
  const port = (server.address() as AddressInfo).port;
  const op: OperatorPort = {
    admit: async () => ({ admitted: false, reasons: ["APPLICATION_INCOMPLETE"] }),
    revoke: async () => true,
    journal: async () => "",
    restart: async () => {},
    close: async () => {},
  };
  try {
    const rs = await runAcceptance({ host: HOST, port, caPem: new X509Certificate(own.certificateDer).toString(), fingerprint: own.fingerprint }, op, {
      ticketWaitMs: 100,
      readyTimeoutMs: 1_000,
      foreignCa: foreign,
    });
    return { rs, authorized };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

describe("второй контрольный сервер: чужой УЦ в доверенных (сессия 57 К4.1)", () => {
  it("сертификат клиента проверен честно (authorized), но корень — чужой УЦ: проверка 9 — 200, не пройдена", async () => {
    const { rs, authorized } = await controlForeign();
    expect(byId(rs)["9"]).toMatchObject({ ok: false, actual: "200" });
    // Принят именно проверенный сертификат чужого УЦ — не обход проверки сертификата.
    expect(authorized).toEqual([true]);
    expect(accepted(rs)).toBe(false);
  }, 60_000);
});

describe("контрольный сервер: проверки умеют провалиться", () => {
  it("TLS 1.2 принят — 2; сессия возобновлена — 3; подписанный запрос без сертификата — 200 — 6; чужой УЦ — 200 — 9", async () => {
    const rs = await control("TLSv1.3");
    const r = byId(rs);
    expect(r["2"]).toMatchObject({ ok: false, actual: "соединение установлено (TLSv1.2)" });
    expect(r["3"]).toMatchObject({ ok: false, actual: "сессия возобновлена" });
    expect(r["6"]).toMatchObject({ ok: false, actual: "200" });
    expect(r["9"]).toMatchObject({ ok: false, actual: "200" });
    expect(accepted(rs)).toBe(false);
  }, 60_000);

  it("сервер только с TLS 1.2 — 1 не пройдена, хотя сертификат проверен по корню (КТ1 № 2)", async () => {
    const r = byId(await control("TLSv1.2"));
    expect(r["1"]?.ok).toBe(false);
    expect(r["1"]?.actual).toMatch(/^проверен, TLSv1\.2, /);
  }, 60_000);
});

describe("разбор и итог", () => {
  it("неполный набор при всех пройденных — «не принято» (КТ1 № 7)", () => {
    const all: CheckResult[] = CHECK_IDS.map((id) => ({ id, name: id, expected: "", actual: "", ok: true }));
    expect(accepted(all)).toBe(true);
    expect(accepted(all.filter((r) => r.id !== "13.5"))).toBe(false);
  });

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
