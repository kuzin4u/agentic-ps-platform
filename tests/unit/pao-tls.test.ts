// П9 TLS песочницы и ступень 0 через настоящее рукопожатие (РП66 п. 1, 3, 4; К3.2): сервер Платформы с сертификатом от УЦ
// песочницы, requestCert без обрыва рукопожатия, только TLS 1.3; сертификат клиента — из сокета один раз за обращение,
// authorized TLS — условие ступени 0 (дополнение чата 1). Ответ на отказ канала — побайтно как у неизвестного агента,
// в журнале — вид причины без серийного номера, DER и SAN (КТ1 № 8). Часы — системные: TLS проверяет срок по ним.
import { X509Certificate, type KeyObject } from "node:crypto";
import { once } from "node:events";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import { TLSSocket, connect as tlsConnect } from "node:tls";
import { newEd25519Signer, signRequest, type Signer } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PaoRequestVerifier, paoIdempotency } from "../../src/pao/index.js";
import { clientCertificate } from "../../src/pao/routes.js";
import { AgentKeys, AgentRegistry, ED25519, InMemoryAgentRegistryStore, SandboxCa, parseKey } from "../../src/registry/index.js";
import type { AgentCertificateRecord } from "../../src/registry/model.js";
import { buildServer, parseTlsHostnames, TLS_MIN_VERSION } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { memoryConsent } from "../support/consent.js";
import { newCsr } from "../support/csr.js";

const params = loadParams();
const HOST = "127.0.0.1";
const pem = (der: Buffer): string => new X509Certificate(der).toString();
const keyPem = (k: KeyObject): string => k.export({ format: "pem", type: "pkcs8" }) as string;

let n = 0;
const uid = (): string => `tls${++n}x${Date.now().toString(36)}`;

interface Agent {
  readonly code: string;
  readonly signer: Signer;
  readonly cert: Buffer;
  readonly key: KeyObject;
  readonly serial: string;
}

interface Running {
  readonly app: FastifyInstance;
  readonly port: number;
  readonly ca: SandboxCa;
  readonly registry: AgentRegistry;
  readonly logs: string[];
  /** Чтения записи сертификата ступенью 0 — по серийному номеру. */
  readonly reads: string[];
  admit(): Promise<Agent>;
}

const opened: FastifyInstance[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  while (opened.length > 0) await opened.pop()?.close();
});

async function start(): Promise<Running> {
  const now = (): Date => new Date();
  const ca = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: params.sandbox_ca_ttl_days });
  const store = new InMemoryAgentRegistryStore();
  const certs = { ca, ttlDays: params.agent_cert_ttl_days, backdateSec: params.cert_not_before_backdate_sec, required: true };
  const registry = new AgentRegistry(store, { keys: params, now, certificates: certs });
  const keys = new AgentKeys(store, { keys: params, now });
  const reads: string[] = [];
  const verifier = new PaoRequestVerifier(
    { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
    {
      skewSec: params.signature_skew_sec,
      now,
      mtls: {
        ca: new X509Certificate(ca.certificateDer),
        getCertificate: async (serial): Promise<AgentCertificateRecord | undefined> => {
          reads.push(serial);
          return registry.getCertificate(serial);
        },
        ticketMaxAgeMs: params.revocation_propagation_max_ms,
      },
    },
  );
  const server = ca.issueServerCertificate([HOST, "localhost"], now(), params.agent_cert_ttl_days, params.cert_not_before_backdate_sec);
  const logs: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      logs.push(String(chunk));
      cb();
    },
  });
  const app = buildServer({
    env: "sandbox",
    logger: { level: "info", stream },
    tls: { key: server.privateKey, certificateDer: server.certificateDer, caDer: ca.certificateDer },
    pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    paoConfiguration: { contour: "sandbox", params },
  });
  opened.push(app);
  await app.listen({ host: HOST, port: 0 });
  const port = (app.server.address() as AddressInfo).port;
  const admit = async (): Promise<Agent> => {
    const code = `nspk:agent:${uid()}:v1`;
    const { signer, publicKey } = newEd25519Signer("tmp");
    const { kid } = parseKey([ED25519], "ed25519", publicKey) as { kid: string };
    const csr = newCsr();
    const d = await registry.admit(
      { agent_code: code, class: "BUYER", model: "m", runtime: "r", alg: "ed25519", public_key: publicKey, csr: csr.csr },
      { contour: "sandbox", operator: "op" },
    );
    if (!d.admitted || !d.certificate) throw new Error("допуск с сертификатом не прошёл");
    return { code, signer: { ...signer, kid }, cert: Buffer.from(d.certificate.der, "base64"), key: csr.privateKey, serial: d.certificate.serial };
  };
  return { app, port, ca, registry, logs, reads, admit };
}

interface Reply {
  readonly status: number;
  readonly body: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly reused: boolean;
  readonly session?: Buffer;
}

interface CallOptions {
  readonly path?: string;
  readonly client?: { readonly cert: Buffer; readonly key: KeyObject };
  /** Подписать обращение этим агентом (x-agent-code — его код, если не задан codeHeader). */
  readonly sign?: Agent;
  readonly codeHeader?: string;
  readonly agent?: HttpsAgent;
  readonly session?: Buffer;
  readonly maxVersion?: "TLSv1.2" | "TLSv1.3";
}

let nonce = 0;
function call(r: Running, o: CallOptions = {}): Promise<Reply> {
  const path = o.path ?? "/pao/v1/agent";
  let headers: Record<string, string> = {};
  if (o.sign) {
    const s = signRequest(
      {
        method: "GET",
        path,
        query: "",
        headers: { "x-agent-code": o.codeHeader ?? o.sign.code, "x-timestamp": new Date().toISOString(), "x-nonce": `t-${++nonce}` },
        body: "",
      },
      o.sign.signer,
    );
    headers = s.headers as Record<string, string>;
  }
  return new Promise((resolve, reject) => {
    let session: Buffer | undefined;
    const req = httpsRequest(
      {
        host: HOST,
        port: r.port,
        path,
        method: "GET",
        headers,
        ca: pem(r.ca.certificateDer),
        ...(o.client ? { cert: pem(o.client.cert), key: keyPem(o.client.key) } : {}),
        ...(o.agent ? { agent: o.agent } : { agent: false }),
        ...(o.session ? { session: o.session } : {}),
        ...(o.maxVersion ? { maxVersion: o.maxVersion } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        const socket = res.socket as TLSSocket;
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers,
            reused: socket.isSessionReused(),
            ...(session ? { session } : {}),
          }),
        );
      },
    );
    req.on("socket", (s) => s.on("session", (b: Buffer) => (session = b)));
    req.on("error", reject);
    req.end();
  });
}

/** Записи журнала ступени 0. */
const channelLogs = (r: Running): Record<string, unknown>[] =>
  r.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => "pao_channel" in l);

describe("TLS песочницы: рукопожатие и ступень 0 (РП66 п. 1, 3)", () => {
  it("сертификат агента — 200; сертификат клиента запрошен, сервер — сертификат от УЦ песочницы по имени адреса", async () => {
    const r = await start();
    const a = await r.admit();
    const res = await call(r, { client: a, sign: a });
    expect(res.status, res.body).toBe(200);
    expect(JSON.parse(res.body)).toMatchObject({ agent_code: a.code });
  });

  it("сертификат чужого УЦ — 401 AGENT_UNKNOWN, вид причины TLS_NOT_AUTHORIZED (authorized TLS, дополнение 1)", async () => {
    const r = await start();
    const a = await r.admit();
    const foreign = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 3650 });
    const csr = newCsr();
    const issued = foreign.issueAgentCertificate(csr.csr, a.code, new Date(), 90, 300);
    if (!issued.ok) throw new Error("выпуск");
    const res = await call(r, { client: { cert: Buffer.from(issued.certificate.der, "base64"), key: csr.privateKey }, sign: a });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body)).toMatchObject({ code: "AGENT_UNKNOWN" });
    expect(channelLogs(r).map((l) => l.pao_channel)).toEqual(["TLS_NOT_AUTHORIZED"]);
  });

  it("без сертификата — 401 AGENT_UNKNOWN / NO_CERTIFICATE: рукопожатие не оборвано, решение — в приложении", async () => {
    const r = await start();
    const a = await r.admit();
    const res = await call(r, { sign: a });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body)).toMatchObject({ code: "AGENT_UNKNOWN" });
    expect(channelLogs(r).map((l) => l.pao_channel)).toEqual(["NO_CERTIFICATE"]);
  });

  it("отозванный — 401 AGENT_UNKNOWN / REVOKED", async () => {
    const r = await start();
    const a = await r.admit();
    await r.registry.revokeCertificate(a.serial);
    const res = await call(r, { client: a, sign: a });
    expect(res.status).toBe(401);
    expect(channelLogs(r).map((l) => l.pao_channel)).toEqual(["REVOKED"]);
  });

  it("SAN ≠ x-agent-code — агент B со своей подписью по каналу A — 401 AGENT_UNKNOWN / CODE_MISMATCH", async () => {
    const r = await start();
    const a = await r.admit();
    const b = await r.admit();
    const res = await call(r, { client: a, sign: b });
    expect(res.status).toBe(401);
    expect(channelLogs(r).map((l) => l.pao_channel)).toEqual(["CODE_MISMATCH"]);
  });

  it("/health и /.well-known/pao-configuration — без сертификата клиента, 200", async () => {
    const r = await start();
    expect((await call(r, { path: "/health" })).status).toBe(200);
    expect((await call(r, { path: "/.well-known/pao-configuration" })).status).toBe(200);
  });

  it("клиент только TLS 1.2 — рукопожатие отклонено (только TLS 1.3, В3)", async () => {
    const r = await start();
    const a = await r.admit();
    expect(TLS_MIN_VERSION).toBe("TLSv1.3");
    await expect(call(r, { client: a, sign: a, maxVersion: "TLSv1.2" })).rejects.toThrow();
  });

  it("keep-alive: отзыв между двумя обращениями одного соединения — второе 401 (отзыв на каждом обращении)", async () => {
    const r = await start();
    const a = await r.admit();
    const agent = new HttpsAgent({ keepAlive: true, maxSockets: 1 });
    let connections = 0;
    r.app.server.on("secureConnection", () => connections++);
    try {
      const first = await call(r, { client: a, sign: a, agent });
      expect(first.status).toBe(200);
      await r.registry.revokeCertificate(a.serial);
      const second = await call(r, { client: a, sign: a, agent });
      expect(second.status).toBe(401);
      expect(connections).toBe(1);
    } finally {
      agent.destroy();
    }
  });
});

describe("возобновлённая сессия TLS 1.3 (дополнение чата 3)", () => {
  it("сессия с сертификатом — сертификат доступен при возобновлении: 200", async () => {
    const r = await start();
    const a = await r.admit();
    const first = await call(r, { client: a, sign: a });
    expect(first.status).toBe(200);
    expect(first.session).toBeDefined();
    const resumed = await call(r, { client: a, sign: a, session: first.session as Buffer });
    expect(resumed.reused).toBe(true);
    expect(resumed.status, resumed.body).toBe(200);
  });

  it("сессия без сертификата — при возобновлении сертификата нет (null): 401 AGENT_UNKNOWN / NO_CERTIFICATE", async () => {
    const r = await start();
    const a = await r.admit();
    const first = await call(r, { path: "/health" });
    expect(first.session).toBeDefined();
    // Клиент предъявляет сертификат в опциях, но сессия возобновлена — сертификат не передаётся.
    const resumed = await call(r, { client: a, sign: a, session: first.session as Buffer });
    expect(resumed.reused).toBe(true);
    expect(resumed.status).toBe(401);
    expect(channelLogs(r).map((l) => l.pao_channel)).toEqual(["NO_CERTIFICATE"]);
  });
});

describe("сертификат клиента — одно чтение за обращение (КТ1 № 5, нюанс 7 РП66)", () => {
  it("сокет — один раз; agent_certificates — один раз (отметка предпроверки)", async () => {
    const r = await start();
    const a = await r.admit();
    const spy = vi.spyOn(TLSSocket.prototype, "getPeerX509Certificate");
    const res = await call(r, { client: a, sign: a });
    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(r.reads).toEqual([a.serial]);
  });

  it("закрытое соединение — сертификата нет, а не исключение (getPeerCertificate отдал бы null)", async () => {
    const r = await start();
    const a = await r.admit();
    const server = new Promise<TLSSocket>((resolve) => r.app.server.once("secureConnection", (s: TLSSocket) => resolve(s)));
    const client = tlsConnect({ host: HOST, port: r.port, ca: pem(r.ca.certificateDer), cert: pem(a.cert), key: keyPem(a.key) });
    const s = await server;
    expect(clientCertificate({ raw: { socket: s } } as never)?.authorized).toBe(true);
    const closed = once(s, "close");
    s.destroy();
    client.destroy();
    await closed;
    expect(() => clientCertificate({ raw: { socket: s } } as never)).not.toThrow();
    expect(clientCertificate({ raw: { socket: s } } as never)).toBeUndefined();
  });
});

describe("ответ и журнал отказа канала (КТ1 № 8)", () => {
  it("401 побайтно как у неизвестного агента без mTLS: статус, тело, тип содержимого, без Retry-After", async () => {
    const r = await start();
    const a = await r.admit();
    const viaChannel = await call(r, { sign: a });
    // Неизвестный агент на сервере без TLS и ступени 0 — тот же код ответа ПАО §6.
    const plainKeys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const plain = buildServer({
      env: "sandbox",
      pao: {
        verifier: new PaoRequestVerifier({ getAgent: async () => undefined, lookupKey: async () => undefined }, { skewSec: params.signature_skew_sec }),
        keys: plainKeys,
        idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }),
        params,
        consent: memoryConsent(),
      },
    });
    opened.push(plain);
    const unknown = await plain.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": "nspk:agent:nobody:v1" } });
    expect(viaChannel.status).toBe(unknown.statusCode);
    expect(viaChannel.body).toBe(unknown.body);
    expect(viaChannel.headers["content-type"]).toBe(unknown.headers["content-type"]);
    expect(viaChannel.headers["retry-after"]).toBeUndefined();
  });

  it("журнал: вид причины есть, серийного номера, DER и SAN нет", async () => {
    const r = await start();
    const a = await r.admit();
    const b = await r.admit();
    await call(r, { client: a, sign: b });
    await r.registry.revokeCertificate(a.serial);
    await call(r, { client: a, sign: a });
    const lines = channelLogs(r);
    expect(lines.map((l) => l.pao_channel)).toEqual(["CODE_MISMATCH", "REVOKED"]);
    const text = r.logs.join("\n");
    for (const secret of [a.serial, a.serial.toUpperCase(), a.cert.toString("base64").slice(0, 40), `urn:${a.code}`, "urn:"]) {
      expect(text, secret).not.toContain(secret);
    }
  });
});

describe("TLS и ступень 0 — только вместе (В1, дополнение к РП66)", () => {
  const deps = (mtls: boolean) => {
    const ca = SandboxCa.generate({ now: new Date(), ttlDays: 3650 });
    const verifier = new PaoRequestVerifier(
      { getAgent: async () => undefined, lookupKey: async () => undefined },
      { skewSec: 300, ...(mtls ? { mtls: { ca: new X509Certificate(ca.certificateDer), getCertificate: async () => undefined, ticketMaxAgeMs: 1000 } } : {}) },
    );
    const keys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const pao = { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() };
    const s = ca.issueServerCertificate(["localhost"], new Date(), 90, 300);
    return { pao, tls: { key: s.privateKey, certificateDer: s.certificateDer, caDer: ca.certificateDer } };
  };

  it("TLS без ступени 0 — отказ запуска", () => {
    const d = deps(false);
    expect(() => buildServer({ env: "sandbox", pao: d.pao, tls: d.tls })).toThrow(/TLS без ступени 0/);
  });

  it("ступень 0 без TLS — отказ запуска", () => {
    expect(() => buildServer({ env: "sandbox", pao: deps(true).pao })).toThrow(/ступень 0 без TLS/);
  });

  it("оба выключены и оба включены — запуск", async () => {
    const off = buildServer({ env: "sandbox", pao: deps(false).pao });
    const d = deps(true);
    const on = buildServer({ env: "sandbox", pao: d.pao, tls: d.tls });
    opened.push(off, on);
    expect((await off.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
  });
});

describe("PLATFORM_TLS_HOSTNAMES — имена сертификата сервера (РП66 п. 4; КТ1 К3.2 № 7)", () => {
  it("DNS и IP через запятую, пробелы вокруг — отбрасываются", () => {
    expect(parseTlsHostnames("platform.sandbox.local, localhost,127.0.0.1 , ::1")).toEqual(["platform.sandbox.local", "localhost", "127.0.0.1", "::1"]);
  });

  it.each([
    ["нет", undefined],
    ["пусто", ""],
    ["только запятые и пробелы", " , ,"],
    ["верхний регистр", "Platform.local"],
    ["шаблон «*»", "*.platform.local"],
    ["зона IPv6", "fe80::1%eth0"],
    ["№ 7: IPv4 вне диапазона", "localhost,256.1.1.1"],
    ["№ 7: ведущий ноль", "01.2.3.4"],
    ["№ 7: три октета", "1.2.3"],
  ])("%s — исключение (STARTUP_PARAMS_INVALID в main.ts)", (_n, value) => {
    expect(() => parseTlsHostnames(value)).toThrow(/PLATFORM_TLS_HOSTNAMES/);
  });

  it("принятые имена выпускаются в сертификат сервера без исключения (одно правило — isServerName)", () => {
    const names = parseTlsHostnames("platform.sandbox.local,1.2.3.example,10.0.0.1,::ffff:10.0.0.1");
    const ca = SandboxCa.generate({ now: new Date(), ttlDays: 3650 });
    const cert = new X509Certificate(ca.issueServerCertificate(names, new Date(), 90, 300).certificateDer);
    expect(cert.checkHost("1.2.3.example")).toBe("1.2.3.example");
    expect(cert.checkIP("10.0.0.1")).toBe("10.0.0.1");
  });
});
