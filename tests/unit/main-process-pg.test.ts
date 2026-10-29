// Дымовой тест рабочей сборки на PostgreSQL (решение владельца 27.10, PS-05в ч. 2б-2 К3а; РП64 п. 7): src/main.ts —
// отдельным процессом с DATABASE_URL на пустой схеме. Самопроверка применяет миграции (sql/120 — реестр агентов),
// /health отвечает, а реестр читается из базы: агент, допущенный в эту схему другим пулом, виден в каталоге ключей
// процесса. Процесс — без оболочки, остановка по номеру. В CI (РП30 п. 7); локально без базы — пропуск.
import { spawn, type ChildProcess } from "node:child_process";
import { X509Certificate, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signRequest, type Signer } from "@kuzin4u/agentic-core";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AgentRegistry, initCaFile, loadCaFile, PgAgentRegistryStore, SandboxCa } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { newCsr } from "../support/csr.js";
import { DATABASE_URL } from "../support/pg.js";

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      s.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("порт не получен"))));
    });
  });

/** Код ошибки попытки готовности: свой code (ERR_TLS_…, ECONNREFUSED), у fetch — cause.code, иначе имя класса. */
const readyError = (e: unknown): string => {
  const x = e as { code?: unknown; cause?: { code?: unknown }; name?: unknown } | null;
  return String(x?.code ?? x?.cause?.code ?? x?.name ?? typeof e);
};

const stop = (child: ChildProcess): Promise<number | null> =>
  new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(child.exitCode);
    child.once("exit", (code) => resolve(code));
    child.kill("SIGTERM");
  });

describe.skipIf(!DATABASE_URL)("рабочая сборка src/main.ts на PostgreSQL (dev, DATABASE_URL; РП64 п. 7)", () => {
  const schema = `t_${process.pid}_${Date.now()}_mainpg`;
  let admin: pg.Pool;
  let pool: pg.Pool;
  let url: string;
  let child: ChildProcess | undefined;

  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Пустая схема: миграции применяет сам main.ts. search_path — параметром строки подключения (и пул, и миграции).
    const u = new URL(DATABASE_URL as string);
    u.searchParams.set("options", `-c search_path=${schema}`);
    url = u.toString();
    pool = new pg.Pool({ connectionString: url, max: 2 });
  });
  afterAll(async () => {
    if (child) await stop(child);
    await pool?.end();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
  });

  it("миграции применены самопроверкой, /health — 200, реестр агентов — из базы (агент другого пула в каталоге ключей)", async () => {
    const port = await freePort();
    const env: NodeJS.ProcessEnv = { ...process.env, PLATFORM_ENV: "dev", PORT: String(port), HOST: "127.0.0.1", DATABASE_URL: url };
    for (const k of ["PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    const proc = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], { env, stdio: ["ignore", "pipe", "pipe"] });
    child = proc;
    let out = "";
    proc.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    const base = `http://127.0.0.1:${port}`;

    let ready = false;
    let last = "";
    for (let i = 0; i < 150 && !ready; i++) {
      expect(proc.exitCode, out).toBeNull();
      ready = await fetch(`${base}/health`).then(
        (r) => ((last = `HTTP ${r.status}`), r.status === 200),
        (e: unknown) => ((last = readyError(e)), false),
      );
      if (!ready) await new Promise((r) => setTimeout(r, 200));
    }
    expect(ready, `последняя ошибка готовности: ${last}\n${out}`).toBe(true);

    // Миграции — в этой схеме, включая реестр агентов (sql/120).
    const applied = (await pool.query<{ name: string }>("SELECT name FROM core_migrations")).rows.map((r) => r.name);
    expect(applied).toContain("120_agent_registry.sql");
    expect(out).not.toContain("DATABASE_URL не задан");

    // Агент допущен в эту схему другим пулом — процесс видит его ключ: реестр читается из базы, не из своей памяти.
    const code = `nspk:agent:mainpg-${Date.now().toString(36)}:v1`;
    const decision = await new AgentRegistry(new PgAgentRegistryStore(pool), { keys: loadParams() }).admit(buyerApplication(code, newAgentSide()), {
      contour: "sandbox",
      operator: "op-main-pg",
    });
    expect(decision.admitted).toBe(true);
    const jwks = await fetch(`${base}/.well-known/agent-keys`);
    expect(jwks.status).toBe(200);
    expect(((await jwks.json()) as { keys: { agent_code: string }[] }).keys.map((k) => k.agent_code)).toContain(code);

    expect(await stop(proc)).toBe(0);
    child = undefined;
  }, 90_000);
});

// Рабочая сборка sandbox на PostgreSQL с настоящим рукопожатием (SEC-1-код ч. 2б-2 К4.1; РП66 п. 3, 4, 6, 7; КТ1 К3.1 № 6):
// УЦ — файл initCaFile во временном каталоге (0600), имена сервера — PLATFORM_TLS_HOSTNAMES. Сертификат сервера
// проверяется по корню УЦ и имени (checkServerIdentity не отключён); ступень 0 — по реестру на PG той же схемы.
const pem = (der: Buffer): string => new X509Certificate(der).toString();
const keyPem = (k: KeyObject): string => k.export({ format: "pem", type: "pkcs8" }) as string;

interface TlsReply {
  readonly status: number;
  readonly body: string;
}

let nonce = 0;
/** Обращение по TLS: корень — УЦ песочницы, имя — host (проверяется); клиентский сертификат и подпись ПАО — по желанию. */
function tlsCall(
  port: number,
  root: string,
  o: { path: string; host?: string; client?: { cert: Buffer; key: KeyObject }; sign?: { code: string; signer: Signer } },
): Promise<TlsReply> {
  const headers = o.sign
    ? (signRequest(
        {
          method: "GET",
          path: o.path,
          query: "",
          headers: { "x-agent-code": o.sign.code, "x-timestamp": new Date().toISOString(), "x-nonce": `mainpg-${++nonce}` },
          body: "",
        },
        o.sign.signer,
      ).headers as Record<string, string>)
    : {};
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: o.host ?? "127.0.0.1",
        port,
        path: o.path,
        method: "GET",
        headers,
        ca: root,
        agent: false,
        ...(o.client ? { cert: pem(o.client.cert), key: keyPem(o.client.key) } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe.skipIf(!DATABASE_URL)("рабочая сборка src/main.ts sandbox на PostgreSQL: TLS и ступень 0 через рукопожатие (РП66; К4.1)", () => {
  const schema = `t_${process.pid}_${Date.now()}_mainsbx`;
  let admin: pg.Pool;
  let pool: pg.Pool;
  let url: string;
  let child: ChildProcess | undefined;

  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    const u = new URL(DATABASE_URL as string);
    u.searchParams.set("options", `-c search_path=${schema}`);
    url = u.toString();
    pool = new pg.Pool({ connectionString: url, max: 2 });
  });
  afterAll(async () => {
    if (child) await stop(child);
    await pool?.end();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
  });

  it("сертификат агента — 200; без сертификата, чужой УЦ, отозванный — 401; /health, ключи, маршрут банка — без сертификата клиента; http — нет", async () => {
    const params = loadParams();
    const caPath = join(mkdtempSync(join(tmpdir(), "main-sbx-")), "ca.pem");
    // УЦ — с часами минутой раньше: notBefore сертификатов не позже часов процесса.
    const ca = initCaFile(caPath, { now: new Date(Date.now() - 60_000), ttlDays: params.sandbox_ca_ttl_days });
    const root = ca.certificatePem;
    const port = await freePort();
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PLATFORM_ENV: "sandbox",
      PORT: String(port),
      HOST: "127.0.0.1",
      DATABASE_URL: url,
      PLATFORM_CA_KEY_PATH: caPath,
      PLATFORM_TLS_HOSTNAMES: "localhost,127.0.0.1",
    };
    for (const k of ["PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    const proc = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], { env, stdio: ["ignore", "pipe", "pipe"] });
    child = proc;
    let out = "";
    proc.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));

    // Готовность — /health по TLS с проверкой сертификата сервера по корню и адресу 127.0.0.1.
    let ready = false;
    let last = "";
    for (let i = 0; i < 150 && !ready; i++) {
      expect(proc.exitCode, out).toBeNull();
      ready = await tlsCall(port, root, { path: "/health" }).then(
        (r) => ((last = `HTTP ${r.status}`), r.status === 200),
        (e: unknown) => ((last = readyError(e)), false),
      );
      if (!ready) await new Promise((r) => setTimeout(r, 200));
    }
    // Красный тест сам называет причину (ERR_TLS_CERT_ALTNAME_INVALID и т. п.), а не только «expected false» (КТ1 К3.1).
    expect(ready, `последняя ошибка готовности: ${last}\n${out}`).toBe(true);

    // Имя localhost — тоже из PLATFORM_TLS_HOSTNAMES; обнаружение ПАО и каталог ключей — без сертификата клиента.
    expect((await tlsCall(port, root, { path: "/health", host: "localhost" })).status).toBe(200);
    expect((await tlsCall(port, root, { path: "/.well-known/pao-configuration" })).status).toBe(200);
    expect((await tlsCall(port, root, { path: "/.well-known/agent-keys" })).status).toBe(200);
    // Маршрут банка (ПИ-8, лента уведомлений) по TLS без клиентского сертификата — ответ слоя участника, как без TLS:
    // неподписанный запрос — 401 SIGNATURE_INVALID, а не обрыв рукопожатия.
    const bank = await tlsCall(port, root, { path: "/participants/v1/notifications" });
    expect(bank.status, bank.body).toBe(401);
    expect(JSON.parse(bank.body)).toEqual({ code: "SIGNATURE_INVALID" });
    // http:// на порт TLS — не обслуживается.
    await expect(fetch(`http://127.0.0.1:${port}/health`)).rejects.toThrow();

    // Журнал запуска: отпечаток УЦ из файла, имена, срок сертификата сервера (КТ1 К3.1 № 1).
    const started = out
      .split("\n")
      .filter((l) => l.startsWith("{"))
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .find((e) => e.msg === "УЦ песочницы загружен");
    expect(started, out).toMatchObject({ ca_fingerprint: ca.fingerprint, tls_hostnames: ["localhost", "127.0.0.1"] });
    expect(typeof started?.server_cert_not_after).toBe("string");

    // Допуск — другим пулом в ту же схему, тем же УЦ из файла, CSR обязателен (как у реестра процесса).
    const registry = new AgentRegistry(new PgAgentRegistryStore(pool), {
      keys: params,
      certificates: {
        ca: loadCaFile(caPath, new Date()),
        ttlDays: params.agent_cert_ttl_days,
        backdateSec: params.cert_not_before_backdate_sec,
        required: true,
      },
    });
    const admit = async () => {
      const code = `nspk:agent:mainsbx-${(++nonce).toString(36)}${Date.now().toString(36)}:v1`;
      const side = newAgentSide();
      const csr = newCsr();
      const d = await registry.admit({ ...buyerApplication(code, side), csr: csr.csr }, { contour: "sandbox", operator: "op-main-sbx" });
      if (!d.admitted || !d.certificate) throw new Error(`допуск с сертификатом не прошёл: ${JSON.stringify(d)}`);
      return { code, signer: side.signer, cert: Buffer.from(d.certificate.der, "base64"), key: csr.privateKey, serial: d.certificate.serial };
    };
    const a = await admit();

    const ok = await tlsCall(port, root, { path: "/pao/v1/agent", client: a, sign: a });
    expect(ok.status, ok.body).toBe(200);
    expect(JSON.parse(ok.body)).toMatchObject({ agent_code: a.code });

    const noCert = await tlsCall(port, root, { path: "/pao/v1/agent", sign: a });
    expect(noCert.status).toBe(401);
    expect(JSON.parse(noCert.body)).toMatchObject({ code: "AGENT_UNKNOWN" });

    // Чужой УЦ: сертификат с тем же кодом агента, но не от УЦ песочницы.
    const foreign = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 3650 });
    const fcsr = newCsr();
    const fissued = foreign.issueAgentCertificate(fcsr.csr, a.code, new Date(), 90, 300);
    if (!fissued.ok) throw new Error("выпуск чужим УЦ не прошёл");
    const alien = await tlsCall(port, root, {
      path: "/pao/v1/agent",
      client: { cert: Buffer.from(fissued.certificate.der, "base64"), key: fcsr.privateKey },
      sign: a,
    });
    expect(alien.status).toBe(401);
    expect(JSON.parse(alien.body)).toMatchObject({ code: "AGENT_UNKNOWN" });

    // Отозванный сертификат — отзыв другим пулом виден процессу на следующем обращении (чтение без кэша, РП64 п. 3).
    const b = await admit();
    expect((await tlsCall(port, root, { path: "/pao/v1/agent", client: b, sign: b })).status).toBe(200);
    await registry.revokeCertificate(b.serial);
    const revoked = await tlsCall(port, root, { path: "/pao/v1/agent", client: b, sign: b });
    expect(revoked.status).toBe(401);
    expect(JSON.parse(revoked.body)).toMatchObject({ code: "AGENT_UNKNOWN" });

    expect(await stop(proc)).toBe(0);
    child = undefined;
  }, 120_000);
});
