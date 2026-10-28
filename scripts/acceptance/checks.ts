// Приёмка развёрнутой песочницы (SANDBOX-ACC К1.2, решение владельца 28.10): 13 проверок против живого процесса по TLS —
// канал (РП66 п. 1, 4, К2.2), открытые пути, ступень 0 (A2 п. 5.1), допуск с CSR (РП65, РП66 п. 3), маршрут банка (РП46 (в)),
// журнал запуска (РП66 п. 6) и перезапуск. Ключи тестового агента — только в памяти этого процесса; Платформе — открытый
// ключ и CSR через порт оператора. Любой сбой проверки — «не пройдена» (fail-closed), а не пропуск.
import { createHash, createPublicKey, generateKeyPairSync, sign, X509Certificate, type KeyObject } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { connect as tlsConnect, type ConnectionOptions, type TLSSocket } from "node:tls";
import { newEd25519Signer, signRequest, type Signer } from "@kuzin4u/agentic-core";
import { SandboxCa } from "../../src/registry/index.js";
import { bitString, oid, seq, set, tlv, uint, utf8 } from "../../src/registry/ca/der.js";
import type { OperatorPort } from "./operator.js";

export interface Target {
  readonly host: string;
  readonly port: number;
  /** Корневой сертификат УЦ песочницы, PEM (вывод ca:init). */
  readonly caPem: string;
  /** Ожидаемый отпечаток SHA-256 корня: hex, регистр и двоеточия не важны. */
  readonly fingerprint: string;
}

export interface CheckResult {
  readonly id: string;
  readonly name: string;
  readonly expected: string;
  readonly actual: string;
  readonly ok: boolean;
}

export interface AcceptanceOptions {
  /** Предел одного сетевого шага. */
  readonly timeoutMs?: number;
  /** Ожидание /health после перезапуска. */
  readonly readyTimeoutMs?: number;
  /** Ожидание билета сессии после рукопожатия (проверка 3). */
  readonly ticketWaitMs?: number;
}

export const normFingerprint = (f: string): string => f.replace(/:/g, "").trim().toLowerCase();

const errCode = (e: unknown): string => {
  const x = e as { code?: unknown; name?: unknown } | undefined;
  return typeof x?.code === "string" ? x.code : typeof x?.name === "string" ? x.name : "UNKNOWN";
};

const tlsBase = (t: Target, timeoutMs: number): ConnectionOptions => ({
  host: t.host,
  port: t.port,
  ca: t.caPem,
  ...(isIP(t.host) === 0 ? { servername: t.host } : {}),
  timeout: timeoutMs,
});

/** Рукопожатие TLS; сокет открыт — закрывает вызывающий. */
function handshake(o: ConnectionOptions, timeoutMs: number): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const s = tlsConnect(o, () => resolve(s));
    s.setTimeout(timeoutMs, () => s.destroy(Object.assign(new Error("timeout"), { code: "TIMEOUT" })));
    s.once("error", reject);
  });
}

interface Reply {
  readonly status: number;
  readonly body: string;
}

interface Agent {
  readonly code: string;
  readonly signer: Signer;
  readonly publicKey: string;
  readonly csr: string;
  readonly certKey: KeyObject;
}

/** Обращение по HTTPS с проверкой сервера по корню и имени; клиентский сертификат и подпись ПАО — по желанию. */
function call(
  t: Target,
  timeoutMs: number,
  path: string,
  o: { client?: { certDer: Buffer; key: KeyObject }; sign?: Agent } = {},
): Promise<Reply> {
  const headers = o.sign
    ? (signRequest(
        {
          method: "GET",
          path,
          query: "",
          headers: { "x-agent-code": o.sign.code, "x-timestamp": new Date().toISOString(), "x-nonce": `acc-${randomTag()}` },
          body: "",
        },
        o.sign.signer,
      ).headers as Record<string, string>)
    : {};
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: t.host,
        port: t.port,
        path,
        method: "GET",
        headers,
        ca: t.caPem,
        agent: false,
        timeout: timeoutMs,
        ...(o.client
          ? { cert: new X509Certificate(o.client.certDer).toString(), key: o.client.key.export({ format: "pem", type: "pkcs8" }) as string }
          : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "TIMEOUT" })));
    req.on("error", reject);
    req.end();
  });
}

const randomTag = (): string => `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

/** Код ошибки ПАО из тела ответа; не JSON — пусто. */
const bodyCode = (r: Reply): string => {
  try {
    const b = JSON.parse(r.body) as { code?: unknown };
    return typeof b.code === "string" ? b.code : "";
  } catch {
    return "";
  }
};
const show = (r: Reply): string => `${r.status}${bodyCode(r) ? ` ${bodyCode(r)}` : ""}`;

/** Отпечаток RFC 7638 открытого ключа Ed25519 — kid агента (РП23 п. 3). */
function agentKid(publicKeySpkiBase64: string): string {
  const jwk = createPublicKey({ key: Buffer.from(publicKeySpkiBase64, "base64"), format: "der", type: "spki" }).export({ format: "jwk" });
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)}}`;
  return createHash("sha256").update(canonical).digest("base64url");
}

/** CSR PKCS#10 по шаблону РП65: P-256, CN, ECDSA-SHA256. */
function newCsr(cn: string): { readonly csr: string; readonly privateKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const info = seq(uint(Buffer.from([0])), seq(set(seq(oid("2.5.4.3"), utf8(cn)))), publicKey.export({ format: "der", type: "spki" }), tlv(0xa0));
  const signature = sign("sha256", info, { key: privateKey, dsaEncoding: "der" });
  return { csr: seq(info, seq(oid("1.2.840.10045.4.3.2")), bitString(signature)).toString("base64"), privateKey };
}

/** Тестовый агент: код acc-*, ключ подписи и ключ сертификата — в памяти. */
function newAgent(): Agent {
  const { signer, publicKey } = newEd25519Signer("unset");
  const kid = agentKid(publicKey);
  const code = `nspk:agent:acc-${randomTag().replace(/[^a-z0-9]/g, "")}:v1`;
  const { csr, privateKey } = newCsr("acceptance");
  return { code, signer: { ...signer, kid }, publicKey, csr, certKey: privateKey };
}

/** Заявление тестового агента (ПС01): класс BUYER, без сведений о принципале. */
const application = (a: Agent, withCsr: boolean): Record<string, unknown> => ({
  agent_code: a.code,
  class: "BUYER",
  model: "sandbox-acceptance",
  runtime: "node",
  alg: "ed25519",
  public_key: a.publicKey,
  ...(withCsr ? { csr: a.csr } : {}),
});

/** Строка журнала запуска «УЦ песочницы загружен» — последняя в выводе текущего запуска. */
export function startupEntry(journal: string): Record<string, unknown> | undefined {
  let found: Record<string, unknown> | undefined;
  for (const line of journal.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const e = JSON.parse(line) as Record<string, unknown>;
      if (e.msg === "УЦ песочницы загружен") found = e;
    } catch {
      // не JSON — пропуск строки
    }
  }
  return found;
}

export async function runAcceptance(t: Target, op: OperatorPort, o: AcceptanceOptions = {}): Promise<CheckResult[]> {
  const timeoutMs = o.timeoutMs ?? 10_000;
  const results: CheckResult[] = [];
  const expectedFp = normFingerprint(t.fingerprint);
  const check = async (id: string, name: string, expected: string, run: () => Promise<{ ok: boolean; actual: string }>) => {
    try {
      const r = await run();
      results.push({ id, name, expected, ...r });
    } catch (e) {
      results.push({ id, name, expected, ok: false, actual: `ошибка: ${errCode(e)}` });
    }
  };

  const serverCert = (id: string) =>
    check(id, "сертификат сервера по корню и имени", `проверен по корню, имя ${t.host}, отпечаток корня = ожидаемому`, async () => {
      const rootFp = normFingerprint(new X509Certificate(t.caPem).fingerprint256);
      const s = await handshake(tlsBase(t, timeoutMs), timeoutMs);
      const authorized = s.authorized;
      const peer = s.getPeerX509Certificate();
      const protocol = s.getProtocol();
      s.destroy();
      const fpOk = rootFp === expectedFp;
      return {
        ok: authorized && fpOk && peer !== undefined,
        actual: `${authorized ? "проверен" : "не проверен"}, ${protocol ?? "?"}, до ${peer ? new Date(peer.validTo).toISOString() : "?"}; корень ${fpOk ? "=" : "≠"} ожидаемому`,
      };
    });

  const openPaths = (id: string) =>
    check(id, "/health и /.well-known/… без сертификата", "200 у каждого", async () => {
      const paths = ["/health", "/.well-known/pao-configuration", "/.well-known/agent-keys"];
      const got = await Promise.all(paths.map((p) => call(t, timeoutMs, p)));
      return { ok: got.every((r) => r.status === 200), actual: got.map((r, i) => `${paths[i]} ${r.status}`).join("; ") };
    });

  const journalCheck = (id: string) =>
    check(id, "журнал запуска", "ca_fingerprint = ожидаемому, есть server_cert_not_after", async () => {
      const e = startupEntry(await op.journal());
      if (!e) return { ok: false, actual: "строки «УЦ песочницы загружен» нет" };
      const fp = typeof e.ca_fingerprint === "string" ? normFingerprint(e.ca_fingerprint) : "";
      const notAfter = typeof e.server_cert_not_after === "string" ? e.server_cert_not_after : "";
      return {
        ok: fp === expectedFp && notAfter !== "",
        actual: `ca_fingerprint ${fp === expectedFp ? "=" : "≠"} ожидаемому; server_cert_not_after ${notAfter || "нет"}`,
      };
    });

  try {
    await serverCert("1");

    await check("2", "TLS 1.2", "отказ рукопожатия", async () => {
      try {
        const s = await handshake({ ...tlsBase(t, timeoutMs), minVersion: "TLSv1.2", maxVersion: "TLSv1.2" }, timeoutMs);
        const p = s.getProtocol();
        s.destroy();
        return { ok: false, actual: `соединение установлено (${p ?? "?"})` };
      } catch (e) {
        return { ok: true, actual: `отказ: ${errCode(e)}` };
      }
    });

    await check("3", "сохранённая сессия", "полное рукопожатие", async () => {
      const first = await handshake(tlsBase(t, timeoutMs), timeoutMs);
      // TLS 1.3: билет приходит после рукопожатия; сервер без билетов (SSL_OP_NO_TICKET) его не присылает.
      const session = await new Promise<Buffer | undefined>((resolve) => {
        const timer = setTimeout(() => resolve(undefined), o.ticketWaitMs ?? 1000);
        first.once("session", (s: Buffer) => {
          clearTimeout(timer);
          resolve(s);
        });
      });
      first.destroy();
      if (!session) return { ok: true, actual: "билета сессии нет — возобновлять нечего" };
      const second = await handshake({ ...tlsBase(t, timeoutMs), session }, timeoutMs);
      const reused = second.isSessionReused();
      second.destroy();
      return { ok: !reused, actual: reused ? "сессия возобновлена" : "билет выдан, но полное рукопожатие" };
    });

    await check("4", "http://", "отказ", async () => {
      try {
        const status = await new Promise<number>((resolve, reject) => {
          const req = httpRequest({ host: t.host, port: t.port, path: "/health", agent: false, timeout: timeoutMs }, (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          });
          req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "TIMEOUT" })));
          req.on("error", reject);
          req.end();
        });
        return { ok: status >= 400, actual: `ответ ${status}` };
      } catch (e) {
        return { ok: true, actual: `отказ: ${errCode(e)}` };
      }
    });

    await openPaths("5");

    await check("6", "/pao/v1/agent без сертификата", "401 AGENT_UNKNOWN", async () => {
      const r = await call(t, timeoutMs, "/pao/v1/agent");
      return { ok: r.status === 401 && bodyCode(r) === "AGENT_UNKNOWN", actual: show(r) };
    });

    const a = newAgent();
    let cert: { der: Buffer; serial: string } | undefined;
    await check("7", "допуск с CSR → /pao/v1/agent с сертификатом", "допущен, 200, свой agent_code", async () => {
      const d = await op.admit(application(a, true));
      if (!d.admitted || !d.certificate) return { ok: false, actual: `не допущен: ${(d.reasons ?? ["без сертификата"]).join(", ")}` };
      cert = { der: Buffer.from(d.certificate.der, "base64"), serial: d.certificate.serial };
      const r = await call(t, timeoutMs, "/pao/v1/agent", { client: { certDer: cert.der, key: a.certKey }, sign: a });
      let code = "";
      try {
        code = String((JSON.parse(r.body) as { agent_code?: unknown }).agent_code ?? "");
      } catch {
        // не JSON — пусто
      }
      return { ok: r.status === 200 && code === a.code, actual: `допущен, серийный ${cert.serial}; ${show(r)}${code === a.code ? ", agent_code свой" : ""}` };
    });

    await check("8", "допуск без CSR", "APPLICATION_INCOMPLETE", async () => {
      const d = await op.admit(application(newAgent(), false));
      return {
        ok: !d.admitted && (d.reasons ?? []).includes("APPLICATION_INCOMPLETE"),
        actual: d.admitted ? "допущен" : `отказ: ${(d.reasons ?? []).join(", ")}`,
      };
    });

    await check("9", "сертификат чужого УЦ", "401 AGENT_UNKNOWN", async () => {
      const foreign = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 1 });
      const fcsr = newCsr("foreign");
      const issued = foreign.issueAgentCertificate(fcsr.csr, a.code, new Date(), 1, 300);
      if (!issued.ok) return { ok: false, actual: "выпуск чужим УЦ не прошёл" };
      const r = await call(t, timeoutMs, "/pao/v1/agent", { client: { certDer: Buffer.from(issued.certificate.der, "base64"), key: fcsr.privateKey }, sign: a });
      return { ok: r.status === 401 && bodyCode(r) === "AGENT_UNKNOWN", actual: show(r) };
    });

    await check("10", "отзыв сертификата", "401 AGENT_UNKNOWN", async () => {
      if (!cert) return { ok: false, actual: "сертификата нет (проверка 7)" };
      const revoked = await op.revoke(cert.serial);
      if (!revoked) return { ok: false, actual: "отзыв не подтверждён" };
      const r = await call(t, timeoutMs, "/pao/v1/agent", { client: { certDer: cert.der, key: a.certKey }, sign: a });
      return { ok: r.status === 401 && bodyCode(r) === "AGENT_UNKNOWN", actual: `отозван; ${show(r)}` };
    });

    await check("11", "маршрут банка без подписи", "401 SIGNATURE_INVALID", async () => {
      const r = await call(t, timeoutMs, "/participants/v1/notifications");
      return { ok: r.status === 401 && bodyCode(r) === "SIGNATURE_INVALID", actual: show(r) };
    });

    await journalCheck("12");

    let restarted = false;
    await check("13", "перезапуск", "/health — 200 после перезапуска", async () => {
      await op.restart();
      const deadline = Date.now() + (o.readyTimeoutMs ?? 90_000);
      while (Date.now() < deadline) {
        const up = await call(t, timeoutMs, "/health").then((r) => r.status === 200, () => false);
        if (up) {
          restarted = true;
          return { ok: true, actual: "/health 200" };
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      return { ok: false, actual: "/health не ответил 200 за отведённое время" };
    });
    if (restarted) {
      await serverCert("13.1");
      await openPaths("13.5");
      await journalCheck("13.12");
    } else {
      for (const id of ["13.1", "13.5", "13.12"]) results.push({ id, name: "повтор после перезапуска", expected: "как до перезапуска", actual: "не выполнялся", ok: false });
    }
  } finally {
    await op.close().catch(() => {});
  }
  return results;
}

/** Принято — только если все проверки пройдены; пустой список — не принято. */
export const accepted = (results: readonly CheckResult[]): boolean => results.length > 0 && results.every((r) => r.ok);

/** Таблица «проверка → ожидание → факт» и итог. */
export function report(results: readonly CheckResult[]): string {
  const rows = results.map((r) => `| ${r.id} | ${r.name} | ${r.expected} | ${r.actual} | ${r.ok ? "да" : "НЕТ"} |`);
  return [
    "| № | Проверка | Ожидание | Факт | Пройдена |",
    "|---|---|---|---|---|",
    ...rows,
    "",
    `Итог: ${accepted(results) ? "принято" : "не принято"} (${results.filter((r) => r.ok).length} из ${results.length})`,
  ].join("\n");
}
