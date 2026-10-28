// П1 Перекрёстная проверка своего DER внешним инструментом (РП65 п. 2, условие владельца 27.10): openssl проверяет CSR
// тестовой сборки и сертификаты УЦ, а наш разбор принимает CSR, созданный openssl. В CI без openssl — красный, локально —
// пропуск. Закрытые ключи openssl живут только во временном каталоге теста.
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SandboxCa } from "../../src/registry/ca/ca.js";
import { parseCsr } from "../../src/registry/ca/csr.js";
import { newCsr } from "../support/csr.js";

const CODE = "nspk:agent:buyref-01:v3";
const NOW = new Date();

const openssl = (...args: string[]) => spawnSync("openssl", args, { encoding: "utf8" });
const hasOpenssl = openssl("version").status === 0;

describe("openssl в CI", () => {
  it("есть, если тест идёт в CI", () => {
    if (process.env.CI) expect(hasOpenssl, "openssl нужен для перекрёстной проверки РП65").toBe(true);
  });
});

describe.skipIf(!hasOpenssl)("перекрёстная проверка УЦ и CSR openssl (РП65 п. 2)", () => {
  const dir = mkdtempSync(join(tmpdir(), "ca-openssl-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const file = (name: string, data: string | Buffer): string => {
    const p = join(dir, name);
    writeFileSync(p, data);
    return p;
  };
  const pem = (der: Buffer | string): string => new X509Certificate(typeof der === "string" ? Buffer.from(der, "base64") : der).toString();

  it("CSR тестовой сборки — openssl req -verify: подпись верна", () => {
    const p = file("ours.csr.der", Buffer.from(newCsr().csr, "base64"));
    const r = openssl("req", "-in", p, "-inform", "DER", "-verify", "-noout");
    expect(r.status, r.stderr).toBe(0);
  });

  it("CSR от openssl req -new (P-256) — наш разбор принимает, сертификат выпускается", () => {
    const key = join(dir, "agent.key");
    expect(openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key).status).toBe(0);
    const csr = join(dir, "openssl.csr.der");
    const r = openssl("req", "-new", "-key", key, "-subj", "/CN=buyref", "-outform", "DER", "-out", csr);
    expect(r.status, r.stderr).toBe(0);
    const b64 = readFileSync(csr).toString("base64");
    expect(parseCsr(b64).ok).toBe(true);
    const issued = SandboxCa.generate({ now: NOW, ttlDays: 3650 }).issueAgentCertificate(b64, CODE, NOW, 90, 300);
    expect(issued.ok).toBe(true);
  });

  it("CSR от openssl с ключом P-384 — TEMPLATE", () => {
    const key = join(dir, "p384.key");
    expect(openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key).status).toBe(0);
    const csr = join(dir, "p384.csr.der");
    expect(openssl("req", "-new", "-key", key, "-subj", "/CN=x", "-outform", "DER", "-out", csr).status).toBe(0);
    expect(parseCsr(readFileSync(csr).toString("base64"))).toEqual({ ok: false, reason: "TEMPLATE" });
  });

  it("openssl verify -purpose sslclient: сертификат агента выпущен УЦ, чужой УЦ — отказ", () => {
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const r = ca.issueAgentCertificate(newCsr().csr, CODE, NOW, 90, 300);
    if (!r.ok) throw new Error(r.reason);
    const caFile = file("ca.crt", pem(ca.certificateDer));
    const agentFile = file("agent.crt", pem(r.certificate.der));
    // -x509_strict: без SKI в корневом и AKI в агентском цепочка отвергается (ошибки 85, 86; РП65 нюанс 4).
    const ok = openssl("verify", "-x509_strict", "-CAfile", caFile, "-purpose", "sslclient", agentFile);
    expect(ok.status, ok.stdout + ok.stderr).toBe(0);
    expect(ok.stdout).toContain("OK");
    const other = file("other.crt", pem(SandboxCa.generate({ now: NOW, ttlDays: 3650 }).certificateDer));
    expect(openssl("verify", "-CAfile", other, "-purpose", "sslclient", agentFile).status).not.toBe(0);
    // Сертификат агента для сервера не годится: только clientAuth.
    expect(openssl("verify", "-CAfile", caFile, "-purpose", "sslserver", agentFile).status).not.toBe(0);
  });

  it("openssl verify -purpose sslserver: сертификат сервера Платформы (РП66 п. 4), имя и адрес; для клиента не годится", () => {
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const s = ca.issueServerCertificate(["platform.sandbox.local", "127.0.0.1"], NOW, 90, 300);
    const caFile = file("srv-ca.crt", pem(ca.certificateDer));
    const srv = file("server.crt", pem(s.certificateDer));
    const ok = openssl("verify", "-x509_strict", "-CAfile", caFile, "-purpose", "sslserver", "-verify_hostname", "platform.sandbox.local", srv);
    expect(ok.status, ok.stdout + ok.stderr).toBe(0);
    expect(openssl("verify", "-x509_strict", "-CAfile", caFile, "-purpose", "sslserver", "-verify_ip", "127.0.0.1", srv).status).toBe(0);
    expect(openssl("verify", "-CAfile", caFile, "-purpose", "sslserver", "-verify_hostname", "other.local", srv).status).not.toBe(0);
    expect(openssl("verify", "-CAfile", caFile, "-purpose", "sslclient", srv).status).not.toBe(0);
    const t = openssl("x509", "-in", srv, "-noout", "-text");
    expect(t.stdout).toMatch(/X509v3 Subject Alternative Name: critical\s+DNS:platform\.sandbox\.local, IP Address:127\.0\.0\.1\s/);
    expect(t.stdout).toMatch(/X509v3 Extended Key Usage:\s+TLS Web Server Authentication\s/);
  });

  it("расширения из CSR не переносятся: чужой SAN и CA:TRUE в запросе → SAN из реестра и CA:FALSE (инвариант 5, КТ1 № 2)", () => {
    const key = join(dir, "ext.key");
    expect(openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key).status).toBe(0);
    const csr = join(dir, "ext.csr.der");
    const made = openssl(
      "req", "-new", "-key", key, "-subj", "/CN=nspk:agent:other:v1", "-outform", "DER", "-out", csr,
      "-addext", "subjectAltName=URI:urn:nspk:agent:other:v1",
      "-addext", "basicConstraints=critical,CA:TRUE",
    );
    expect(made.status, made.stderr).toBe(0);
    // Запрос действительно несёт чужой SAN и CA:TRUE.
    const asked = openssl("req", "-in", csr, "-inform", "DER", "-noout", "-text");
    expect(asked.stdout).toContain("URI:urn:nspk:agent:other:v1");
    expect(asked.stdout).toContain("CA:TRUE");

    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const r = ca.issueAgentCertificate(readFileSync(csr).toString("base64"), CODE, NOW, 90, 300);
    if (!r.ok) throw new Error(r.reason);
    const der = Buffer.from(r.certificate.der, "base64");
    expect(new X509Certificate(der).subjectAltName).toBe(`URI:urn:${CODE}`);
    expect(der.includes(Buffer.from("urn:nspk:agent:other:v1", "ascii"))).toBe(false);
    expect(der.includes(Buffer.from("300c0603551d130101ff04023000", "hex"))).toBe(true);
    const t = openssl("x509", "-in", file("ext-agent.crt", pem(der)), "-noout", "-text");
    expect(t.stdout).toMatch(/CA:FALSE/);
    expect(t.stdout).not.toContain("other");
  });

  it("openssl x509: SAN — ровно URI кода агента, CA:FALSE, digitalSignature, clientAuth; субъект пуст", () => {
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const r = ca.issueAgentCertificate(newCsr().csr, CODE, NOW, 90, 300);
    if (!r.ok) throw new Error(r.reason);
    const f = file("agent-text.crt", pem(r.certificate.der));
    const t = openssl("x509", "-in", f, "-noout", "-text");
    expect(t.status, t.stderr).toBe(0);
    expect(t.stdout).toMatch(/X509v3 Subject Alternative Name: critical\s+URI:urn:nspk:agent:buyref-01:v3\s/);
    expect(t.stdout).toMatch(/X509v3 Basic Constraints: critical\s+CA:FALSE/);
    expect(t.stdout).toMatch(/X509v3 Key Usage: critical\s+Digital Signature\s/);
    expect(t.stdout).toMatch(/X509v3 Extended Key Usage:\s+TLS Web Client Authentication\s/);
    expect(t.stdout).toMatch(/Signature Algorithm: ecdsa-with-SHA256/);
    expect(t.stdout).toMatch(/Subject:\s*\n/);
    // Корневой: CA:TRUE, pathlen 0, Certificate Sign.
    const root = openssl("x509", "-in", file("ca-text.crt", pem(ca.certificateDer)), "-noout", "-text");
    expect(root.stdout).toMatch(/CA:TRUE, pathlen:0/);
    expect(root.stdout).toMatch(/Key Usage: critical\s+Certificate Sign\s/);
  });
});
