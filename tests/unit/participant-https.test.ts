// Тестовый банк-участник (Р-1031, Р-1040, К1.2 сессии 61): sign / revoke по ПИ-8 по HTTPS против buildServer с TLS 1.3 и
// сертификатом сервера от УЦ песочницы (как pao-tls и acceptance-checks); доверенный ключ — из keygen инструмента.
// PENDING_SIGNATURE → ACTIVE → REVOKED; чужой корень, неверный отпечаток и чужое имя сервера — отказ до обращения к ПИ-8.
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { AddressInfo } from "node:net";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { checkRoot, loadBankKey, opaqueRef, revokeMandate, signMandate, type Target } from "../../scripts/participant/client.js";
import { keygen, ParticipantToolError } from "../../scripts/participant/keys.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { isOpaquePrincipalRef } from "../../src/consent/terms.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import { SandboxCa } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { loadParams } from "../../src/shared/config.js";

const params = loadParams();
const HOST = "localhost";
const A = "nspk:agent:test-bank:v1";
const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const MAIN = join(REPO, "scripts/participant/main.ts");
const run = promisify(execFile);

const cleanup: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});

const intent = (): MandateRequest => ({
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: new Date(Date.now() + 7 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
});

/** Песочница в процессе: УЦ, сертификат сервера на names, банк из keygen в доверенных, журнал согласий в памяти. */
async function sandbox(o: { names?: string[] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "participant-https-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const keyPath = join(dir, "bank.pem");
  const rec = keygen({ participant_code: "test-bank", keyPath, repoRoot: mkdtempSync(join(dir, "repo-")) });
  const ca = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: params.sandbox_ca_ttl_days });
  const server = ca.issueServerCertificate(o.names ?? [HOST, "127.0.0.1"], new Date(), params.agent_cert_ttl_days, params.cert_not_before_backdate_sec);
  const trusted = new TrustedParticipants([rec], { stand: false });
  const consent = new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => trusted.revocationOrder() });
  const app: FastifyInstance = buildServer({
    env: "sandbox",
    tls: { key: server.privateKey, certificateDer: server.certificateDer, caDer: ca.certificateDer },
    participants: { trusted, consent, params },
  });
  const seen: string[] = [];
  app.addHook("onRequest", async (req) => {
    seen.push(req.url);
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  cleanup.push(() => app.close());
  const port = (app.server.address() as AddressInfo).port;
  const caPem = ca.certificatePem;
  const caPath = join(dir, "root.crt");
  writeFileSync(caPath, caPem);
  const target: Target = { host: HOST, port, caPem, fingerprint: ca.fingerprint };
  const mandate = async () => {
    const m = await consent.request(A, createHash("sha256").update(randomUUID()).digest("hex"), intent());
    if (!m.id || !m.hash) throw new Error("нет id или hash");
    return { id: m.id, hash: m.hash };
  };
  const status = async (id: string) => (await consent.get(id, A))?.status;
  return { dir, keyPath, rec, ca, caPath, target, seen, mandate, status, consent };
}

const toolCode = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return e instanceof ParticipantToolError ? `${e.code} ${e.message}` : `other:${(e as Error).message}`;
  }
  return "ok";
};

describe("participant sign / revoke по HTTPS", () => {
  it("PENDING_SIGNATURE → sign → ACTIVE → revoke → REVOKED; подпись проверена ключом из participants.json", async () => {
    const s = await sandbox();
    const key = loadBankKey(s.keyPath, "test-bank");
    expect(key.kid).toBe(s.rec.kid);
    const m = await s.mandate();
    expect(await s.status(m.id)).toBe("PENDING_SIGNATURE");
    const signed = await signMandate(s.target, key, { mandate_id: m.id, mandate_hash: m.hash, decision: "SIGN", signature_type: "simple", token_consent: true });
    expect(signed).toEqual({ status: 200, body: { mandate_id: m.id, status: "ACTIVE" } });
    expect(await s.status(m.id)).toBe("ACTIVE");
    const revoked = await revokeMandate(s.target, key, { mandate_id: m.id, mandate_hash: m.hash });
    expect(revoked).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
    expect(await s.status(m.id)).toBe("REVOKED");
  });

  it("REJECT → REJECTED", async () => {
    const s = await sandbox();
    const key = loadBankKey(s.keyPath, "test-bank");
    const m = await s.mandate();
    const r = await signMandate(s.target, key, { mandate_id: m.id, mandate_hash: m.hash, decision: "REJECT", signature_type: "simple", token_consent: false });
    expect(r).toEqual({ status: 200, body: { mandate_id: m.id, status: "REJECTED" } });
  });

  it("подпись верна, но Mandate.hash не тот — отказ ПИ-8, мандат остаётся PENDING_SIGNATURE", async () => {
    const s = await sandbox();
    const key = loadBankKey(s.keyPath, "test-bank");
    const m = await s.mandate();
    const r = await signMandate(s.target, key, { mandate_id: m.id, mandate_hash: "0".repeat(64), decision: "SIGN", signature_type: "simple", token_consent: true });
    expect(r.status).not.toBe(200);
    expect(await s.status(m.id)).toBe("PENDING_SIGNATURE");
  });

  it("чужой корень (с его же верным отпечатком) — отказ TLS, к ПИ-8 обращения нет", async () => {
    const s = await sandbox();
    const foreign = SandboxCa.generate({ now: new Date(Date.now() - 60_000), ttlDays: 1 });
    const key = loadBankKey(s.keyPath, "test-bank");
    const m = await s.mandate();
    const t: Target = { ...s.target, caPem: foreign.certificatePem, fingerprint: foreign.fingerprint };
    const code = await toolCode(signMandate(t, key, { mandate_id: m.id, mandate_hash: m.hash, decision: "SIGN", signature_type: "simple", token_consent: true }));
    expect(code).toMatch(/^CONNECT_FAILED /);
    expect(s.seen).toEqual([]);
    expect(await s.status(m.id)).toBe("PENDING_SIGNATURE");
  });

  it("неверный --fingerprint — отказ до соединения, к ПИ-8 обращения нет", async () => {
    const s = await sandbox();
    const other = SandboxCa.generate({ now: new Date(), ttlDays: 1 }).fingerprint;
    const key = loadBankKey(s.keyPath, "test-bank");
    const m = await s.mandate();
    const code = await toolCode(signMandate({ ...s.target, fingerprint: other }, key, { mandate_id: m.id, mandate_hash: m.hash, decision: "SIGN", signature_type: "simple", token_consent: true }));
    expect(code).toMatch(/^FINGERPRINT_MISMATCH /);
    expect(s.seen).toEqual([]);
    // Отпечаток с двоеточиями и в верхнем регистре — тот же (как у acceptance).
    expect(() => checkRoot(s.target.caPem, s.ca.fingerprint.toUpperCase().match(/../g)!.join(":"))).not.toThrow();
  });

  it("сертификат сервера на чужое имя от того же УЦ — отказ TLS (проверка имени), к ПИ-8 обращения нет", async () => {
    const s = await sandbox({ names: ["other.example"] });
    const key = loadBankKey(s.keyPath, "test-bank");
    const m = await s.mandate();
    const code = await toolCode(signMandate(s.target, key, { mandate_id: m.id, mandate_hash: m.hash, decision: "SIGN", signature_type: "simple", token_consent: true }));
    expect(code).toMatch(/^CONNECT_FAILED .*ERR_TLS_CERT_ALTNAME_INVALID/);
    expect(s.seen).toEqual([]);
  });

  it("--hash не 64 hex — ARGS_INVALID до соединения", async () => {
    const s = await sandbox();
    const key = loadBankKey(s.keyPath, "test-bank");
    const code = await toolCode(revokeMandate(s.target, key, { mandate_id: "m-1", mandate_hash: "ABC" }));
    expect(code).toMatch(/^ARGS_INVALID /);
    expect(s.seen).toEqual([]);
  });

  it("ключ не ed25519 или не PEM — KEY_INVALID", async () => {
    const s = await sandbox();
    const bad = join(s.dir, "bad.pem");
    writeFileSync(bad, "не ключ");
    expect(await toolCode(Promise.resolve().then(() => loadBankKey(bad, "test-bank")))).toMatch(/^KEY_INVALID /);
  });

  it("непрозрачная ссылка банка: 7 цифр подряд — новая выборка; итог проходит правило сервера", () => {
    const digits = Buffer.from("1234567890abcdef", "base64url");
    const normal = Buffer.from("abcdefghijklmnop", "base64url");
    const draws = [digits, normal];
    let calls = 0;
    const ref = opaqueRef("sig", () => draws[calls++]!);
    expect(calls).toBe(2);
    expect(ref).toBe("sig-abcdefghijklmnop");
    expect(isOpaquePrincipalRef(ref)).toBe(true);
    expect(isOpaquePrincipalRef(`sig-${digits.toString("base64url")}`)).toBe(false);
    for (let i = 0; i < 200; i++) expect(isOpaquePrincipalRef(opaqueRef("sig"))).toBe(true);
  });
});

describe("participant CLI sign / revoke", () => {
  const cli = async (...args: string[]) => {
    try {
      const r = await run(process.execPath, ["--import", "tsx", MAIN, ...args], { cwd: REPO, encoding: "utf8", timeout: 30_000 });
      return { code: 0, stdout: r.stdout, stderr: r.stderr };
    } catch (e) {
      const x = e as { code?: number; stdout?: string; stderr?: string };
      return { code: x.code ?? -1, stdout: x.stdout ?? "", stderr: x.stderr ?? "" };
    }
  };

  it("sign и revoke из командной строки — код 0, ACTIVE и REVOKED; неверный отпечаток — код 1 без обращения", async () => {
    const s = await sandbox();
    const m = await s.mandate();
    const common = ["--host", HOST, "--port", String(s.target.port), "--ca", s.caPath, "--key", s.keyPath, "--code", "test-bank", "--mandate", m.id, "--hash", m.hash];
    const bad = await cli("sign", ...common, "--fingerprint", SandboxCa.generate({ now: new Date(), ttlDays: 1 }).fingerprint);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toMatch(/FINGERPRINT_MISMATCH/);
    expect(s.seen).toEqual([]);
    const signed = await cli("sign", ...common, "--fingerprint", s.ca.fingerprint, "--token-consent");
    expect(signed.code).toBe(0);
    expect(JSON.parse(signed.stdout)).toEqual({ status: 200, body: { mandate_id: m.id, status: "ACTIVE" } });
    const revoked = await cli("revoke", ...common, "--fingerprint", s.ca.fingerprint);
    expect(revoked.code).toBe(0);
    expect(JSON.parse(revoked.stdout)).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
  });

  it("нет обязательных параметров или неверный --decision — код 2", async () => {
    expect((await cli("sign", "--code", "test-bank", "--key", "/nonexistent")).code).toBe(2);
    const s = await sandbox();
    const r = await cli(
      "sign", "--host", HOST, "--port", String(s.target.port), "--ca", s.caPath, "--fingerprint", s.ca.fingerprint,
      "--key", s.keyPath, "--code", "test-bank", "--mandate", "m-1", "--hash", "a".repeat(64), "--decision", "MAYBE",
    );
    expect(r.code).toBe(2);
    expect(s.seen).toEqual([]);
  });
});
