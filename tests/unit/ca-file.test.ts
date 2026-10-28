// Ключ УЦ песочницы — файл с явной инициализацией (РП66 п. 6; решения владельца 28.10, PR #80): ca:init создаёт файл 0600
// без перезаписи и выводит открытый корневой сертификат и отпечаток; загрузка при запуске sandbox — шесть видов причины
// STARTUP_CA_KEY_INVALID; закрытый ключ — не в выводе, не в тексте ошибок и не в журнале самопроверки (страж).
// Ключи — только сгенерированные в тесте, файлы — во временном каталоге; рамка PEM ключа собирается из частей (guard.py).
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, X509Certificate, type KeyObject } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SandboxCa } from "../../src/registry/ca/ca.js";
import { CA_KEY_REASONS, CaKeyError, initCaFile, loadCaFile, type CaKeyReason } from "../../src/registry/ca/file.js";
import { newCsr } from "../support/csr.js";

const NOW = new Date("2026-10-28T10:00:00.000Z");
const DAY = 86_400_000;
const CODE = "nspk:agent:buyref-01:v3";
const KEY_LABEL = ["PRIVATE", "KEY"].join(" ");
const KEY_BEGIN = `-----BEGIN ${KEY_LABEL}-----`;

const dir = (): string => mkdtempSync(join(tmpdir(), "ca-file-"));
const sha256 = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");
const keyPem = (k: KeyObject): string => k.export({ format: "pem", type: "pkcs8" }) as string;
const certPem = (der: Buffer): string => new X509Certificate(der).toString();
/** PEM УЦ — блок ключа и блок сертификата. */
const split = (pem: string): [string, string] => pem.split(/(?=-----BEGIN CERTIFICATE-----)/) as [string, string];
/** Тело закрытого ключа без рамок и переводов строк — для стража «ключа нет в тексте». */
const keyBody = (pem: string): string => split(pem)[0].replace(KEY_BEGIN, "").replace(/-----END [A-Z ]+-----/, "").replaceAll("\n", "");

/** Файл с содержимым и правами (по умолчанию 0600). */
function file(content: string, mode = 0o600): string {
  const p = join(dir(), "ca.pem");
  writeFileSync(p, content, { mode });
  chmodSync(p, mode);
  return p;
}

const reasonOf = (fn: () => unknown): CaKeyReason | undefined => {
  try {
    fn();
  } catch (e) {
    if (e instanceof CaKeyError) return e.reason;
    throw e;
  }
  return undefined;
};

describe("ca:init — initCaFile (РП66 п. 6)", () => {
  it("новый файл 0600: PKCS#8 и корневой сертификат; загрузка отдаёт тот же УЦ", () => {
    const p = join(dir(), "ca.pem");
    const ca = initCaFile(p, { now: NOW, ttlDays: 3650 });
    expect(statSync(p).mode & 0o777).toBe(0o600);
    const text = readFileSync(p, "utf8");
    expect(text.split(KEY_BEGIN)).toHaveLength(2);
    expect(text.split("-----BEGIN CERTIFICATE-----")).toHaveLength(2);
    const loaded = loadCaFile(p, new Date(NOW.getTime() + DAY));
    expect(loaded.fingerprint).toBe(ca.fingerprint);
    expect(loaded.notBefore).toEqual(ca.notBefore);
    expect(loaded.notAfter).toEqual(ca.notAfter);
    expect(loaded.keyId).toEqual(ca.keyId);
  });

  it("существующий файл не перезаписывается: EEXIST, содержимое прежнее", () => {
    const p = join(dir(), "ca.pem");
    initCaFile(p, { now: NOW, ttlDays: 3650 });
    const before = sha256(p);
    expect(() => initCaFile(p, { now: NOW, ttlDays: 3650 })).toThrow(expect.objectContaining({ code: "EEXIST" }));
    expect(sha256(p)).toBe(before);
  });

  it("УЦ из файла выпускает сертификат, который проверяется исходным корневым (подпись и AKI)", () => {
    const p = join(dir(), "ca.pem");
    const original = initCaFile(p, { now: NOW, ttlDays: 3650 });
    const loaded = loadCaFile(p, NOW);
    const r = loaded.issueAgentCertificate(newCsr().csr, CODE, NOW, 90, 300);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const cert = new X509Certificate(Buffer.from(r.certificate.der, "base64"));
    const root = new X509Certificate(original.certificateDer);
    expect(cert.checkIssued(root)).toBe(true);
    expect(cert.verify(root.publicKey)).toBe(true);
  });
});

describe("загрузка ключа УЦ при запуске sandbox — шесть видов причины (РП66 п. 6)", () => {
  const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });

  it("перечень видов причины закрыт — ровно шесть", () => {
    expect([...CA_KEY_REASONS]).toEqual(["NO_PATH", "NO_FILE", "MODE_TOO_OPEN", "UNPARSABLE", "KEY_MISMATCH", "OUTSIDE_VALIDITY"]);
  });

  it("NO_PATH — пути нет или пустой", () => {
    expect(reasonOf(() => loadCaFile(undefined, NOW))).toBe("NO_PATH");
    expect(reasonOf(() => loadCaFile("", NOW))).toBe("NO_PATH");
  });

  it("NO_FILE — файла нет; каталог — не обычный файл", () => {
    expect(reasonOf(() => loadCaFile(join(dir(), "нет.pem"), NOW))).toBe("NO_FILE");
    const d = join(dir(), "каталог");
    mkdirSync(d, { mode: 0o600 });
    expect(reasonOf(() => loadCaFile(d, NOW))).toBe("NO_FILE");
  });

  it("MODE_TOO_OPEN — права шире 0600 (группа, прочие, исполнение); 0600 и 0400 — приняты", () => {
    for (const mode of [0o640, 0o604, 0o700, 0o644, 0o666]) {
      expect(reasonOf(() => loadCaFile(file(ca.exportPem(), mode), NOW)), mode.toString(8)).toBe("MODE_TOO_OPEN");
    }
    for (const mode of [0o600, 0o400]) {
      expect(loadCaFile(file(ca.exportPem(), mode), NOW).fingerprint, mode.toString(8)).toBe(ca.fingerprint);
    }
  });

  it("UNPARSABLE — не PEM, не два блока, лишний текст, ключ не P-256, сертификат не корневой УЦ песочницы", () => {
    const [caKey, caCert] = split(ca.exportPem());
    const server = ca.issueServerCertificate(["localhost"], NOW, 90, 300);
    const cases: Record<string, string> = {
      пусто: "",
      мусор: "не PEM",
      "только ключ": caKey,
      "только сертификат": caCert,
      "два сертификата": caKey + caCert + caCert,
      "два ключа": caKey + caKey + caCert,
      "лишний текст": `${ca.exportPem()}хвост\n`,
      "испорченный ключ": caKey.replace(/\n[A-Za-z0-9+/]{8}/, "\nAAAAAAAA") + caCert,
      "ключ Ed25519": keyPem(generateKeyPairSync("ed25519").privateKey) + caCert,
      // Ключ от сертификата, но сертификат — сервера (CA:false, пустой субъект), а не корневой УЦ.
      "не корневой": keyPem(server.privateKey) + certPem(server.certificateDer),
    };
    for (const [label, text] of Object.entries(cases)) expect(reasonOf(() => loadCaFile(file(text), NOW)), label).toBe("UNPARSABLE");
  });

  it("KEY_MISMATCH — ключ другого УЦ P-256 при этом сертификате", () => {
    const [otherKey] = split(SandboxCa.generate({ now: NOW, ttlDays: 3650 }).exportPem());
    expect(reasonOf(() => loadCaFile(file(otherKey + ca.certificatePem), NOW))).toBe("KEY_MISMATCH");
  });

  it("OUTSIDE_VALIDITY — часы Платформы до notBefore и с notAfter УЦ; последняя секунда срока — принята", () => {
    const p = file(SandboxCa.generate({ now: NOW, ttlDays: 1 }).exportPem());
    expect(reasonOf(() => loadCaFile(p, new Date(NOW.getTime() - 1000)))).toBe("OUTSIDE_VALIDITY");
    expect(reasonOf(() => loadCaFile(p, new Date(NOW.getTime() + DAY)))).toBe("OUTSIDE_VALIDITY");
    expect(loadCaFile(p, new Date(NOW.getTime() + DAY - 1000)).notAfter).toEqual(new Date(NOW.getTime() + DAY));
  });

  it("страж: текст ошибки — только вид причины, без пути и содержимого файла", () => {
    const text = split(SandboxCa.generate({ now: NOW, ttlDays: 3650 }).exportPem())[0] + ca.certificatePem;
    const p = file(text);
    let caught: unknown;
    try {
      loadCaFile(p, NOW);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CaKeyError);
    const s = `${String(caught)} ${(caught as Error).stack ?? ""}`;
    expect(s).not.toContain(keyBody(text).slice(0, 40));
    expect(s).not.toContain(p);
  });
});

describe("npm run ca:init — процесс (решения владельца 28.10, PR #80)", () => {
  const run = (path: string | undefined) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.PLATFORM_CA_KEY_PATH;
    if (path !== undefined) env.PLATFORM_CA_KEY_PATH = path;
    const r = spawnSync(process.execPath, ["--import", "tsx", "src/ca-init.ts"], { env, encoding: "utf8" });
    return { code: r.status, out: `${r.stdout}${r.stderr}`, stdout: r.stdout };
  };

  it("путь из PLATFORM_CA_KEY_PATH: файл 0600; вывод — отпечаток и открытый корневой PEM, закрытого ключа нет; повтор — EEXIST, файл прежний", () => {
    const p = join(dir(), "ca.pem");
    const first = run(p);
    expect(first.code, first.out).toBe(0);
    expect(statSync(p).mode & 0o777).toBe(0o600);
    const loaded = loadCaFile(p, new Date());
    expect(first.stdout).toContain(loaded.fingerprint);
    expect(first.stdout).toContain(loaded.certificatePem);
    expect(first.out).not.toContain(KEY_LABEL);
    expect(first.out).not.toContain(keyBody(readFileSync(p, "utf8")).slice(0, 40));
    // Срок — sandbox_ca_ttl_days стенда (3 650 дней).
    expect(loaded.notAfter.getTime() - loaded.notBefore.getTime()).toBe(3650 * DAY);

    const before = sha256(p);
    const again = run(p);
    expect(again.code).toBe(1);
    expect(again.out).toContain("EEXIST");
    expect(sha256(p)).toBe(before);
  }, 30_000);

  it("без PLATFORM_CA_KEY_PATH — код 1, файл не создаётся", () => {
    const r = run(undefined);
    expect(r.code).toBe(1);
    expect(r.out).toContain("PLATFORM_CA_KEY_PATH");
  }, 30_000);
});
