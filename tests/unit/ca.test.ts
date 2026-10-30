// П1 УЦ песочницы и разбор CSR (РП27 п. 1–2, РП65 п. 1–2, 5): один шаблон, строгий DER, пределы длин, владение ключом;
// сертификат сервера и notBefore с запасом (РП66 п. 4, 5).
import { createHash, createVerify, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SANDBOX_CA_NAME, SandboxCa } from "../../src/registry/ca/ca.js";
import { CSR_MAX_BASE64_CHARS, P256_SPKI_PREFIX, parseCsr } from "../../src/registry/ca/csr.js";
import { bitString, DerError, MAX_DEPTH, oid, parseStrict, seq, set, time, tlv, uint } from "../../src/registry/ca/der.js";
import { buildCsrDer, newCsr, p256 } from "../support/csr.js";

const CODE = "nspk:agent:buyref-01:v3";
const NOW = new Date("2026-10-27T10:00:00.250Z");
const DAY = 86_400_000;

const ca = (now = NOW, ttlDays = 3650) => SandboxCa.generate({ now, ttlDays });
const x509 = (b64: string) => new X509Certificate(Buffer.from(b64, "base64"));

describe("УЦ песочницы: выпуск сертификата агента по CSR (РП65 п. 2)", () => {
  it("сертификат по шаблону: пустой субъект, SAN — ровно URI кода агента, CA:false, clientAuth, подпись УЦ", () => {
    const c = ca();
    const { csr, publicKey } = newCsr("попытка подставить CN=nspk:agent:other:v1");
    const r = c.issueAgentCertificate(csr, CODE, NOW, 90, 300);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const cert = x509(r.certificate.der);
    const root = new X509Certificate(c.certificateDer);
    // Пустой субъект Node отдаёт как undefined.
    expect(cert.subject ?? "").toBe("");
    expect(cert.issuer).toBe(`CN=${SANDBOX_CA_NAME}`);
    expect(cert.subjectAltName).toBe(`URI:urn:${CODE}`);
    expect(cert.ca).toBe(false);
    // X509Certificate.ca учитывает и keyUsage: CA:true без keyCertSign он тоже назовёт false (поломка К2 П6) — поэтому
    // расширение сверяется байтами: basicConstraints, критичное, пустая последовательность (CA:false по умолчанию).
    const der = Buffer.from(r.certificate.der, "base64");
    expect(der.includes(Buffer.from("300c0603551d130101ff04023000", "hex"))).toBe(true);
    // keyUsage digitalSignature, критичное: Node отдаёт в keyUsage только EKU — сверка байтами (КТ1 № 10).
    expect(der.includes(Buffer.from("300e0603551d0f0101ff040403020780", "hex"))).toBe(true);
    // AKI — только keyIdentifier, равный SKI УЦ, некритичное (РП65 нюанс 4).
    expect(der.includes(Buffer.concat([Buffer.from("301f0603551d23041830168014", "hex"), c.keyId]))).toBe(true);
    expect(cert.keyUsage).toEqual(["1.3.6.1.5.5.7.3.2"]);
    expect(cert.verify(c.publicKey)).toBe(true);
    expect(cert.checkIssued(root)).toBe(true);
    // Ключ сертификата — из CSR, субъект из CSR не перенесён (инвариант 5).
    expect(cert.publicKey.export({ format: "der", type: "spki" })).toEqual(publicKey.export({ format: "der", type: "spki" }));
    expect(cert.serialNumber.toLowerCase()).toBe(r.certificate.serial);
    expect(r.certificate.not_before).toBe("2026-10-27T10:00:00.000Z");
    expect(r.certificate.not_after).toBe(new Date(Date.parse("2026-10-27T10:00:00Z") + 90 * DAY).toISOString());
    expect(Date.parse(cert.validFrom)).toBe(Date.parse(r.certificate.not_before));
    expect(Date.parse(cert.validTo)).toBe(Date.parse(r.certificate.not_after));
    // Каноническая base64.
    expect(Buffer.from(r.certificate.der, "base64").toString("base64")).toBe(r.certificate.der);
  });

  it("корневой сертификат: самоподписанный, CA:true, субъект = issuer агентских", () => {
    const c = ca();
    const root = new X509Certificate(c.certificateDer);
    expect(root.ca).toBe(true);
    expect(root.subject).toBe(`CN=${SANDBOX_CA_NAME}`);
    expect(root.verify(root.publicKey)).toBe(true);
    expect(Date.parse(root.validTo) - Date.parse(root.validFrom)).toBe(3650 * DAY);
    expect(c.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    // SKI — SHA-1 от subjectPublicKey (метод 1 RFC 5280), некритичное (РП65 нюанс 4).
    const point = c.publicKey.export({ format: "der", type: "spki" }).subarray(P256_SPKI_PREFIX.length);
    expect(c.keyId).toEqual(createHash("sha1").update(point).digest());
    expect(c.certificateDer.includes(Buffer.concat([Buffer.from("301d0603551d0e04160414", "hex"), c.keyId]))).toBe(true);
  });

  it("срок сертификата не выходит за срок УЦ: notAfter = min(now + ttl, notAfter УЦ)", () => {
    const c = ca(NOW, 100);
    const later = new Date(NOW.getTime() + 50 * DAY);
    const r = c.issueAgentCertificate(newCsr().csr, CODE, later, 90, 300);
    expect(r.ok && r.certificate.not_after).toBe(c.notAfter.toISOString());
  });

  it("серийный номер: 16 байт, положительный, разный у каждого выпуска", () => {
    const c = ca();
    const serials = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const r = c.issueAgentCertificate(newCsr().csr, CODE, NOW, 90, 300);
      if (!r.ok) throw new Error(r.reason);
      expect(r.certificate.serial).toMatch(/^[4-7][0-9a-f]{31}$/);
      serials.add(r.certificate.serial);
    }
    expect(serials.size).toBe(20);
  });

  it("код агента не песочницы и УЦ вне срока — исключение, а не сертификат (инвариант 3)", () => {
    const c = ca(NOW, 10);
    expect(() => c.issueAgentCertificate(newCsr().csr, "other:agent:x:v1", NOW, 90, 300)).toThrow(/не песочницы/);
    expect(() => c.issueAgentCertificate(newCsr().csr, `${CODE} `, NOW, 90, 300)).toThrow(/не песочницы/);
    // Грамматика — та же, что у реестра (parseAgentCode, КТ1 № 7): версия не длиннее 9 цифр.
    expect(() => c.issueAgentCertificate(newCsr().csr, "nspk:agent:buyref-01:v1234567890", NOW, 90, 300)).toThrow(/не песочницы/);
    expect(() => c.issueAgentCertificate(newCsr().csr, CODE, new Date(Number.NaN), 90, 300)).toThrow(/не разбирается/);
    expect(() => c.issueAgentCertificate(newCsr().csr, CODE, new Date(NOW.getTime() + 10 * DAY), 90, 300)).toThrow(/вне срока/);
    expect(() => c.issueAgentCertificate(newCsr().csr, CODE, new Date(NOW.getTime() - 1000), 90, 300)).toThrow(/вне срока/);
  });

  it("плохой CSR — отказ с видом причины, сертификата нет", () => {
    const r = ca().issueAgentCertificate("нет", CODE, NOW, 90, 300);
    expect(r).toEqual({ ok: false, reason: "FORMAT" });
  });
});

describe("notBefore с запасом в прошлое (РП66 п. 5)", () => {
  const SEC0 = Date.parse("2026-10-27T10:00:00Z");

  it("notBefore = часы − запас, notAfter = часы + срок: чужие часы клиента отстают", () => {
    const c = ca();
    const later = new Date(NOW.getTime() + DAY);
    const r = c.issueAgentCertificate(newCsr().csr, CODE, later, 90, 300);
    expect(r.ok && r.certificate.not_before).toBe(new Date(SEC0 + DAY - 300_000).toISOString());
    expect(r.ok && r.certificate.not_after).toBe(new Date(SEC0 + DAY + 90 * DAY).toISOString());
    expect(r.ok && Date.parse(x509(r.certificate.der).validFrom)).toBe(SEC0 + DAY - 300_000);
  });

  it("notBefore не раньше notBefore УЦ: max(notBefore УЦ, часы − запас)", () => {
    const c = ca();
    const r = c.issueAgentCertificate(newCsr().csr, CODE, new Date(NOW.getTime() + 100_000), 90, 300);
    expect(r.ok && r.certificate.not_before).toBe(c.notBefore.toISOString());
    const s = c.issueServerCertificate(["localhost"], new Date(NOW.getTime() + 100_000), 90, 300);
    expect(s.notBefore.toISOString()).toBe(c.notBefore.toISOString());
  });

  it("корень с запасом (Р-918): notBefore = часы − запас, notAfter = часы + срок; лист в ту же секунду — без обрезки", () => {
    const c = SandboxCa.generate({ now: NOW, ttlDays: 3650, backdateSec: 300 });
    expect(c.notBefore.toISOString()).toBe(new Date(SEC0 - 300_000).toISOString());
    expect(c.notAfter.toISOString()).toBe(new Date(SEC0 + 3650 * DAY).toISOString());
    const root = new X509Certificate(c.certificateDer);
    expect(Date.parse(root.validFrom)).toBe(SEC0 - 300_000);
    expect(Date.parse(root.validTo)).toBe(SEC0 + 3650 * DAY);
    // Сразу после ca:init запас листа — полный, а не обрезанный до notBefore корня.
    const r = c.issueAgentCertificate(newCsr().csr, CODE, NOW, 90, 300);
    expect(r.ok && r.certificate.not_before).toBe(new Date(SEC0 - 300_000).toISOString());
    expect(c.issueServerCertificate(["localhost"], NOW, 90, 300).notBefore.toISOString()).toBe(new Date(SEC0 - 300_000).toISOString());
    // Клиент, отстающий на запас, — в сроке корня и листа.
    expect(r.ok && x509(r.certificate.der).checkIssued(root)).toBe(true);
  });

  it("корень: запас по умолчанию 0 — прежнее поведение; 0 и 3 600 — принят; вне 0…3 600 и не целое — исключение", () => {
    expect(ca().notBefore.toISOString()).toBe(new Date(SEC0).toISOString());
    expect(SandboxCa.generate({ now: NOW, ttlDays: 1, backdateSec: 0 }).notBefore.toISOString()).toBe(new Date(SEC0).toISOString());
    expect(SandboxCa.generate({ now: NOW, ttlDays: 1, backdateSec: 3600 }).notBefore.toISOString()).toBe(new Date(SEC0 - 3_600_000).toISOString());
    for (const bad of [-1, 3601, 1.5, Number.NaN]) {
      expect(() => SandboxCa.generate({ now: NOW, ttlDays: 1, backdateSec: bad }), String(bad)).toThrow(/запас notBefore/);
    }
  });

  it("запас 0 и 3 600 — принят; вне 0…3 600 и не целое — исключение", () => {
    const c = ca();
    const later = new Date(NOW.getTime() + DAY);
    expect(c.issueAgentCertificate(newCsr().csr, CODE, later, 90, 0).ok).toBe(true);
    const r = c.issueAgentCertificate(newCsr().csr, CODE, later, 90, 3600);
    expect(r.ok && r.certificate.not_before).toBe(new Date(SEC0 + DAY - 3_600_000).toISOString());
    for (const bad of [-1, 3601, 1.5, Number.NaN]) {
      expect(() => c.issueAgentCertificate(newCsr().csr, CODE, later, 90, bad), String(bad)).toThrow(/запас notBefore/);
      expect(() => c.issueServerCertificate(["localhost"], later, 90, bad), String(bad)).toThrow(/запас notBefore/);
    }
  });
});

describe("УЦ песочницы: сертификат сервера Платформы (РП66 п. 4)", () => {
  // Поломки К3.1 — каждая своим тестом (Р-747; ревью из чата 28.10, № 1): serverAuth, SAN критичное, AKI.
  const server = () => {
    const c = ca();
    return { c, s: c.issueServerCertificate(["localhost"], NOW, 90, 300) };
  };

  it("extKeyUsage — только serverAuth", () => {
    const { s } = server();
    expect(new X509Certificate(s.certificateDer).keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
  });

  it("SAN — критичное при пустом субъекте (RFC 5280 §4.2.1.6; дополнение чата 2)", () => {
    const { s } = server();
    expect(new X509Certificate(s.certificateDer).subject ?? "").toBe("");
    expect(s.certificateDer.includes(Buffer.from("0603551d110101ff04", "hex"))).toBe(true);
  });

  it("AKI — keyIdentifier = SKI УЦ (РП65 нюанс 4)", () => {
    const { c, s } = server();
    expect(s.certificateDer.includes(Buffer.concat([Buffer.from("301f0603551d23041830168014", "hex"), c.keyId]))).toBe(true);
  });

  it("IPv6 в SAN — байтами по RFC 4291: «::» в конце, в середине и отдельно, восемь групп, хвост IPv4 (КТ1 К3.2 № 6)", () => {
    const c = ca();
    // [запись в PLATFORM_TLS_HOSTNAMES, та же адресная запись в другой форме, соседний адрес]
    const cases: [string, string, string][] = [
      ["2001:db8::", "2001:db8:0:0:0:0:0:0", "2001:db8::1"],
      ["2001:db8::1:0:0:1", "2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:2"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:7"],
      ["::", "0:0:0:0:0:0:0:0", "::1"],
      ["1::1.2.3.4", "1::102:304", "1::1.2.3.5"],
    ];
    for (const [ip, same, near] of cases) {
      const cert = new X509Certificate(c.issueServerCertificate([ip], NOW, 90, 300).certificateDer);
      expect(cert.checkIP(ip), ip).toBe(ip);
      expect(cert.checkIP(same), `${ip} = ${same}`).toBe(same);
      expect(cert.checkIP(near), `${ip} ≠ ${near}`).toBeUndefined();
    }
  });

  it("по шаблону: пустой субъект, SAN критичное — DNS и IP, serverAuth, digitalSignature, CA:false, SKI / AKI, подпись УЦ", () => {
    const c = ca();
    const later = new Date(NOW.getTime() + DAY);
    const s = c.issueServerCertificate(["platform.sandbox.local", "localhost", "127.0.0.1", "::1", "::ffff:10.0.0.1"], later, 90, 300);
    const cert = new X509Certificate(s.certificateDer);
    expect(cert.subject ?? "").toBe("");
    expect(cert.issuer).toBe(`CN=${SANDBOX_CA_NAME}`);
    expect(cert.checkIssued(new X509Certificate(c.certificateDer))).toBe(true);
    expect(cert.verify(c.publicKey)).toBe(true);
    // SAN при пустом субъекте — критичное (RFC 5280 §4.2.1.6; дополнение чата 2): OID, BOOLEAN TRUE, OCTET STRING.
    expect(s.certificateDer.includes(Buffer.from("0603551d110101ff04", "hex"))).toBe(true);
    expect(cert.checkHost("platform.sandbox.local")).toBe("platform.sandbox.local");
    expect(cert.checkHost("localhost")).toBe("localhost");
    expect(cert.checkHost("other.local")).toBeUndefined();
    expect(cert.checkIP("127.0.0.1")).toBe("127.0.0.1");
    expect(cert.checkIP("::1")).toBe("::1");
    expect(cert.checkIP("::ffff:10.0.0.1")).toBe("::ffff:10.0.0.1");
    expect(cert.checkIP("127.0.0.2")).toBeUndefined();
    expect(cert.keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    expect(cert.ca).toBe(false);
    expect(s.certificateDer.includes(Buffer.from("300c0603551d130101ff04023000", "hex"))).toBe(true);
    expect(s.certificateDer.includes(Buffer.from("300e0603551d0f0101ff040403020780", "hex"))).toBe(true);
    // SKI — от своего ключа; AKI — SKI УЦ (РП65 нюанс 4).
    const point = cert.publicKey.export({ format: "der", type: "spki" }).subarray(P256_SPKI_PREFIX.length);
    const ski = createHash("sha1").update(point).digest();
    expect(s.certificateDer.includes(Buffer.concat([Buffer.from("301d0603551d0e04160414", "hex"), ski]))).toBe(true);
    expect(s.certificateDer.includes(Buffer.concat([Buffer.from("301f0603551d23041830168014", "hex"), c.keyId]))).toBe(true);
    // Закрытый ключ — пара к сертификату: подпись им проверяется открытым ключом сертификата.
    const sig = sign("sha256", Buffer.from("x"), s.privateKey);
    expect(createVerify("sha256").update("x").verify(cert.publicKey, sig)).toBe(true);
    expect(Date.parse(cert.validFrom)).toBe(Date.parse("2026-10-28T10:00:00Z") - 300_000);
    expect(Date.parse(cert.validTo)).toBe(Date.parse("2026-10-28T10:00:00Z") + 90 * DAY);
  });

  it("цифры в метках, кроме последней, — допустимы (RFC 1123 §2.1): 1.2.3.example, host-01.local, 0x1.local", () => {
    const s = ca().issueServerCertificate(["1.2.3.example", "host-01.local", "0x1.local"], NOW, 90, 300);
    const cert = new X509Certificate(s.certificateDer);
    expect(cert.checkHost("1.2.3.example")).toBe("1.2.3.example");
    expect(cert.checkHost("host-01.local")).toBe("host-01.local");
  });

  it("срок не дольше УЦ; УЦ вне срока — исключение", () => {
    const c = ca(NOW, 100);
    expect(c.issueServerCertificate(["localhost"], new Date(NOW.getTime() + 50 * DAY), 90, 300).notAfter).toEqual(c.notAfter);
    expect(() => c.issueServerCertificate(["localhost"], new Date(NOW.getTime() + 100 * DAY), 90, 300)).toThrow(/вне срока/);
  });

  it.each([
    ["пустой список", []],
    ["верхний регистр", ["Platform.local"]],
    ["завершающая точка", ["platform.local."]],
    ["шаблон «*»", ["*.platform.local"]],
    ["пустая метка", ["platform..local"]],
    ["дефис в начале метки", ["-platform.local"]],
    ["метка длиннее 63", [`${"a".repeat(64)}.local`]],
    ["имя длиннее 253", [Array.from({ length: 64 }, () => "abc").join(".")]],
    ["зона IPv6", ["fe80::1%eth0"]],
    ["пробел", ["platform .local"]],
    ["пустая строка", [""]],
    ["одно верное, одно нет", ["localhost", "Localhost"]],
    // КТ1 К3.2 № 7 (RFC 1123 §2.1): последняя метка из одних цифр — не адрес IP и не имя DNS.
    ["IPv4 вне диапазона", ["256.1.1.1"]],
    ["IPv4 с ведущим нулём", ["01.2.3.4"]],
    ["три октета", ["1.2.3"]],
    ["одна цифровая метка", ["8080"]],
    ["имя с цифровой последней меткой", ["platform.123"]],
  ])("имена: %s — исключение", (_n, names) => {
    expect(() => ca().issueServerCertificate(names, NOW, 90, 300)).toThrow(/имена сервера|имя сервера/);
  });
});

describe("разбор CSR: запись и пределы (РП65 п. 1–2)", () => {
  const good = newCsr();

  it("CSR по шаблону принимается", () => {
    expect(parseCsr(good.csr).ok).toBe(true);
  });

  it.each([
    ["не строка", 42],
    ["пустая строка", ""],
    ["PEM", `-----BEGIN CERTIFICATE REQUEST-----\n${good.csr}\n-----END CERTIFICATE REQUEST-----`],
    ["с переводом строки", `${good.csr.slice(0, 40)}\n${good.csr.slice(40)}`],
    ["с пробелом", ` ${good.csr}`],
    ["base64url", Buffer.from(good.csr, "base64").toString("base64url")],
  ])("%s — FORMAT", (_n, v) => {
    expect(parseCsr(v)).toEqual({ ok: false, reason: "FORMAT" });
  });

  it("без дополнения — FORMAT (CSR подобран так, что его запись кончается на «=», КТ1 № 5)", () => {
    // Длина подписи ECDSA плавает — CN удлиняется, пока длина DER не станет некратной 3.
    let padded: string | undefined;
    for (let n = 1; !padded && n < 64; n++) {
      const c = newCsr("x".repeat(n)).csr;
      if (c.endsWith("=")) padded = c;
    }
    expect(padded).toBeDefined();
    expect(parseCsr(padded as string).ok).toBe(true);
    expect(parseCsr((padded as string).replace(/=+$/, ""))).toEqual({ ok: false, reason: "FORMAT" });
  });

  it("лишние биты перед «=» — FORMAT (каноническая запись, РП23 доп. 6)", () => {
    const der = Buffer.concat([Buffer.from(good.csr, "base64")]);
    // Длина DER не кратна 3 — последний знак перед «=» несёт неиспользуемые биты.
    const b64 = der.length % 3 === 0 ? Buffer.concat([der, Buffer.from([0])]).toString("base64") : der.toString("base64");
    const i = b64.indexOf("=") - 1;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const tweaked = b64.slice(0, i) + alphabet[(alphabet.indexOf(b64[i]!) + 1) % 64] + b64.slice(i + 1);
    expect(Buffer.from(tweaked, "base64").equals(Buffer.from(b64, "base64"))).toBe(true);
    expect(parseCsr(tweaked)).toEqual({ ok: false, reason: "FORMAT" });
  });

  it("строка длиннее предела — TOO_LONG до декодирования; 2 046 байт — не TOO_LONG", () => {
    expect(parseCsr("A".repeat(CSR_MAX_BASE64_CHARS + 4))).toEqual({ ok: false, reason: "TOO_LONG" });
    // 2 732 знака — 2 049 байт, уже больше предела DER; на 4 знака меньше — 2 046 байт.
    expect(parseCsr("A".repeat(CSR_MAX_BASE64_CHARS))).toEqual({ ok: false, reason: "TOO_LONG" });
    const atLimit = parseCsr("A".repeat(CSR_MAX_BASE64_CHARS - 4));
    expect(atLimit.ok).toBe(false);
    expect(!atLimit.ok && atLimit.reason).not.toBe("TOO_LONG");
  });

  it("CSR длиннее 2 048 байт (длинный субъект) — TOO_LONG", () => {
    const pair = p256();
    const long = buildCsrDer({ ...pair, cn: "x".repeat(2100) });
    expect(long.length).toBeGreaterThan(2048);
    expect(parseCsr(long.toString("base64"))).toEqual({ ok: false, reason: "TOO_LONG" });
  });
});

describe("разбор CSR: строгий DER (РП65 п. 2)", () => {
  const der = (): Buffer => Buffer.from(newCsr().csr, "base64");
  const b64 = (b: Buffer): string => b.toString("base64");

  it("обрезанный — DER", () => {
    const d = der();
    expect(parseCsr(b64(d.subarray(0, d.length - 1)))).toEqual({ ok: false, reason: "DER" });
    expect(parseCsr(b64(d.subarray(0, 1)))).toEqual({ ok: false, reason: "DER" });
  });

  it("байты после конца — DER", () => {
    expect(parseCsr(b64(Buffer.concat([der(), Buffer.from([0])])))).toEqual({ ok: false, reason: "DER" });
  });

  it("длина не в кратчайшей записи — DER", () => {
    const d = der();
    expect(d[1]).toBe(0x81);
    // 0x81 LL → 0x82 00 LL: та же длина длинной формой.
    const longForm = Buffer.concat([Buffer.from([0x30, 0x82, 0x00, d[2]!]), d.subarray(3)]);
    expect(parseCsr(b64(longForm))).toEqual({ ok: false, reason: "DER" });
  });

  it("неопределённая длина — DER", () => {
    const d = der();
    const indefinite = Buffer.concat([Buffer.from([0x30, 0x80]), d.subarray(3), Buffer.from([0, 0])]);
    expect(parseCsr(b64(indefinite))).toEqual({ ok: false, reason: "DER" });
  });

  it("вложенность — граница с обеих сторон (РП65 нюанс 6): субъект на глубине 3, 4 обёртки — принят, 5 — DER", () => {
    const wrapped = (n: number): Buffer => {
      let s = seq();
      for (let i = 0; i < n; i++) s = seq(s);
      return s;
    };
    const pair = p256();
    // Субъект — глубина 3 (CSR 1, CRI 2): n обёрток кладут пустую SEQUENCE на глубину 3 + n; MAX_DEPTH — отказ.
    expect(MAX_DEPTH).toBe(8);
    expect(parseCsr(b64(buildCsrDer({ ...pair, subject: wrapped(4) }))).ok).toBe(true);
    expect(parseCsr(b64(buildCsrDer({ ...pair, subject: wrapped(5) })))).toEqual({ ok: false, reason: "DER" });
  });

  it("parseStrict: многобайтовый тег и длина длиннее двух байт — DerError", () => {
    expect(() => parseStrict(Buffer.from([0x1f, 0x01, 0x00]))).toThrow(DerError);
    expect(() => parseStrict(Buffer.from([0x30, 0x83, 0x00, 0x00, 0x01, 0x00]))).toThrow(DerError);
    expect(() => parseStrict(Buffer.from([0x30, 0x81, 0x05, 0, 0, 0, 0, 0]))).toThrow(/кратчайшей/);
  });
});

describe("разбор CSR: шаблон и подпись (РП65 п. 2)", () => {
  const b64 = (b: Buffer): string => b.toString("base64");

  it.each([
    ["P-384", () => generateKeyPairSync("ec", { namedCurve: "secp384r1" })],
    ["RSA", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
    ["ed25519", () => generateKeyPairSync("ed25519")],
  ])("ключ %s — TEMPLATE", (_n, gen) => {
    const pair = gen();
    expect(parseCsr(b64(buildCsrDer(pair)))).toEqual({ ok: false, reason: "TEMPLATE" });
  });

  it("P-256, но подпись ecdsa-with-SHA384 — TEMPLATE", () => {
    const pair = p256();
    expect(parseCsr(b64(buildCsrDer({ ...pair, sigOid: "1.2.840.10045.4.3.3" })))).toEqual({ ok: false, reason: "TEMPLATE" });
  });

  it("подписан чужим ключом — SIGNATURE (нет владения ключом)", () => {
    const pair = p256();
    expect(parseCsr(b64(buildCsrDer({ ...pair, signWith: p256().privateKey })))).toEqual({ ok: false, reason: "SIGNATURE" });
  });

  it("испорченная подпись — SIGNATURE", () => {
    const d = Buffer.from(newCsr().csr, "base64");
    d[d.length - 2] = d[d.length - 2]! ^ 0x01;
    expect(parseCsr(b64(d))).toEqual({ ok: false, reason: "SIGNATURE" });
  });

  it("точка не на кривой — KEY", () => {
    const pair = p256();
    const spki = Buffer.concat([P256_SPKI_PREFIX, Buffer.from([0x04]), Buffer.alloc(64, 0x01)]);
    expect(parseCsr(b64(buildCsrDer({ ...pair, spki })))).toEqual({ ok: false, reason: "KEY" });
  });

  it("сжатая точка — TEMPLATE", () => {
    const pair = p256();
    const raw = pair.publicKey.export({ format: "der", type: "spki" });
    const x = raw.subarray(P256_SPKI_PREFIX.length + 1, P256_SPKI_PREFIX.length + 33);
    const compressed = Buffer.concat([Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex"), Buffer.from([0x02]), x]);
    expect(parseCsr(b64(buildCsrDer({ ...pair, spki: compressed })))).toEqual({ ok: false, reason: "TEMPLATE" });
  });

  it("версия не 0 — TEMPLATE", () => {
    const pair = p256();
    const good = Buffer.from(buildCsrDer(pair));
    // version 020100 → 020101; подпись не совпадёт, но шаблон проверяется раньше.
    const i = good.indexOf(Buffer.from("020100", "hex"));
    const v1 = Buffer.from(good);
    v1[i + 2] = 0x01;
    expect(parseCsr(b64(v1))).toEqual({ ok: false, reason: "TEMPLATE" });
  });

  // КТ1 № 6: остальные отступления от шаблона — подписаны верно, отказ только по шаблону.
  describe("отступления от шаблона при верной подписи — TEMPLATE", () => {
    const pair = p256();
    const spki = pair.publicKey.export({ format: "der", type: "spki" });
    const ecdsa = seq(oid("1.2.840.10045.4.3.2"));
    const signed = (info: Buffer): Buffer => sign("sha256", info, { key: pair.privateKey, dsaEncoding: "der" });
    const info = seq(uint(Buffer.from([0])), seq(), spki, tlv(0xa0));

    it("ecdsa-with-SHA256 с параметром NULL", () => {
      const csr = seq(info, seq(oid("1.2.840.10045.4.3.2"), tlv(0x05)), bitString(signed(info)));
      expect(parseCsr(b64(csr))).toEqual({ ok: false, reason: "TEMPLATE" });
    });

    it("неиспользуемые биты подписи ≠ 0", () => {
      const csr = seq(info, ecdsa, bitString(signed(info), 1));
      expect(parseCsr(b64(csr))).toEqual({ ok: false, reason: "TEMPLATE" });
    });

    it("четвёртый элемент верхнего уровня", () => {
      const csr = seq(info, ecdsa, bitString(signed(info)), tlv(0x05));
      expect(parseCsr(b64(csr))).toEqual({ ok: false, reason: "TEMPLATE" });
    });

    it("CRI без атрибутов [0]", () => {
      const noAttrs = seq(uint(Buffer.from([0])), seq(), spki);
      const csr = seq(noAttrs, ecdsa, bitString(signed(noAttrs)));
      expect(parseCsr(b64(csr))).toEqual({ ok: false, reason: "TEMPLATE" });
    });

    it("тот же CSR по шаблону — принят (контроль)", () => {
      expect(parseCsr(b64(seq(info, ecdsa, bitString(signed(info))))).ok).toBe(true);
    });
  });
});

describe("DER: запись", () => {
  it("OID, INTEGER и время по RFC 5280", () => {
    expect(oid("1.2.840.10045.4.3.2").toString("hex")).toBe("06082a8648ce3d040302");
    expect(oid("2.5.29.17").toString("hex")).toBe("0603551d11");
    expect(uint(Buffer.from([0, 0, 0x80])).toString("hex")).toBe("02020080");
    expect(uint(Buffer.from([0, 0x01])).toString("hex")).toBe("020101");
    expect(time(new Date("2049-12-31T23:59:59Z")).toString("ascii").slice(2)).toBe("491231235959Z");
    expect(time(new Date("2050-01-01T00:00:00Z")).toString("ascii").slice(2)).toBe("20500101000000Z");
    expect(time(new Date("2049-12-31T23:59:59Z"))[0]).toBe(0x17);
    expect(time(new Date("2050-01-01T00:00:00Z"))[0]).toBe(0x18);
    expect(set(seq()).toString("hex")).toBe("31023000");
  });
});
