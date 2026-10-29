// П9 Ступень 0 — сертификат канала mTLS (РП27 п. 3, РП66 п. 1–2): шаги по порядку, каждый — своим видом причины (поломка
// любого шага красит свой тест, а не прячется за соседним: цепочку и запись реестра перекрывают друг друга по коду ответа).
// Агенту — только AGENT_UNKNOWN, в том числе за истёкший и отозванный сертификат; сбой реестра — UPSTREAM_UNAVAILABLE.
// Список отзыва — чтение на каждом обращении: на PostgreSQL отзыв другим пулом виден следующей проверке (РП64 п. 3).
// Сертификат здесь — DER из PaoRequest; извлечение из TLS-сокета — тест рукопожатия (К3).
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { newEd25519Signer, signRequest, type HttpLike, type Signer } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PaoRequestVerifier, type ChannelTicket, type PaoAuthResult, type PaoPrecheckResult, type PaoRequest } from "../../src/pao/index.js";
import {
  AgentKeys,
  AgentRegistry,
  ED25519,
  InMemoryAgentRegistryStore,
  PgAgentRegistryStore,
  SandboxCa,
  parseKey,
  type AgentRegistryStore,
  type KeyPolicy,
} from "../../src/registry/index.js";
import { BOOLEAN_TRUE, octetString, oid, seq, tlv, utf8 } from "../../src/registry/ca/der.js";
import type { AgentCertificateRecord } from "../../src/registry/model.js";
import { newCsr } from "../support/csr.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const NOW = new Date("2026-10-27T12:00:00.000Z");
const SKEW = 300;
const POLICY: KeyPolicy = { key_ttl_days: 90, key_overlap_days: 7 };
const TTL_DAYS = 90;
/** revocation_propagation_max_ms стенда — срок отметки предпроверки (КТ1 К3.2 № 1 (а)). */
const TICKET_MS = 1000;

let db: TestDb | undefined;
beforeAll(async () => {
  if (DATABASE_URL) db = await openTestDb("pao_channel");
});
afterAll(async () => {
  await db?.close();
});

let n = 0;
const uid = (): string => `ch${++n}x${Date.now().toString(36)}`;

/** Хранилище и «другой процесс» на той же базе: в памяти — то же хранилище, на PG — новый пул. */
interface Variant {
  readonly store: () => AgentRegistryStore;
  readonly other: (s: AgentRegistryStore) => AgentRegistryStore;
}
const variants: [string, Variant][] = [["память", { store: () => new InMemoryAgentRegistryStore(), other: (s) => s }]];
if (DATABASE_URL) {
  variants.push([
    "PostgreSQL",
    { store: () => new PgAgentRegistryStore((db as TestDb).pool), other: () => new PgAgentRegistryStore((db as TestDb).reopen()) },
  ]);
}

function agentSigner(): { signer: Signer; publicKey: string } {
  const { signer, publicKey } = newEd25519Signer("tmp");
  const { kid } = parseKey([ED25519], "ed25519", publicKey) as { kid: string };
  return { signer: { ...signer, kid }, publicKey };
}

let nonceSeq = 0;
/** cert — DER; authorized — итог проверки цепочки TLS (по умолчанию подтверждена: здесь проверяются свои шаги). */
function signed(signer: Signer, agent_code: string, cert: Buffer | undefined, ts: Date = NOW, authorized = true): PaoRequest {
  const req: HttpLike = {
    method: "GET",
    path: "/pao/v1/agent",
    query: "",
    headers: { "x-agent-code": agent_code, "x-timestamp": ts.toISOString(), "x-nonce": `c-${++nonceSeq}` },
    body: "",
  };
  const s = signRequest(req, signer);
  return { method: s.method, path: s.path, query: s.query ?? "", headers: s.headers, body: "", ...(cert ? { clientCertificate: { der: cert, authorized } } : {}) };
}

const outcome = (r: PaoAuthResult | PaoPrecheckResult): string => (r === undefined || r.ok ? "OK" : r.channel ? `${r.code}/${r.channel}` : r.code);

/** GeneralName SAN: [6] URI, [2] DNS, [0] otherName (OID и значение UTF8String). */
const uri = (s: string): Buffer => tlv(0x86, Buffer.from(s, "ascii"));
const dns = (s: string): Buffer => tlv(0x82, Buffer.from(s, "ascii"));
const otherName = (): Buffer => tlv(0xa0, Buffer.concat([oid("1.3.6.1.4.1.99999.1"), tlv(0xa0, utf8("x"))]));

/**
 * Сертификат с произвольным SAN, подписанный ключом УЦ, — для шага «вид субъекта» (решение владельца 27.10, PR #79).
 * Закрытый метод signTbs вызывается только здесь и намеренно: штатный выпуск (issueAgentCertificate) подписывает ровно один
 * URI кода песочницы (РП65 п. 2, нюанс 3), а открыть в коде выпуск с произвольным SAN — значит обойти шаблон РП65. Без
 * подписи УЦ такой сертификат отсёк бы шаг 2, и шаг 3 остался бы непроверенным.
 */
function caSigned(ca: SandboxCa, names: string | readonly Buffer[], serial: Buffer): Buffer {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const general = typeof names === "string" ? [uri(names)] : names;
  const san = seq(oid("2.5.29.17"), BOOLEAN_TRUE, octetString(seq(...general)));
  const signTbs = (ca as unknown as { signTbs: (...a: unknown[]) => Buffer }).signTbs.bind(ca);
  return signTbs(serial, seq(), NOW, new Date(NOW.getTime() + 86_400_000), publicKey, [san]);
}

describe.each(variants)("ступень 0 — сертификат канала: %s (РП66 п. 1)", (_name, v) => {
  /**
   * tamper — подмена записи, которую видит проверка: запись другого агента или другие байты под тем же серийным номером
   * (в реестре так не бывает — серийный номер первичный ключ; проверяется, что шаг 4 сверяет запись целиком).
   */
  function stand(opts: { tamper?: (r: AgentCertificateRecord) => AgentCertificateRecord; caOverride?: X509Certificate } = {}) {
    let clock = NOW;
    const now = (): Date => clock;
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const store = v.store();
    const registry = new AgentRegistry(store, { keys: POLICY, now, certificates: { ca, ttlDays: TTL_DAYS, backdateSec: 300, required: true } });
    const keys = new AgentKeys(store, { keys: POLICY, now });
    let failReads = false;
    let reads = 0;
    const read = async (serial: string): Promise<AgentCertificateRecord | undefined> => {
      reads++;
      if (failReads) throw new Error("PG: нет соединения");
      const r = await registry.getCertificate(serial);
      return r && opts.tamper ? opts.tamper(r) : r;
    };
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: SKEW, now, mtls: { ca: opts.caOverride ?? new X509Certificate(ca.certificateDer), getCertificate: read, ticketMaxAgeMs: TICKET_MS } },
    );
    const admit = async (): Promise<{ code: string; signer: Signer; cert: Buffer; serial: string }> => {
      const code = `nspk:agent:${uid()}:v1`;
      const { signer, publicKey } = agentSigner();
      const d = await registry.admit(
        { agent_code: code, class: "BUYER", model: "m", runtime: "r", alg: "ed25519", public_key: publicKey, csr: newCsr().csr },
        { contour: "sandbox", operator: "op" },
      );
      if (!d.admitted || !d.certificate) throw new Error("допуск с сертификатом не прошёл");
      return { code, signer, cert: Buffer.from(d.certificate.der, "base64"), serial: d.certificate.serial };
    };
    return { ca, store, registry, verifier, admit, setClock: (d: Date) => (clock = d), failReads: () => (failReads = true), reads: () => reads };
  }

  it("свой сертификат, код из SAN = x-agent-code — принято (verify и предпроверка)", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("OK");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("OK");
    // Связка серийного номера (КТ1 № 6): Node — hex в верхнем регистре, реестр — в нижнем, ведущих нулей нет.
    expect(new X509Certificate(a.cert).serialNumber.toLowerCase()).toBe(a.serial);
    expect(a.serial).toMatch(/^[4-7][0-9a-f]{31}$/);
  });

  it("шаг 1: сертификата нет — AGENT_UNKNOWN / NO_CERTIFICATE, раньше реестра агентов", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, undefined)))).toBe("AGENT_UNKNOWN/NO_CERTIFICATE");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, undefined)))).toBe("AGENT_UNKNOWN/NO_CERTIFICATE");
  });

  it("TLS не подтвердил цепочку (authorized ≠ true) — AGENT_UNKNOWN / TLS_NOT_AUTHORIZED, хотя сертификат свой (дополнение 1)", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert, NOW, false)))).toBe("AGENT_UNKNOWN/TLS_NOT_AUTHORIZED");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert, NOW, false)))).toBe("AGENT_UNKNOWN/TLS_NOT_AUTHORIZED");
  });

  it("TLS_NOT_AUTHORIZED — код OpenSSL рядом, только вида [A-Z0-9_]; текст и пустое — не передаются (КТ1 К3.2 № 9)", async () => {
    const s = stand();
    const a = await s.admit();
    const withError = (authorizationError: string): PaoRequest => {
      const r = signed(a.signer, a.code, a.cert, NOW, false);
      return { ...r, clientCertificate: { der: a.cert, authorized: false, authorizationError } };
    };
    const tlsError = (r: PaoAuthResult | PaoPrecheckResult) => (r && !r.ok ? r.channelTlsError : "ok");
    expect(tlsError(await s.verifier.verify(withError("CERT_HAS_EXPIRED")))).toBe("CERT_HAS_EXPIRED");
    expect(tlsError(await s.verifier.precheck(withError("UNABLE_TO_GET_ISSUER_CERT")))).toBe("UNABLE_TO_GET_ISSUER_CERT");
    for (const bad of ["certificate has expired", "", "A".repeat(65), "CERT\nHAS"]) {
      expect(tlsError(await s.verifier.verify(withError(bad))), JSON.stringify(bad)).toBeUndefined();
    }
    // Без authorizationError — как прежде: вид причины есть, кода нет.
    expect(tlsError(await s.verifier.verify(signed(a.signer, a.code, a.cert, NOW, false)))).toBeUndefined();
  });

  it("шаг 2: чужой УЦ или не сертификат — AGENT_UNKNOWN / NOT_ISSUED_BY_CA", async () => {
    const s = stand();
    const a = await s.admit();
    const foreign = SandboxCa.generate({ now: NOW, ttlDays: 3650 }).issueAgentCertificate(newCsr().csr, a.code, NOW, TTL_DAYS, 300);
    if (!foreign.ok) throw new Error("выпуск чужим УЦ");
    const der = Buffer.from(foreign.certificate.der, "base64");
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, der)))).toBe("AGENT_UNKNOWN/NOT_ISSUED_BY_CA");
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, Buffer.from("не сертификат"))))).toBe("AGENT_UNKNOWN/NOT_ISSUED_BY_CA");
    // Корневой сертификат УЦ — выпущен самим УЦ, но не агентский: дальше его не пускает шаг 3.
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, s.ca.certificateDer)))).toBe("AGENT_UNKNOWN/SUBJECT_NOT_AGENT");
  });

  it("шаг 3: SAN — оператор или код не песочницы, хотя подписан УЦ, — AGENT_UNKNOWN / SUBJECT_NOT_AGENT", async () => {
    const s = stand();
    const a = await s.admit();
    for (const uri of ["urn:nspk:operator:op-1", "urn:other:agent:x:v1", `urn:${a.code}x,URI:urn:${a.code}`]) {
      const der = caSigned(s.ca, uri, Buffer.from("4000000000000000000000000000000a", "hex"));
      expect(outcome(await s.verifier.verify(signed(a.signer, a.code, der))), uri).toBe("AGENT_UNKNOWN/SUBJECT_NOT_AGENT");
    }
  });

  it("шаг 3: несколько записей SAN, хотя первая — URI агента, — AGENT_UNKNOWN / SUBJECT_NOT_AGENT (ровно один URI, КТ1 № 2)", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit();
    const cases: [string, Buffer[]][] = [
      ["[URI A, URI A]", [uri(`urn:${a.code}`), uri(`urn:${a.code}`)]],
      ["[URI A, URI B]", [uri(`urn:${a.code}`), uri(`urn:${b.code}`)]],
      ["[DNS, URI A]", [dns("agent.example"), uri(`urn:${a.code}`)]],
      ["[URI A, otherName]", [uri(`urn:${a.code}`), otherName()]],
    ];
    for (const [name, names] of cases) {
      const der = caSigned(s.ca, names, Buffer.from("4000000000000000000000000000000b", "hex"));
      expect(outcome(await s.verifier.verify(signed(a.signer, a.code, der))), name).toBe("AGENT_UNKNOWN/SUBJECT_NOT_AGENT");
    }
  });

  it("шаг 4: запись реестра другого агента под тем же серийным номером — AGENT_UNKNOWN / NOT_IN_REGISTRY", async () => {
    // Байты те же — держит только сверка agent_code записи с кодом из SAN.
    const s = stand({ tamper: (r) => ({ ...r, agent_code: "nspk:agent:someone-else:v1" }) });
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/NOT_IN_REGISTRY");
  });

  it("шаг 4: под тем же серийным номером в реестре другие байты DER — AGENT_UNKNOWN / NOT_IN_REGISTRY (нюанс РП66)", async () => {
    // Агент в записи тот же — держит только сверка байтов: сертификат не тот, что выдан, хотя номер и SAN совпадают.
    const s = stand({ tamper: (r) => ({ ...r, der: Buffer.from(r.der, "base64").reverse().toString("base64") }) });
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/NOT_IN_REGISTRY");
  });

  it("шаг 4: выпущен УЦ, но нет в реестре — AGENT_UNKNOWN / NOT_IN_REGISTRY", async () => {
    const s = stand();
    const a = await s.admit();
    const issued = s.ca.issueAgentCertificate(newCsr().csr, a.code, NOW, TTL_DAYS, 300);
    if (!issued.ok) throw new Error("выпуск");
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, Buffer.from(issued.certificate.der, "base64"))))).toBe(
      "AGENT_UNKNOWN/NOT_IN_REGISTRY",
    );
  });

  it("шаг 5: SAN ≠ x-agent-code — агент B со своей подписью через канал A — AGENT_UNKNOWN / CODE_MISMATCH", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit();
    // Подпись B верна, B в реестре, сертификат A действует — держит только сверка кода канала с x-agent-code.
    expect(outcome(await s.verifier.verify(signed(b.signer, b.code, a.cert)))).toBe("AGENT_UNKNOWN/CODE_MISMATCH");
    expect(outcome(await s.verifier.precheck(signed(b.signer, b.code, a.cert)))).toBe("AGENT_UNKNOWN/CODE_MISMATCH");
    expect(outcome(await s.verifier.verify(signed(b.signer, b.code, b.cert)))).toBe("OK");
    // Повтор x-agent-code (массив) — не совпадение, а не догадка (инвариант 3).
    const dup = signed(a.signer, a.code, a.cert);
    expect(outcome(await s.verifier.verify({ ...dup, headers: { ...dup.headers, "x-agent-code": [a.code, a.code] } }))).toBe(
      "AGENT_UNKNOWN/CODE_MISMATCH",
    );
  });

  it("шаг 6: вне срока по часам Платформы — AGENT_UNKNOWN / OUTSIDE_VALIDITY, не AGENT_KEY_REVOKED (РП66 п. 2)", async () => {
    const s = stand();
    const a = await s.admit();
    const rec = await s.registry.getCertificate(a.serial);
    const notAfter = new Date(rec?.not_after as string);
    s.setClock(new Date(notAfter.getTime() - 1000));
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("OK");
    s.setClock(notAfter);
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/OUTSIDE_VALIDITY");
    s.setClock(new Date(NOW.getTime() - 1000));
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/OUTSIDE_VALIDITY");
  });

  it("шаг 6: неразбираемое время в записи или часах — AGENT_UNKNOWN / OUTSIDE_VALIDITY, не допуск (КТ1 № 3, инвариант 3)", async () => {
    for (const field of ["not_before", "not_after"] as const) {
      const s = stand({ tamper: (r) => ({ ...r, [field]: "не дата" }) });
      const a = await s.admit();
      expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert))), field).toBe("AGENT_UNKNOWN/OUTSIDE_VALIDITY");
    }
    const s = stand();
    const a = await s.admit();
    s.setClock(new Date(Number.NaN));
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/OUTSIDE_VALIDITY");
  });

  it("исключение самой проверки — AGENT_UNKNOWN / CHECK_FAILED, а не исключение из хука (КТ1 № 4)", async () => {
    // Доверенный УЦ не сертификат — checkIssued бросает: отказ без обращения к реестру.
    const s = stand({ caOverride: {} as X509Certificate });
    const a = await s.admit();
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/CHECK_FAILED");
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/CHECK_FAILED");
  });

  it("шаг 6: отозван — следующая же проверка AGENT_UNKNOWN / REVOKED; отзыв «другим процессом» виден без кэша", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("OK");
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/REVOKED");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/REVOKED");
  });

  it("отметка предпроверки: verify не читает реестр сертификатов второй раз; отзыв во время чтения тела обращение не прерывает (нюанс 7 РП66)", async () => {
    const s = stand();
    const a = await s.admit();
    const req = signed(a.signer, a.code, a.cert);
    const pre = await s.verifier.precheck(req);
    if (!pre?.ok) throw new Error("предпроверка не прошла");
    expect(s.reads()).toBe(1);
    // Отзыв между onRequest и preHandler (чтение тела): обращение уже допущено ступенью 0 — исполняется (инвариант 8).
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    expect(outcome(await s.verifier.verify({ ...req, channelTicket: pre.channelTicket }))).toBe("OK");
    expect(s.reads()).toBe(1);
  });

  it("отметка старше revocation_propagation_max_ms по часам Платформы — ступень 0 заново: REVOKED; на границе — принята (КТ1 № 1 (а))", async () => {
    const s = stand();
    const a = await s.admit();
    const issue = async () => {
      s.setClock(NOW);
      const req = signed(a.signer, a.code, a.cert);
      const pre = await s.verifier.precheck(req);
      if (!pre?.ok) throw new Error("предпроверка не прошла");
      return { req, ticket: pre.channelTicket };
    };
    const onBorder = await issue();
    const late = await issue();
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    s.setClock(new Date(NOW.getTime() + TICKET_MS));
    expect(outcome(await s.verifier.verify({ ...onBorder.req, channelTicket: onBorder.ticket }))).toBe("OK");
    s.setClock(new Date(NOW.getTime() + TICKET_MS + 1));
    expect(outcome(await s.verifier.verify({ ...late.req, channelTicket: late.ticket }))).toBe("AGENT_UNKNOWN/REVOKED");
  });

  it("часы Платформы пошли назад после предпроверки — отметка не принимается, ступень 0 заново (инвариант 3)", async () => {
    const s = stand();
    const a = await s.admit();
    const req = signed(a.signer, a.code, a.cert);
    const pre = await s.verifier.precheck(req);
    if (!pre?.ok) throw new Error("предпроверка не прошла");
    // Возраст отметки отрицателен; ступень 0 заново отсекает срок (часы раньше notBefore = notBefore УЦ), а принятая отметка
    // дала бы OK.
    s.setClock(new Date(NOW.getTime() - 1));
    expect(outcome(await s.verifier.verify({ ...req, channelTicket: pre.channelTicket }))).toBe("AGENT_UNKNOWN/OUTSIDE_VALIDITY");
  });

  it("отметка однократна: повтор той же отметки — ступень 0 заново", async () => {
    const s = stand();
    const a = await s.admit();
    const req = signed(a.signer, a.code, a.cert);
    const pre = await s.verifier.precheck(req);
    if (!pre?.ok) throw new Error("предпроверка не прошла");
    expect(outcome(await s.verifier.verify({ ...req, channelTicket: pre.channelTicket }))).toBe("OK");
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    const again = signed(a.signer, a.code, a.cert);
    expect(outcome(await s.verifier.verify({ ...again, channelTicket: pre.channelTicket }))).toBe("AGENT_UNKNOWN/REVOKED");
  });

  it("прямой verify с отозванным сертификатом и чужой отметкой (не выданной проверяющим) — ступень 0 сам: REVOKED (В2)", async () => {
    const s = stand();
    const a = await s.admit();
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    const forged = Object.freeze({}) as ChannelTicket;
    expect(outcome(await s.verifier.verify({ ...signed(a.signer, a.code, a.cert), channelTicket: forged }))).toBe("AGENT_UNKNOWN/REVOKED");
  });

  it("отметка другого обращения (другие DER и x-agent-code) — не принимается: REVOKED (В2)", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit();
    const pre = await s.verifier.precheck(signed(b.signer, b.code, b.cert));
    if (!pre?.ok) throw new Error("предпроверка B не прошла");
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    expect(outcome(await s.verifier.verify({ ...signed(a.signer, a.code, a.cert), channelTicket: pre.channelTicket }))).toBe(
      "AGENT_UNKNOWN/REVOKED",
    );
  });

  it("отметка того же x-agent-code, но другой сертификат (DER) — не принимается: CODE_MISMATCH", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit();
    const pre = await s.verifier.precheck(signed(a.signer, a.code, a.cert));
    if (!pre?.ok) throw new Error("предпроверка не прошла");
    expect(outcome(await s.verifier.verify({ ...signed(a.signer, a.code, b.cert), channelTicket: pre.channelTicket }))).toBe(
      "AGENT_UNKNOWN/CODE_MISMATCH",
    );
  });

  it("отметка того же сертификата, но другой x-agent-code — не принимается: CODE_MISMATCH", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit();
    const pre = await s.verifier.precheck(signed(a.signer, a.code, a.cert));
    if (!pre?.ok) throw new Error("предпроверка не прошла");
    expect(outcome(await s.verifier.verify({ ...signed(b.signer, b.code, a.cert), channelTicket: pre.channelTicket }))).toBe(
      "AGENT_UNKNOWN/CODE_MISMATCH",
    );
  });

  it("сбой чтения реестра сертификатов — UPSTREAM_UNAVAILABLE с причиной, не AGENT_UNKNOWN (РП23 доп. 4)", async () => {
    const s = stand();
    const a = await s.admit();
    s.failReads();
    const r = await s.verifier.verify(signed(a.signer, a.code, a.cert));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("UPSTREAM_UNAVAILABLE");
    expect(r.cause).toBeInstanceOf(Error);
    expect(r.channel).toBeUndefined();
  });
});

describe("без mtls (стенд, dev — РП27 п. 5): сертификат не требуется и не читается", () => {
  it("обращение без сертификата принимается как прежде", async () => {
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: POLICY, now: () => NOW });
    const keys = new AgentKeys(store, { keys: POLICY, now: () => NOW });
    const { signer, publicKey } = agentSigner();
    const code = `nspk:agent:${uid()}:v1`;
    await registry.admit({ agent_code: code, class: "BUYER", model: "m", runtime: "r", alg: "ed25519", public_key: publicKey }, { contour: "sandbox", operator: "op" });
    const verifier = new PaoRequestVerifier({ getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) }, { skewSec: SKEW, now: () => NOW });
    expect(outcome(await verifier.verify(signed(signer, code, undefined)))).toBe("OK");
  });
});
