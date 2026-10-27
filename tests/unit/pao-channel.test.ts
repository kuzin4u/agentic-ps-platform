// П9 Ступень 0 — сертификат канала mTLS (РП27 п. 3, РП66 п. 1–2): шаги по порядку, каждый — своим видом причины (поломка
// любого шага красит свой тест, а не прячется за соседним: цепочку и запись реестра перекрывают друг друга по коду ответа).
// Агенту — только AGENT_UNKNOWN, в том числе за истёкший и отозванный сертификат; сбой реестра — UPSTREAM_UNAVAILABLE.
// Список отзыва — чтение на каждом обращении: на PostgreSQL отзыв другим пулом виден следующей проверке (РП64 п. 3).
// Сертификат здесь — DER из PaoRequest; извлечение из TLS-сокета — тест рукопожатия (К3).
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { newEd25519Signer, signRequest, type HttpLike, type Signer } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PaoRequestVerifier, type PaoAuthResult, type PaoRequest } from "../../src/pao/index.js";
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
import { BOOLEAN_TRUE, octetString, oid, seq, tlv } from "../../src/registry/ca/der.js";
import { newCsr } from "../support/csr.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const NOW = new Date("2026-10-27T12:00:00.000Z");
const SKEW = 300;
const POLICY: KeyPolicy = { key_ttl_days: 90, key_overlap_days: 7 };
const TTL_DAYS = 90;

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
function signed(signer: Signer, agent_code: string, cert: Buffer | undefined, ts: Date = NOW): PaoRequest {
  const req: HttpLike = {
    method: "GET",
    path: "/pao/v1/agent",
    query: "",
    headers: { "x-agent-code": agent_code, "x-timestamp": ts.toISOString(), "x-nonce": `c-${++nonceSeq}` },
    body: "",
  };
  const s = signRequest(req, signer);
  return { method: s.method, path: s.path, query: s.query ?? "", headers: s.headers, body: "", ...(cert ? { clientCertificate: cert } : {}) };
}

const outcome = (r: PaoAuthResult | undefined): string => (r === undefined || r.ok ? "OK" : r.channel ? `${r.code}/${r.channel}` : r.code);

/**
 * Сертификат с произвольным SAN, подписанный ключом УЦ, — для шага «вид субъекта»: штатный выпуск УЦ кода не песочницы не
 * подписывает (РП65 нюанс 3). Закрытый метод signTbs — только в тесте.
 */
function caSigned(ca: SandboxCa, sanUri: string, serial: Buffer): Buffer {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const san = seq(oid("2.5.29.17"), BOOLEAN_TRUE, octetString(seq(tlv(0x86, Buffer.from(sanUri, "ascii")))));
  const signTbs = (ca as unknown as { signTbs: (...a: unknown[]) => Buffer }).signTbs.bind(ca);
  return signTbs(serial, seq(), NOW, new Date(NOW.getTime() + 86_400_000), publicKey, [san]);
}

describe.each(variants)("ступень 0 — сертификат канала: %s (РП66 п. 1)", (_name, v) => {
  function stand() {
    let clock = NOW;
    const now = (): Date => clock;
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const store = v.store();
    const registry = new AgentRegistry(store, { keys: POLICY, now, certificates: { ca, ttlDays: TTL_DAYS, required: true } });
    const keys = new AgentKeys(store, { keys: POLICY, now });
    let failReads = false;
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      {
        skewSec: SKEW,
        now,
        mtls: {
          ca: new X509Certificate(ca.certificateDer),
          getCertificate: (serial) => (failReads ? Promise.reject(new Error("PG: нет соединения")) : registry.getCertificate(serial)),
        },
      },
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
    return { ca, store, registry, verifier, admit, setClock: (d: Date) => (clock = d), failReads: () => (failReads = true) };
  }

  it("свой сертификат, код из SAN = x-agent-code — принято (verify и предпроверка)", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("OK");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("OK");
  });

  it("шаг 1: сертификата нет — AGENT_UNKNOWN / NO_CERTIFICATE, раньше реестра агентов", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, undefined)))).toBe("AGENT_UNKNOWN/NO_CERTIFICATE");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, undefined)))).toBe("AGENT_UNKNOWN/NO_CERTIFICATE");
  });

  it("шаг 2: чужой УЦ или не сертификат — AGENT_UNKNOWN / NOT_ISSUED_BY_CA", async () => {
    const s = stand();
    const a = await s.admit();
    const foreign = SandboxCa.generate({ now: NOW, ttlDays: 3650 }).issueAgentCertificate(newCsr().csr, a.code, NOW, TTL_DAYS);
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

  it("шаг 4: выпущен УЦ, но нет в реестре (или запись другого агента) — AGENT_UNKNOWN / NOT_IN_REGISTRY", async () => {
    const s = stand();
    const a = await s.admit();
    const issued = s.ca.issueAgentCertificate(newCsr().csr, a.code, NOW, TTL_DAYS);
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

  it("шаг 6: отозван — следующая же проверка AGENT_UNKNOWN / REVOKED; отзыв «другим процессом» виден без кэша", async () => {
    const s = stand();
    const a = await s.admit();
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("OK");
    await new AgentRegistry(v.other(s.store), { keys: POLICY, now: () => NOW }).revokeCertificate(a.serial);
    expect(outcome(await s.verifier.verify(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/REVOKED");
    expect(outcome(await s.verifier.precheck(signed(a.signer, a.code, a.cert)))).toBe("AGENT_UNKNOWN/REVOKED");
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
