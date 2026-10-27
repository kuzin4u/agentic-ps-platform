// П1 Сертификат mTLS при допуске (РП27 п. 2, 4; РП65 п. 1, 3): поле csr в заявлении, выпуск УЦ песочницы по коду из
// записи, запись сертификата в транзакции допуска, список отзыва в реестре. Один набор — на памяти (локально) и на
// PostgreSQL (CI, РП30 п. 7); неделимость при сбое вставки сертификата — на обоих.
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AgentRegistry,
  DEFAULT_KEY_ALGORITHMS,
  ED25519,
  InMemoryAgentRegistryStore,
  PgAgentRegistryStore,
  SandboxCa,
  type AdmissionDecision,
  type AgentCertificateRecord,
  type AgentKey,
  type AgentRecord,
  type AgentRegistryStore,
  type CsrRejection,
  type RegistryCertificates,
} from "../../src/registry/index.js";
import { createStand } from "../../src/stand/index.js";
import { newCsr } from "../support/csr.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const NOW = new Date("2026-10-27T12:00:00.000Z");
const LATER = new Date("2026-10-27T13:00:00.000Z");
const OPERATOR = "buyref-operator";

let db: TestDb | undefined;
beforeAll(async () => {
  if (DATABASE_URL) db = await openTestDb("registry_certs");
});
afterAll(async () => {
  await db?.close();
});

let n = 0;
const uid = (): string => `c${++n}x${Date.now().toString(36)}`;

const variants: [string, () => AgentRegistryStore][] = [["память", () => new InMemoryAgentRegistryStore()]];
if (DATABASE_URL) variants.push(["PostgreSQL", () => new PgAgentRegistryStore((db as TestDb).pool)]);

const publicKey = (): string => generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");

const application = (id: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  agent_code: `nspk:agent:${id}:v1`,
  class: "BUYER",
  model: "buyer-agent-ref",
  runtime: "node-20",
  alg: "ed25519",
  public_key: publicKey(),
  ...over,
});

describe.each(variants)("сертификат mTLS при допуске: %s (РП65 п. 1, 3)", (_name, make) => {
  const setup = (over: Partial<RegistryCertificates> = {}) => {
    let clock = NOW;
    const store = make();
    const ca = SandboxCa.generate({ now: NOW, ttlDays: 3650 });
    const rejected: CsrRejection[] = [];
    const registry = new AgentRegistry(store, {
      keys: { key_ttl_days: 90, key_overlap_days: 7 },
      now: () => clock,
      certificates: { ca, ttlDays: 90, required: false, onRejected: (r) => rejected.push(r), ...over },
    });
    return { store, ca, registry, rejected, setClock: (d: Date) => (clock = d) };
  };
  const cert = (d: AdmissionDecision): AgentCertificateRecord => {
    expect(d.admitted).toBe(true);
    if (!d.admitted || !d.certificate) throw new Error("сертификата нет");
    return d.certificate;
  };

  it("CSR в заявлении → сертификат УЦ в решении о допуске и в реестре; SAN — код из записи (инвариант 5)", async () => {
    const { ca, registry } = setup();
    const id = uid();
    const d = await registry.admit(application(id, { csr: newCsr("nspk:agent:other:v9").csr }), { contour: "sandbox", operator: OPERATOR });
    const c = cert(d);
    expect(c).toMatchObject({ agent_code: `nspk:agent:${id}:v1`, revoked_at: null, not_before: NOW.toISOString() });
    const x = new X509Certificate(Buffer.from(c.der, "base64"));
    expect(x.subjectAltName).toBe(`URI:urn:nspk:agent:${id}:v1`);
    expect(x.verify(ca.publicKey)).toBe(true);
    expect(await registry.getCertificate(c.serial)).toEqual(c);
    expect(await registry.certificatesOf(`nspk:agent:${id}:v1`)).toEqual([c]);
  });

  it("стенд: CSR необязателен — без него допуск без сертификата", async () => {
    const { registry } = setup();
    const id = uid();
    const d = await registry.admit(application(id), { contour: "sandbox", operator: OPERATOR });
    expect(d).toMatchObject({ admitted: true });
    expect(d).not.toHaveProperty("certificate");
    expect(await registry.certificatesOf(`nspk:agent:${id}:v1`)).toEqual([]);
  });

  it("песочница с mTLS: CSR обязателен — без него APPLICATION_INCOMPLETE, ничего не сохранено", async () => {
    const { registry } = setup({ required: true });
    const id = uid();
    expect(await registry.admit(application(id), { contour: "sandbox", operator: OPERATOR })).toEqual({
      admitted: false,
      reasons: ["APPLICATION_INCOMPLETE"],
    });
    expect(await registry.get(`nspk:agent:${id}:v1`)).toBeUndefined();
    expect(cert(await registry.admit(application(uid(), { csr: newCsr().csr }), { contour: "sandbox", operator: OPERATOR }))).toBeDefined();
  });

  it.each([
    ["не строка", 42, "FORMAT"],
    ["null", null, "FORMAT"],
    ["PEM", "-----BEGIN CERTIFICATE REQUEST-----", "FORMAT"],
    ["испорченная подпись", "signWith", "SIGNATURE"],
  ])("плохой CSR (%s) — KEY_INVALID, вид причины — только в журнал, ничего не сохранено", async (_n, csr, reason) => {
    const { registry, rejected } = setup();
    const id = uid();
    let value: unknown = csr;
    if (csr === "signWith") {
      const der = Buffer.from(newCsr().csr, "base64");
      der[der.length - 2] = der[der.length - 2]! ^ 0x01;
      value = der.toString("base64");
    }
    expect(await registry.admit(application(id, { csr: value }), { contour: "sandbox", operator: OPERATOR })).toEqual({
      admitted: false,
      reasons: ["KEY_INVALID"],
    });
    expect(rejected).toEqual([reason]);
    expect(await registry.get(`nspk:agent:${id}:v1`)).toBeUndefined();
  });

  it("плохой CSR вместе с другими основаниями — все основания сразу (РП21 п. 2)", async () => {
    const { registry } = setup();
    const d = await registry.admit(application(uid(), { class: "ROBOT", csr: "AAAA" }), { contour: "sandbox", operator: OPERATOR });
    expect(d.admitted).toBe(false);
    expect(!d.admitted && [...d.reasons].sort()).toEqual(["CLASS_UNKNOWN", "KEY_INVALID"]);
  });

  it("контур operator: csr не читается — плохой CSR не отказ, сертификата нет (УЦ оператора, РП27 п. 6)", async () => {
    const rejected: CsrRejection[] = [];
    // ГОСТ — после точки расширения РП5; в тесте логики допуска контур operator принимает ed25519 (как registry.test.ts).
    const registry = new AgentRegistry(make(), {
      keys: { key_ttl_days: 90, key_overlap_days: 7 },
      now: () => NOW,
      algorithms: { ...DEFAULT_KEY_ALGORITHMS, operator: [ED25519] },
      certificates: { ca: SandboxCa.generate({ now: NOW, ttlDays: 3650 }), ttlDays: 90, required: true, onRejected: (r) => rejected.push(r) },
    });
    const d = await registry.admit(application(uid(), { csr: "мусор", conformance_run_ref: "run-1" }), {
      contour: "operator",
      operator: OPERATOR,
    });
    expect(d).toMatchObject({ admitted: true });
    expect(d).not.toHaveProperty("certificate");
    expect(rejected).toEqual([]);
  });

  it("реестр без УЦ (рабочий сервер до ч. 2): csr не читается", async () => {
    const store = make();
    const registry = new AgentRegistry(store, { keys: { key_ttl_days: 90, key_overlap_days: 7 }, now: () => NOW });
    const d = await registry.admit(application(uid(), { csr: "мусор" }), { contour: "sandbox", operator: OPERATOR });
    expect(d).toMatchObject({ admitted: true });
    expect(d).not.toHaveProperty("certificate");
  });

  it("отзыв: необратим, повтор — тот же revoked_at; чужой серийный номер — undefined; запись агента не меняется", async () => {
    const { registry, setClock } = setup();
    const id = uid();
    const c = cert(await registry.admit(application(id, { csr: newCsr().csr }), { contour: "sandbox", operator: OPERATOR }));
    setClock(LATER);
    const r1 = await registry.revokeCertificate(c.serial);
    expect(r1).toEqual({ ...c, revoked_at: LATER.toISOString() });
    setClock(new Date(LATER.getTime() + 60_000));
    expect(await registry.revokeCertificate(c.serial)).toEqual(r1);
    expect(await registry.getCertificate(c.serial)).toEqual(r1);
    expect(await registry.revokeCertificate("0".repeat(32))).toBeUndefined();
    // Отзыв сертификата не трогает статус агента (РП27 п. 4: приостановление и отзыв — разные действия).
    expect(await registry.get(`nspk:agent:${id}:v1`)).toMatchObject({ status: "ACTIVE", row_version: 1 });
  });

  // Вставка в хранилище в обход допуска — только здесь, чтобы вызвать сбой последней вставки транзакции допуска.
  const another = async (store: AgentRegistryStore, like: string): Promise<[AgentRecord, AgentKey]> => {
    const id = uid();
    const rec: AgentRecord = { ...(await store.get(like))!, agent_code: `nspk:agent:${id}:v1`, id };
    const key: AgentKey = { ...(await store.keysOf(like))[0]!, kid: `kid-${id}`, agent_code: rec.agent_code, public_key: `pk-${id}` };
    return [rec, key];
  };

  it("допуск неделим: сбой вставки сертификата (повтор серийного номера) — нет ни агента, ни владельца, ни ключа", async () => {
    const { store, registry } = setup();
    const c = cert(await registry.admit(application(uid(), { csr: newCsr().csr }), { contour: "sandbox", operator: OPERATOR }));
    const [rec, key] = await another(store, c.agent_code);
    await expect(store.insert(rec, key, { ...c, agent_code: rec.agent_code })).rejects.toThrow();
    expect(await store.get(rec.agent_code)).toBeUndefined();
    expect(await store.ownerOf(rec.issuer, rec.id)).toBeUndefined();
    expect(await store.getKey(key.kid)).toBeUndefined();
    expect(await store.certificatesOf(rec.agent_code)).toEqual([]);
    // Прежний сертификат с этим серийным номером — у прежнего агента.
    expect(await store.getCertificate(c.serial)).toEqual(c);
  });

  it("сертификат чужого агента в insert — исключение, ничего не сохранено", async () => {
    const { store, registry } = setup();
    const c = cert(await registry.admit(application(uid(), { csr: newCsr().csr }), { contour: "sandbox", operator: OPERATOR }));
    const [rec, key] = await another(store, c.agent_code);
    await expect(store.insert(rec, key, { ...c, serial: "1".repeat(32) })).rejects.toThrow(/не этого агента/);
    expect(await store.get(rec.agent_code)).toBeUndefined();
    expect(await store.getCertificate("1".repeat(32))).toBeUndefined();
  });
});

describe("стенд: csr в заявлении необязателен, УЦ стенда (РП65 п. 1)", () => {
  it("с CSR — сертификат, подписанный caCertificate стенда; без CSR — как прежде; плохой CSR — KEY_INVALID", async () => {
    const s = createStand();
    try {
      const root = new X509Certificate(Buffer.from(s.caCertificate, "base64"));
      expect(root.ca).toBe(true);
      const id = uid();
      const d = await s.admit(application(id, { csr: newCsr().csr }), OPERATOR);
      if (!d.admitted || !d.certificate) throw new Error("сертификата нет");
      const x = new X509Certificate(Buffer.from(d.certificate.der, "base64"));
      expect(x.checkIssued(root) && x.verify(root.publicKey)).toBe(true);
      expect(x.subjectAltName).toBe(`URI:urn:nspk:agent:${id}:v1`);
      const plain = await s.admit(application(uid()), OPERATOR);
      expect(plain).toMatchObject({ admitted: true });
      expect(plain).not.toHaveProperty("certificate");
      expect(await s.admit(application(uid(), { csr: "AAAA" }), OPERATOR)).toEqual({ admitted: false, reasons: ["KEY_INVALID"] });
    } finally {
      await s.close();
    }
  });
});
