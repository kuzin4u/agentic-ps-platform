// П10 / П2 Подпись принципала (PS-06 К2.4; РП12, РП36): ПИ-8 POST /participants/v1/mandates/{id}/sign только с подписью
// участника над Mandate.hash; доверенные ключи — до PS-20; запись только при PENDING_SIGNATURE; повтор — без второй записи.
// Одни и те же проверки — на памяти ядра (всегда) и на PostgreSQL (в CI, РП30 п. 7).
import { createHash, generateKeyPairSync, randomUUID, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AsyncHashChainJournal, canonicalJson } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { mandateIdFor, type MandateDecisionPayload } from "../../src/consent/model.js";
import { MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator, type IssuerEmulator } from "../../src/env/issuer/index.js";
import {
  loadTrustedParticipants,
  STAND_REVOCATION_ORDER,
  PARTICIPANT_SIGNATURE_CONTEXT,
  participantSigningInput,
  STAND_ISSUER_CODE,
  TrustedParticipants,
  type ParticipantSignedRecord,
  type TrustedParticipantKey,
} from "../../src/participants/trusted.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buildServer } from "../../src/server.js";
import { createStand } from "../../src/stand/index.js";
import type { Mandate, MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { signedInject } from "../support/signed-inject.js";
import { signDirect } from "../support/consent-sign.js";

const A = "nspk:agent:sign-a:v1";
const T0 = new Date("2026-10-18T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 };
const key = (): string => createHash("sha256").update(randomUUID()).digest("hex");

const intent = (over: Partial<MandateRequest> = {}): MandateRequest => ({
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});

const cart = (parent_id: string): MandateRequest =>
  intent({
    type: "CART",
    parent_id,
    subject: "корзина SHOP-1042",
    amount_limit: 12_900,
    cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
  });

/** Ключ участника вне эмулятора: «боевой» банк теста. */
function liveKey(code: string): { key: TrustedParticipantKey; sign: (r: ParticipantSignedRecord) => string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  return {
    key: { participant_code: code, kid: jwkThumbprint({ crv, kty, x }), alg: "ed25519", public_key, revocation_order: `bank:${code}:revocation:v1` },
    sign: (r) => edSign(null, participantSigningInput(r), privateKey).toString("base64url"),
  };
}

interface Ctx {
  store: ConsentStore;
  consent: ConsentJournal;
  app: FastifyInstance;
  emu: IssuerEmulator;
}

function setup(store: ConsentStore): Ctx {
  const consent = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
  const emu = createIssuerEmulator();
  const trusted = new TrustedParticipants([emu.trustedKey], { stand: true });
  const app = buildServer({ env: "dev", participants: { trusted, consent, params: POLICY } });
  return { store, consent, app, emu };
}

function record(c: Ctx, id: string, hash: string, over: Partial<ParticipantSignedRecord> = {}): ParticipantSignedRecord {
  return {
    participant_code: c.emu.participant_code,
    kid: c.emu.trustedKey.kid,
    mandate_id: id,
    mandate_hash: hash,
    decision: "SIGN",
    signature_type: "simple",
    signature_ref: `sig-${id.slice(-6)}`,
    token_consent: true,
    signed_at: T0.toISOString(),
    ...over,
  };
}

/** Тело запроса: запись без mandate_id (он в пути) и подпись. */
function body(r: ParticipantSignedRecord, signature: string): Record<string, unknown> {
  const { mandate_id: _id, ...rest } = r;
  void _id;
  return { ...rest, signature };
}

async function post(c: Ctx, id: string, payload: unknown) {
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/mandates/${id}/sign`, payload: payload as object });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
}

/** Запрос мандата агентом A: id и hash присваивает Платформа, в ответе они есть всегда. */
async function mk(c: Ctx, req: MandateRequest): Promise<{ id: string; hash: string }> {
  const m = await c.consent.request(A, key(), req);
  if (!m.id || !m.hash) throw new Error("нет id или hash");
  return { id: m.id, hash: m.hash };
}

/** Мандат и подписанное эмулятором решение по его Mandate.hash. */
async function signed(c: Ctx, req: MandateRequest = intent(), over: Partial<ParticipantSignedRecord> = {}) {
  const m = await mk(c, req);
  const r = record(c, m.id, m.hash, over);
  return { m, r, sig: c.emu.signRecord(r) };
}

async function decisions(c: Ctx, id: string): Promise<string[]> {
  const row = (await c.store.getMandate(id))!;
  return (await c.store.journal(row.chain).all()).filter((e) => e.ref === id && e.kind !== "MANDATE_REQUESTED").map((e) => e.kind);
}

function suite(open: () => Promise<ConsentStore>) {
  let c: Ctx;
  beforeAll(async () => {
    c = setup(await open());
  });

  it("подпись эмулятора над Mandate.hash → 200 ACTIVE, одна запись MANDATE_SIGNED с записью участника", async () => {
    const { m, r, sig } = await signed(c);
    const res = await post(c, m.id, body(r, sig));
    expect(res).toEqual({ status: 200, body: { mandate_id: m.id, status: "ACTIVE" } });
    expect((await c.consent.get(m.id, A))?.status).toBe("ACTIVE");
    const row = (await c.store.getMandate(m.id))!;
    const e = (await c.store.journal(row.chain).all()).find((x) => x.kind === "MANDATE_SIGNED")!;
    expect(e.payload).toEqual({ ...r, signature: sig } satisfies MandateDecisionPayload);
    expect(e.parent_ref).toBe(m.id);
  });

  it("REJECT → REJECTED; затем SIGN — 409 MANDATE_NOT_PENDING, записи нет", async () => {
    const { m, r, sig } = await signed(c, intent(), { decision: "REJECT" });
    expect((await post(c, m.id, body(r, sig))).body).toEqual({ mandate_id: m.id, status: "REJECTED" });
    const s2 = record(c, m.id, m.hash, { signature_ref: "sig-other" });
    expect(await post(c, m.id, body(s2, c.emu.signRecord(s2)))).toEqual({ status: 409, body: { code: "MANDATE_NOT_PENDING" } });
    expect(await decisions(c, m.id)).toEqual(["MANDATE_REJECTED"]);
  });

  it("повтор той же подписи — 200 текущий статус, второй записи нет; другая подпись после записи — 409", async () => {
    const { m, r, sig } = await signed(c);
    await post(c, m.id, body(r, sig));
    expect(await post(c, m.id, body(r, sig))).toEqual({ status: 200, body: { mandate_id: m.id, status: "ACTIVE" } });
    const other = record(c, m.id, m.hash, { signed_at: "2026-10-18T10:00:01Z" });
    expect((await post(c, m.id, body(other, c.emu.signRecord(other)))).status).toBe(409);
    expect(await decisions(c, m.id)).toEqual(["MANDATE_SIGNED"]);
  });

  it("10 одновременных одинаковых подписей — одна запись, все 200 ACTIVE", async () => {
    const { m, r, sig } = await signed(c);
    const all = await Promise.all(Array.from({ length: 10 }, () => post(c, m.id, body(r, sig))));
    expect(all.every((x) => x.status === 200 && x.body.status === "ACTIVE")).toBe(true);
    expect(await decisions(c, m.id)).toEqual(["MANDATE_SIGNED"]);
  });

  it("SIGN и REJECT одновременно — одно 200, другое 409, ровно одна запись решения", async () => {
    const m = await mk(c, intent());
    const s = record(c, m.id, m.hash);
    const r = record(c, m.id, m.hash, { decision: "REJECT" });
    const res = await Promise.all([post(c, m.id, body(s, c.emu.signRecord(s))), post(c, m.id, body(r, c.emu.signRecord(r)))]);
    expect(res.map((x) => x.status).sort()).toEqual([200, 409]);
    expect((await decisions(c, m.id)).length).toBe(1);
    expect(["ACTIVE", "REJECTED"]).toContain((await c.consent.get(m.id, A))?.status);
  });

  it("повтор той же подписи после отзыва — 200 REVOKED, записи нет (РП36 доп. п. 4)", async () => {
    const { m, r, sig } = await signed(c);
    await post(c, m.id, body(r, sig));
    const row = (await c.store.getMandate(m.id))!;
    await new AsyncHashChainJournal(c.store.journal(row.chain), () => T0.toISOString()).append("MANDATE_REVOKED", m.id, {}, m.id);
    expect(await post(c, m.id, body(r, sig))).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
    expect(await decisions(c, m.id)).toEqual(["MANDATE_SIGNED", "MANDATE_REVOKED"]);
  });

  it("неразборный JSON — 400 REQUEST_INVALID телом ПИ-8", async () => {
    const res = await c.app.inject({
      method: "POST",
      url: "/participants/v1/mandates/mnd_00000000-0000-4000-8000-000000000000/sign",
      headers: { "content-type": "application/json" },
      payload: "{",
    });
    expect([res.statusCode, res.json()]).toEqual([400, { code: "REQUEST_INVALID" }]);
  });

  it("подпись после отзыва — 409, записи нет", async () => {
    const m = await mk(c, intent());
    const row = (await c.store.getMandate(m.id))!;
    await new AsyncHashChainJournal(c.store.journal(row.chain), () => T0.toISOString()).append("MANDATE_REVOKED", m.id, {}, m.id);
    const r = record(c, m.id, m.hash);
    expect(await post(c, m.id, body(r, c.emu.signRecord(r)))).toEqual({ status: 409, body: { code: "MANDATE_NOT_PENDING" } });
    expect(await decisions(c, m.id)).toEqual(["MANDATE_REVOKED"]);
  });

  it("CART под ACTIVE родителем подписывается; под отозванным родителем — 409 (РП35 п. 2), записи нет", async () => {
    const p = await signed(c);
    await post(c, p.m.id, body(p.r, p.sig));
    const okCart = await mk(c, cart(p.m.id));
    const rc = record(c, okCart.id, okCart.hash);
    expect((await post(c, okCart.id, body(rc, c.emu.signRecord(rc)))).body.status).toBe("ACTIVE");

    const cart2 = await mk(c, cart(p.m.id));
    const row = (await c.store.getMandate(p.m.id))!;
    await new AsyncHashChainJournal(c.store.journal(row.chain), () => T0.toISOString()).append("MANDATE_REVOKED", p.m.id, {}, p.m.id);
    const r2 = record(c, cart2.id, cart2.hash);
    expect(await post(c, cart2.id, body(r2, c.emu.signRecord(r2)))).toEqual({ status: 409, body: { code: "MANDATE_NOT_PENDING" } });
    expect(await decisions(c, cart2.id)).toEqual([]);
  });

  it("чужой mandate_hash (другого мандата или отдельно вычисленный) — 409 MANDATE_HASH_MISMATCH, записи нет", async () => {
    const a = await mk(c, intent());
    const b = await mk(c, intent());
    const r = record(c, a.id, b.hash);
    expect(await post(c, a.id, body(r, c.emu.signRecord(r)))).toEqual({ status: 409, body: { code: "MANDATE_HASH_MISMATCH" } });
    const row = (await c.store.getMandate(a.id))!;
    const r2 = record(c, a.id, row.terms_hash);
    expect((await post(c, a.id, body(r2, c.emu.signRecord(r2)))).body.code).toBe("MANDATE_HASH_MISMATCH");
    expect(await decisions(c, a.id)).toEqual([]);
  });

  it("подпись без метки контекста, с другой меткой, чужим ключом, другим полем — 401 SIGNATURE_INVALID", async () => {
    const { m, r } = await signed(c);
    const own = liveKey("bank-test");
    // Своим ключом: без метки и с другой меткой — подпись не та.
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pk = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
    const k: TrustedParticipantKey = {
      participant_code: "bank-test",
      kid: jwkThumbprint({ crv, kty, x }),
      alg: "ed25519",
      public_key: pk,
      revocation_order: "bank:bank-test:revocation:v1",
    };
    const t2 = new TrustedParticipants([k], { stand: false });
    const rec = { ...r, participant_code: "bank-test", kid: k.kid };
    const sigOf = (obj: unknown) => edSign(null, Buffer.from(canonicalJson(obj), "utf8"), privateKey).toString("base64url");
    const { context: _c2, ...plain } = JSON.parse(participantSigningInput(rec).toString("utf8")) as Record<string, unknown>;
    void _c2;
    expect(t2.verify("bank-test", k.kid, rec, sigOf({ ...plain, context: PARTICIPANT_SIGNATURE_CONTEXT }))).toBe(true);
    expect(t2.verify("bank-test", k.kid, rec, sigOf(plain))).toBe(false);
    expect(t2.verify("bank-test", k.kid, rec, sigOf({ ...plain, context: "pao:mandate-id:v1" }))).toBe(false);

    // По HTTP: чужой ключ под кодом эмулятора, изменённое поле после подписи, неизвестный kid.
    const sigEmu = c.emu.signRecord(r);
    expect((await post(c, m.id, body(r, own.sign(r)))).status).toBe(401);
    expect((await post(c, m.id, body({ ...r, token_consent: false }, sigEmu))).status).toBe(401);
    expect((await post(c, m.id, body({ ...r, kid: own.key.kid }, sigEmu))).status).toBe(401);
    // Испорченная подпись: другой знак в середине (не в хвосте — там лишние биты base64url).
    const flipped = sigEmu.slice(0, 10) + (sigEmu[10] === "A" ? "B" : "A") + sigEmu.slice(11);
    expect((await post(c, m.id, body(r, flipped))).status).toBe(401);
    expect(await decisions(c, m.id)).toEqual([]);
  });

  it("неизвестный мандат — 404 только после проверки подписи; без подписи — 401", async () => {
    const id = "mnd_00000000-0000-4000-8000-000000000000";
    const r = record(c, id, "0".repeat(64));
    expect(await post(c, id, body(r, c.emu.signRecord(r)))).toEqual({ status: 404, body: { code: "MANDATE_NOT_FOUND" } });
    expect((await post(c, id, body(r, "A".repeat(86)))).status).toBe(401);
  });

  it("тело не по схеме: нет подписи, лишнее поле, неверный перечень, id не по маске — 400 REQUEST_INVALID", async () => {
    const { m, r, sig } = await signed(c);
    const { signature: _s, ...noSig } = body(r, sig);
    void _s;
    expect((await post(c, m.id, noSig)).status).toBe(400);
    expect((await post(c, m.id, { ...body(r, sig), extra: 1 })).status).toBe(400);
    expect((await post(c, m.id, { ...body(r, sig), decision: "MAYBE" })).status).toBe(400);
    expect((await post(c, m.id, { ...body(r, sig), signed_at: "вчера" })).status).toBe(400);
    expect((await post(c, "mnd_x", body(r, sig))).status).toBe(400);
    expect(await decisions(c, m.id)).toEqual([]);
  });

  it("A7 п. 3.2: простая подпись выше порога суммы или срока, не в рублях — 422; усиленная — ACTIVE; отказ — без порога", async () => {
    for (const req of [
      intent({ amount_limit: POLICY.qualified_signature_above_kop + 1 }),
      intent({ valid_to: "2026-11-17T10:00:01Z" }),
      intent({ currency: "USD" }),
    ]) {
      const { m, r, sig } = await signed(c, req);
      expect(await post(c, m.id, body(r, sig))).toEqual({ status: 422, body: { code: "QUALIFIED_SIGNATURE_REQUIRED" } });
      expect(await decisions(c, m.id)).toEqual([]);
      const q = record(c, m.id, m.hash, { signature_type: "qualified" });
      expect((await post(c, m.id, body(q, c.emu.signRecord(q)))).body.status).toBe("ACTIVE");
    }
    const atLimit = await signed(c, intent({ amount_limit: POLICY.qualified_signature_above_kop, valid_to: "2026-11-17T10:00:00Z" }));
    expect((await post(c, atLimit.m.id, body(atLimit.r, atLimit.sig))).body.status).toBe("ACTIVE");
    const rej = await signed(c, intent({ amount_limit: POLICY.qualified_signature_above_kop + 1 }), { decision: "REJECT" });
    expect((await post(c, rej.m.id, body(rej.r, rej.sig))).body.status).toBe("REJECTED");
  });
}

describe("подпись принципала — память", () => {
  suite(async () => new MemoryConsentStore());
});

describe.skipIf(!DATABASE_URL)("подпись принципала — PostgreSQL", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("psign");
  });
  afterAll(async () => db?.close());
  suite(async () => new PgConsentStore(db.pool));
});

describe("порядок отзыва в мандате (РП37, № 22)", () => {
  it("задаёт Платформа из записи участника: в ответе, в записи журнала и в Mandate.hash; поле от агента игнорируется", async () => {
    const c = setup(new MemoryConsentStore());
    const consent = new ConsentJournal(new MemoryConsentStore(), {
      now: () => T0,
      revocationOrder: () => new TrustedParticipants([c.emu.trustedKey], { stand: true }).revocationOrder(),
    });
    const m: Mandate = await consent.request(A, key(), { ...intent(), revocation_order: "agent:own" } as MandateRequest);
    expect(m.revocation_order).toBe(STAND_REVOCATION_ORDER);
    expect(m.agent_code).toBe(A);
    // Хэш записи покрывает порядок отзыва: банк подписывает мандат вместе с ним.
    const other = await new ConsentJournal(new MemoryConsentStore(), { now: () => T0, revocationOrder: () => "bank:x:revocation:v1" }).request(
      A,
      createHash("sha256").update("k").digest("hex"),
      intent(),
    );
    const same = await new ConsentJournal(new MemoryConsentStore(), { now: () => T0, revocationOrder: () => STAND_REVOCATION_ORDER }).request(
      A,
      createHash("sha256").update("k").digest("hex"),
      intent(),
    );
    expect(other.id).toBe(same.id);
    expect(other.hash).not.toBe(same.hash);
  });

  it("порядок отзыва не задан — мандат не пишется (ConsentStateUnknown → 503), индекса нет", async () => {
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { now: () => T0, revocationOrder: () => undefined });
    const k = key();
    await expect(j.request(A, k, intent())).rejects.toThrow(/порядок отзыва/);
    expect(await store.getMandate(mandateIdFor(A, k))).toBeUndefined();
  });

  it("повтор записанного мандата после смены порядка у участника — тот же мандат с записанным порядком (ПАО §2)", async () => {
    let ro = "bank:a:revocation:v1";
    const j = new ConsentJournal(new MemoryConsentStore(), { now: () => T0, revocationOrder: () => ro });
    const k = key();
    const first = await j.request(A, k, intent());
    ro = "bank:a:revocation:v2";
    const again: Mandate = await j.request(A, k, intent());
    expect(again.id).toBe(first.id);
    expect(again.hash).toBe(first.hash);
    expect(again.revocation_order).toBe("bank:a:revocation:v1");
  });

  it("CART наследует порядок отзыва родителя, даже если у участника он сменился (РП37 п. 6)", async () => {
    let ro = "bank:a:revocation:v1";
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { now: () => T0, revocationOrder: () => ro });
    const p = await j.request(A, key(), intent());
    await signDirect(store, p.id!, T0);
    ro = "bank:a:revocation:v2";
    const c: Mandate = await j.request(A, key(), cart(p.id!));
    expect(c.revocation_order).toBe("bank:a:revocation:v1");
  });

  it("запись мандата без порядка отзыва (до РП37) не читается как действующая — ConsentStateUnknown (A7 п. 2.2)", async () => {
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { now: () => T0, revocationOrder: () => STAND_REVOCATION_ORDER });
    const m = await j.request(A, key(), intent());
    const row = (await store.getMandate(m.id!))!;
    // Та же цепочка, но запись с payload без revocation_order — как записанная до РП37.
    const legacyStore = new MemoryConsentStore();
    await legacyStore.insertMandate(row);
    const subj = (await store.getSubject(m.id!))!;
    await legacyStore.insertSubject(subj);
    const head = (await store.journal(row.chain).all())[0]!;
    const { revocation_order: _ro, ...legacy } = head.payload as Record<string, unknown>;
    void _ro;
    await new AsyncHashChainJournal(legacyStore.journal(row.chain), () => head.at).append("MANDATE_REQUESTED", m.id!, legacy, null);
    const lj = new ConsentJournal(legacyStore, { now: () => T0, revocationOrder: () => STAND_REVOCATION_ORDER });
    await expect(lj.get(m.id!, A)).rejects.toThrow(/порядка отзыва/);
  });

  it("TrustedParticipants: боевой участник важнее эмулятора; пусто — undefined; разные порядки у одного участника и неверная форма — ошибка запуска", () => {
    const a = liveKey("bank-a");
    expect(new TrustedParticipants([], { stand: false }).revocationOrder()).toBeUndefined();
    expect(new TrustedParticipants([createIssuerEmulator().trustedKey], { stand: true }).revocationOrder()).toBe(STAND_REVOCATION_ORDER);
    expect(new TrustedParticipants([createIssuerEmulator().trustedKey, a.key], { stand: true }).revocationOrder()).toBe("bank:bank-a:revocation:v1");
    const a2 = liveKey("bank-a");
    expect(() => new TrustedParticipants([a.key, { ...a2.key, revocation_order: "bank:bank-a:revocation:v2" }], { stand: false })).toThrow(/разные revocation_order/);
    expect(() => new TrustedParticipants([{ ...a.key, revocation_order: "" }], { stand: false })).toThrow(/revocation_order/);
  });
});

describe("доверенные участники до PS-20 (РП36 п. 4, доп.)", () => {
  const dir = mkdtempSync(join(tmpdir(), "participants-"));
  const file = (name: string, doc: unknown): string => {
    const p = join(dir, name);
    writeFileSync(p, JSON.stringify(doc));
    return p;
  };

  it("пути нет — пустой список: любая подпись отклоняется", async () => {
    const c = setup(new MemoryConsentStore());
    const app = buildServer({
      env: "dev",
      participants: { trusted: loadTrustedParticipants(undefined, { stand: false }), consent: c.consent, params: POLICY },
    });
    const m = await mk(c, intent());
    const r = record(c, m.id, m.hash);
    const res = await app.inject({ method: "POST", url: `/participants/v1/mandates/${m.id}/sign`, payload: body(r, c.emu.signRecord(r)) });
    expect(res.statusCode).toBe(401);
  });

  it("один боевой участник из файла — принимается; второй — ошибка запуска с понятным сообщением", () => {
    const a = liveKey("bank-a");
    const b = liveKey("bank-b");
    expect(() => loadTrustedParticipants(file("one.json", { participants: [a.key] }), { stand: false })).not.toThrow();
    expect(() => loadTrustedParticipants(file("two.json", { participants: [a.key, b.key] }), { stand: false })).toThrow(
      /не больше 1.*РП36 доп/,
    );
    // Два ключа одного банка — один участник.
    const a2 = liveKey("bank-a");
    expect(() => new TrustedParticipants([a.key, a2.key], { stand: false })).not.toThrow();
    // Эмулятор стенда не считается.
    expect(() => new TrustedParticipants([a.key, createIssuerEmulator().trustedKey], { stand: true })).not.toThrow();
  });

  it("ключ эмулятора эмитента вне стенда — ошибка запуска", () => {
    const emu = createIssuerEmulator().trustedKey;
    expect(emu.participant_code).toBe(STAND_ISSUER_CODE);
    expect(() => loadTrustedParticipants(file("emu.json", { participants: [emu] }), { stand: false })).toThrow(/только на стенде/);
  });

  it("неверный файл, лишнее поле, kid не отпечаток, слабый или не ed25519 ключ, повтор — ошибка запуска", () => {
    const a = liveKey("bank-a");
    expect(() => loadTrustedParticipants(join(dir, "нет.json"), { stand: false })).toThrow(/не читается/);
    writeFileSync(join(dir, "bad.json"), "{");
    expect(() => loadTrustedParticipants(join(dir, "bad.json"), { stand: false })).toThrow(/не JSON/);
    expect(() => loadTrustedParticipants(file("extra.json", { participants: [{ ...a.key, private_key: "x" }] }), { stand: false })).toThrow();
    expect(() => loadTrustedParticipants(file("top.json", { participants: [a.key], more: 1 }), { stand: false })).toThrow();
    const { revocation_order: _r, ...noOrder } = a.key;
    void _r;
    expect(() => loadTrustedParticipants(file("noorder.json", { participants: [noOrder] }), { stand: false })).toThrow(/revocation_order/);
    expect(() => new TrustedParticipants([{ ...a.key, kid: "x" }], { stand: false })).toThrow(/kid/);
    // Нейтраль Ed25519 (точка малого порядка) в DER SPKI.
    const weak = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from("01" + "00".repeat(31), "hex")]).toString("base64");
    expect(() => new TrustedParticipants([{ ...a.key, public_key: weak }], { stand: false })).toThrow(/не принят/);
    expect(() => new TrustedParticipants([a.key, a.key], { stand: false })).toThrow(/дважды/);
    expect(() => new TrustedParticipants([{ ...a.key, participant_code: "банк" }], { stand: false })).toThrow(/participant_code/);
  });
});

describe("стенд: эмулятор эмитента подписывает тем же POST (РП36 п. 4)", () => {
  it("агент запрашивает мандат по ПАО → issuer.sign → GET ACTIVE; повтор с новой меткой времени — 409; неизвестный — 404", async () => {
    const stand = createStand();
    const code = "nspk:agent:sign-stand:v1";
    const side = newAgentSide();
    expect((await stand.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
    const valid_to = new Date(Date.now() + 7 * 86_400_000).toISOString();
    const created = await signedInject(stand.app, side, code, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(intent({ valid_to })),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(created.statusCode).toBe(201);
    const id = (created.json() as { id: string }).id;
    expect(await stand.issuer.sign(id)).toEqual({ statusCode: 200, body: { mandate_id: id, status: "ACTIVE" } });
    const got = await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${id}` });
    expect((got.json() as { status: string }).status).toBe("ACTIVE");
    stand.setClock(new Date(Date.now() + 1000));
    expect((await stand.issuer.sign(id)).statusCode).toBe(409);
    expect(await stand.issuer.sign("mnd_00000000-0000-4000-8000-000000000000")).toEqual({
      statusCode: 404,
      body: { code: "MANDATE_NOT_FOUND" },
    });
    await stand.close();
  });
});
