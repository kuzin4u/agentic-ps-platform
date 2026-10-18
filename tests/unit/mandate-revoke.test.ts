// П2 / П10 Отзыв мандата (PS-06 К2.6; РП38, A7 п. 6): клиентом — ПИ-8 POST /participants/v1/mandates/{id}/revoke
// с подписью участника (своя метка), агентом — ПАО POST /pao/v1/mandates/{id}/relinquish. Запись — только при
// PENDING_SIGNATURE или ACTIVE; отзыв родителя отзывает CART свёрткой (РП35); лок записи по мандату (РП36 доп. п. 4).
// Журнал и шлюз участников — на памяти ядра (всегда) и на PostgreSQL (в CI, РП30 п. 7); ПАО — через стенд.
import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import type { MandateRevocationPayload } from "../../src/consent/model.js";
import { MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator, type IssuerEmulator } from "../../src/env/issuer/index.js";
import { TrustedParticipants, type ParticipantRevocationRecord, type ParticipantSignedRecord } from "../../src/participants/trusted.js";
import { buildServer } from "../../src/server.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { signedInject } from "../support/signed-inject.js";

const A = "nspk:agent:revoke-a:v1";
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

const revocation = (c: Ctx, id: string, hash: string, over: Partial<ParticipantRevocationRecord> = {}): ParticipantRevocationRecord => ({
  participant_code: c.emu.participant_code,
  kid: c.emu.trustedKey.kid,
  mandate_id: id,
  mandate_hash: hash,
  revocation_ref: `rev-${id.slice(-6)}`,
  revoked_at: T0.toISOString(),
  ...over,
});

const decision = (c: Ctx, id: string, hash: string): ParticipantSignedRecord => ({
  participant_code: c.emu.participant_code,
  kid: c.emu.trustedKey.kid,
  mandate_id: id,
  mandate_hash: hash,
  decision: "SIGN",
  signature_type: "simple",
  signature_ref: `sig-${id.slice(-6)}`,
  token_consent: true,
  signed_at: T0.toISOString(),
});

/** Тело запроса: запись без mandate_id (он в пути) и подпись. */
function body<R extends { mandate_id: string }>(r: R, signature: string): Record<string, unknown> {
  const { mandate_id: _id, ...rest } = r;
  void _id;
  return { ...rest, signature };
}

async function call(c: Ctx, op: "sign" | "revoke", id: string, payload: unknown) {
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/mandates/${id}/${op}`, payload: payload as object });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
}

const revoke = (c: Ctx, id: string, hash: string) => {
  const r = revocation(c, id, hash);
  return call(c, "revoke", id, body(r, c.emu.signRevocation(r)));
};
const sign = (c: Ctx, id: string, hash: string) => {
  const r = decision(c, id, hash);
  return call(c, "sign", id, body(r, c.emu.signRecord(r)));
};

async function mk(c: Ctx, req: MandateRequest): Promise<{ id: string; hash: string }> {
  const m = await c.consent.request(A, key(), req);
  if (!m.id || !m.hash) throw new Error("нет id или hash");
  return { id: m.id, hash: m.hash };
}

/** Записи по мандату после MANDATE_REQUESTED, в порядке цепочки. */
async function kinds(c: Ctx, id: string): Promise<string[]> {
  const row = (await c.store.getMandate(id))!;
  return (await c.store.journal(row.chain).all()).filter((e) => e.ref === id && e.kind !== "MANDATE_REQUESTED").map((e) => e.kind);
}

function suite(open: () => Promise<ConsentStore>): void {
  let c: Ctx;
  beforeAll(async () => {
    c = setup(await open());
  });
  afterAll(async () => c.app.close());

  it("ACTIVE → отзыв клиентом: 200 REVOKED; в записи — запись участника и подпись; повтор — 200 без записи", async () => {
    const m = await mk(c, intent());
    expect((await sign(c, m.id, m.hash)).body.status).toBe("ACTIVE");
    const r = revocation(c, m.id, m.hash);
    const sig = c.emu.signRevocation(r);
    expect(await call(c, "revoke", m.id, body(r, sig))).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
    expect((await c.consent.get(m.id, A))?.status).toBe("REVOKED");
    const row = (await c.store.getMandate(m.id))!;
    const rec = (await c.store.journal(row.chain).all()).find((e) => e.kind === "MANDATE_REVOKED")!;
    expect(rec.payload as MandateRevocationPayload).toEqual({ ...r, signature: sig });
    expect(await call(c, "revoke", m.id, body(r, sig))).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
    expect(await revoke(c, m.id, m.hash)).toEqual({ status: 200, body: { mandate_id: m.id, status: "REVOKED" } });
    expect(await kinds(c, m.id)).toEqual(["MANDATE_SIGNED", "MANDATE_REVOKED"]);
  });

  it("PENDING_SIGNATURE → отзыв: REVOKED; подпись после отзыва — 409 MANDATE_NOT_PENDING", async () => {
    const m = await mk(c, intent());
    expect((await revoke(c, m.id, m.hash)).body.status).toBe("REVOKED");
    expect(await sign(c, m.id, m.hash)).toEqual({ status: 409, body: { code: "MANDATE_NOT_PENDING" } });
    expect(await kinds(c, m.id)).toEqual(["MANDATE_REVOKED"]);
  });

  it("REJECTED → отзыв: 200 REJECTED без записи", async () => {
    const m = await mk(c, intent());
    const d = { ...decision(c, m.id, m.hash), decision: "REJECT" as const };
    expect((await call(c, "sign", m.id, body(d, c.emu.signRecord(d)))).body.status).toBe("REJECTED");
    expect(await revoke(c, m.id, m.hash)).toEqual({ status: 200, body: { mandate_id: m.id, status: "REJECTED" } });
    expect(await kinds(c, m.id)).toEqual(["MANDATE_REJECTED"]);
  });

  it("отзыв родителя — CART REVOKED (РП35); подпись CART после — 409", async () => {
    const p = await mk(c, intent());
    await sign(c, p.id, p.hash);
    const k = await mk(c, cart(p.id));
    expect((await revoke(c, p.id, p.hash)).body.status).toBe("REVOKED");
    expect((await c.consent.get(k.id, A))?.status).toBe("REVOKED");
    expect(await sign(c, k.id, k.hash)).toEqual({ status: 409, body: { code: "MANDATE_NOT_PENDING" } });
    expect(await revoke(c, k.id, k.hash)).toEqual({ status: 200, body: { mandate_id: k.id, status: "REVOKED" } });
    expect(await kinds(c, k.id)).toEqual([]);
  });

  it("без подписи участника отзыва нет: подпись решения как отзыв, чужая подпись, подмена поля — 401; записи нет", async () => {
    const m = await mk(c, intent());
    const r = revocation(c, m.id, m.hash);
    // Подпись решения над тем же мандатом — другая метка (РП38 п. 1).
    const asDecision = c.emu.signRecord(decision(c, m.id, m.hash));
    expect(await call(c, "revoke", m.id, body(r, asDecision))).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
    const other = createIssuerEmulator();
    expect(await call(c, "revoke", m.id, body(r, other.signRevocation(r)))).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
    const sig = c.emu.signRevocation(r);
    const changed = { ...body(r, sig), revocation_ref: "rev-other" };
    expect(await call(c, "revoke", m.id, changed)).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
    // Подпись отзыва другого мандата — mandate_id из пути входит в подписанную запись.
    const n = await mk(c, intent());
    expect(await call(c, "revoke", n.id, body(r, sig))).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
    expect(await kinds(c, m.id)).toEqual([]);
    expect((await c.consent.get(m.id, A))?.status).toBe("PENDING_SIGNATURE");
  });

  it("ссылки банка — только непрозрачные: СНИЛС, ЕСИА, телефон, адрес в revocation_ref или signature_ref — 400, записи нет (`/audit` К2.6 № 2)", async () => {
    const m = await mk(c, intent());
    for (const ref of ["123-456-789 01", "esia1234567", "+79161234567", "client@bank.ru", "Иванов"]) {
      const r = revocation(c, m.id, m.hash, { revocation_ref: ref });
      expect(await call(c, "revoke", m.id, body(r, c.emu.signRevocation(r)))).toEqual({ status: 400, body: { code: "REQUEST_INVALID" } });
      const d = { ...decision(c, m.id, m.hash), signature_ref: ref };
      expect(await call(c, "sign", m.id, body(d, c.emu.signRecord(d)))).toEqual({ status: 400, body: { code: "REQUEST_INVALID" } });
    }
    expect(await kinds(c, m.id)).toEqual([]);
  });

  it("хэш не тот — 409 MANDATE_HASH_MISMATCH; неизвестный — 404; лишнее поле или id не по маске — 400", async () => {
    const m = await mk(c, intent());
    const bad = revocation(c, m.id, "0".repeat(64));
    expect(await call(c, "revoke", m.id, body(bad, c.emu.signRevocation(bad)))).toEqual({ status: 409, body: { code: "MANDATE_HASH_MISMATCH" } });
    const unknown = "mnd_00000000-0000-4000-8000-000000000000";
    const u = revocation(c, unknown, m.hash);
    expect(await call(c, "revoke", unknown, body(u, c.emu.signRevocation(u)))).toEqual({ status: 404, body: { code: "MANDATE_NOT_FOUND" } });
    const r = revocation(c, m.id, m.hash);
    expect(await call(c, "revoke", m.id, { ...body(r, c.emu.signRevocation(r)), status: "REVOKED" })).toEqual({
      status: 400,
      body: { code: "REQUEST_INVALID" },
    });
    expect((await call(c, "revoke", "mnd_x", body(r, c.emu.signRevocation(r)))).status).toBe(400);
    expect(await kinds(c, m.id)).toEqual([]);
  });

  // Гонка — прямыми вызовами журнала: запросы через inject идут по очереди и шаги записи не чередуют.
  const signDirect = (id: string, hash: string) =>
    c.consent.sign({ ...decision(c, id, hash), signature: "s" }, () => true, POLICY).then(
      () => "записано",
      (err: Error) => err.message.split(":")[1]?.trim(),
    );

  it("отзыв и подпись одновременно (отзыв первым): после отзыва записи решения нет, подпись — MANDATE_NOT_PENDING (лок записи, РП38 п. 4)", async () => {
    const m = await mk(c, intent());
    const [rev, sig] = await Promise.all([
      c.consent.revoke({ ...revocation(c, m.id, m.hash), signature: "s" }, () => true),
      signDirect(m.id, m.hash),
    ]);
    expect(rev.status).toBe("REVOKED");
    expect(sig).toBe("MANDATE_NOT_PENDING");
    expect(await kinds(c, m.id)).toEqual(["MANDATE_REVOKED"]);
    expect((await c.consent.get(m.id, A))?.status).toBe("REVOKED");
  });

  it("отказ агента и подпись одновременно (отказ первым): записи решения нет, подпись — MANDATE_NOT_PENDING", async () => {
    const m = await mk(c, intent());
    const [left, sig] = await Promise.all([c.consent.relinquish(m.id, A, "kid-a"), signDirect(m.id, m.hash)]);
    expect(left?.status).toBe("REVOKED");
    expect(sig).toBe("MANDATE_NOT_PENDING");
    expect(await kinds(c, m.id)).toEqual(["MANDATE_RELINQUISHED"]);
  });

  it("10 одновременных отзывов в журнале — одна запись", async () => {
    const m = await mk(c, intent());
    const all = await Promise.all(
      Array.from({ length: 10 }, (_, i) => c.consent.revoke({ ...revocation(c, m.id, m.hash, { revocation_ref: `r${i}` }), signature: "s" }, () => true)),
    );
    expect(all.filter((x) => !x.replayed)).toHaveLength(1);
    expect(await kinds(c, m.id)).toEqual(["MANDATE_REVOKED"]);
  });

  it("10 одновременных отзывов — одна запись, все 200 REVOKED", async () => {
    const m = await mk(c, intent());
    await sign(c, m.id, m.hash);
    const all = await Promise.all(Array.from({ length: 10 }, () => revoke(c, m.id, m.hash)));
    expect(all.every((x) => x.status === 200 && x.body.status === "REVOKED")).toBe(true);
    expect(await kinds(c, m.id)).toEqual(["MANDATE_SIGNED", "MANDATE_REVOKED"]);
  });

  it("10 одновременных relinquish в журнале — одна запись (лок записи, `/audit` К2.6 № 6)", async () => {
    const m = await mk(c, intent());
    const all = await Promise.all(Array.from({ length: 10 }, () => c.consent.relinquish(m.id, A, "kid-a")));
    expect(all.every((x) => x?.status === "REVOKED")).toBe(true);
    expect(await kinds(c, m.id)).toEqual(["MANDATE_RELINQUISHED"]);
  });

  it("relinquish: свой — запись {agent_code, kid}; чужой и неизвестный — undefined, записи нет", async () => {
    const m = await mk(c, intent());
    expect(await c.consent.relinquish(m.id, "nspk:agent:other:v1", "kid-b")).toBeUndefined();
    expect(await c.consent.relinquish("mnd_00000000-0000-4000-8000-000000000000", A, "kid-a")).toBeUndefined();
    expect(await kinds(c, m.id)).toEqual([]);
    expect((await c.consent.relinquish(m.id, A, "kid-a"))?.status).toBe("REVOKED");
    const row = (await c.store.getMandate(m.id))!;
    const rec = (await c.store.journal(row.chain).all()).find((e) => e.kind === "MANDATE_RELINQUISHED")!;
    expect(rec.payload).toEqual({ agent_code: A, kid: "kid-a" });
  });
}

describe("отзыв мандата — память", () => {
  suite(async () => new MemoryConsentStore());
});

describe.skipIf(!DATABASE_URL)("отзыв мандата — PostgreSQL", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("prevoke");
  });
  afterAll(async () => db?.close());
  suite(async () => new PgConsentStore(db.pool));
});

describe("ПАО relinquish и отзыв клиентом на стенде (РП38 п. 3)", () => {
  const code = "nspk:agent:relinquish:v1";
  const otherCode = "nspk:agent:relinquish-b:v1";
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  const valid_to = new Date(Date.now() + 7 * 86_400_000).toISOString();

  beforeAll(() => {
    stand = createStand();
    side = newAgentSide();
    other = newAgentSide();
    expect(stand.admit(buyerApplication(code, side), "op").admitted).toBe(true);
    expect(stand.admit(buyerApplication(otherCode, other), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const create = async (req: MandateRequest): Promise<string> => {
    const res = await signedInject(stand.app, side, code, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(req),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(res.statusCode).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const relinquish = (id: string, as: AgentSide = side, asCode = code, key: string | null = randomUUID(), payload = "") =>
    signedInject(stand.app, as, asCode, {
      method: "POST",
      path: `/pao/v1/mandates/${id}/relinquish`,
      body: payload,
      headers: key === null ? {} : { "idempotency-key": key },
    });
  const status = async (id: string) =>
    ((await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${id}` })).json() as { status: string }).status;

  it("relinquish родителя: 200 Mandate REVOKED, CART — REVOKED при GET; повтор тем же ключом — тот же ответ, новым — 200 без записи", async () => {
    const p = await create(intent({ valid_to }));
    expect((await stand.issuer.sign(p)).statusCode).toBe(200);
    const k = await create(cart(p));
    const idem = randomUUID();
    const res = await relinquish(p, side, code, idem);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ id: p, status: "REVOKED", agent_code: code });
    expect(await status(k)).toBe("REVOKED");
    expect((await relinquish(p, side, code, idem)).json()).toEqual(res.json());
    expect((await relinquish(p)).json()).toMatchObject({ status: "REVOKED" });
    // Запись отказа — агент и ключ проверенного обращения (инвариант 5, `/audit` К2.6 № 4); повтор записи не дал.
    const ev = (await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${p}/evidence` })).json() as {
      records: { kind: string; ref: string; payload: unknown }[];
    };
    expect(ev.records.filter((r) => r.kind === "MANDATE_RELINQUISHED").map((r) => [r.ref, r.payload])).toEqual([
      [p, { agent_code: code, kid: side.kid }],
    ]);
  });

  it("чужой, неизвестный, не по форме id — 404 MANDATE_NOT_FOUND; тело не пустое — 400; без ключа — 400", async () => {
    const p = await create(intent({ valid_to }));
    expect((await relinquish(p, other, otherCode)).json()).toMatchObject({ code: "MANDATE_NOT_FOUND" });
    expect((await relinquish("mnd_00000000-0000-4000-8000-000000000000")).statusCode).toBe(404);
    expect((await relinquish("mnd_x")).statusCode).toBe(404);
    expect((await relinquish(p, side, code, randomUUID(), "{}")).json()).toMatchObject({ code: "REQUEST_INVALID" });
    expect((await relinquish(p, side, code, null)).json()).toMatchObject({ code: "IDEMPOTENCY_REQUIRED" });
    expect(await status(p)).toBe("PENDING_SIGNATURE");
  });

  it("стенд: issuer.revoke — отзыв клиентом той же точкой ПИ-8; GET REVOKED; неизвестный — 404", async () => {
    const p = await create(intent({ valid_to }));
    await stand.issuer.sign(p);
    expect(await stand.issuer.revoke(p)).toEqual({ statusCode: 200, body: { mandate_id: p, status: "REVOKED" } });
    expect(await status(p)).toBe("REVOKED");
    expect((await stand.issuer.revoke("mnd_00000000-0000-4000-8000-000000000000")).statusCode).toBe(404);
  });
});
