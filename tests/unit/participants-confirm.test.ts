// ПИ-8 POST /participants/v1/confirmations/{id} (PS-19 ч. 1, РП50 п. 4–6, Дополнения п. 3; инвариант 7): решение человека
// по запросу подтверждения — запись банка клиента корневого INTENT с подписью Ed25519 над totals_hash итоговых значений;
// при APPROVE — однократная ссылка. Порядок проверок: тело → подпись → запрос → банк клиента → decided_at → повтор →
// totals_hash → срок и статус. Банков два: эмулятор (банк клиента) и «боевой» банк теста с верной подписью.
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ConsentJournal } from "../../src/consent/journal.js";
import {
  CONFIRMATION_REF,
  MemoryConfirmationStore,
  newConfirmationId,
  participantConfirmationSigningInput,
  totalsHash,
  type ConfirmationDecision,
  type ConfirmationRecord,
  type ConfirmationStore,
} from "../../src/confirm/index.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { participantRoutes } from "../../src/participants/routes.js";
import { TrustedParticipants, type TrustedParticipantKey } from "../../src/participants/trusted.js";
import { jwkThumbprint } from "../../src/registry/keys.js";

const AGENT = "nspk:agent:buyref-01:v3";
const M = "mnd_00000000-0000-4000-8000-000000000001";
const T0 = Date.parse("2026-10-22T10:00:00.000Z");
const HOLD_MS = 900_000;
const SKEW_SEC = 300;
const emu = createIssuerEmulator();

/** «Боевой» банк теста: подпись верна, но клиент мандата — не его. */
function liveBank(code: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  const key: TrustedParticipantKey = { participant_code: code, kid: jwkThumbprint({ crv, kty, x }), alg: "ed25519", public_key, revocation_order: `bank:${code}:revocation:v1` };
  return { key, sign: (r: Parameters<typeof participantConfirmationSigningInput>[0]) => edSign(null, participantConfirmationSigningInput(r), privateKey).toString("base64url") };
}
const live = liveBank("bank:live");

interface Ctx {
  app: FastifyInstance;
  store: MemoryConfirmationStore;
  logs: string[];
  setNow(ms: number): void;
  /** Мандат: банк клиента; undefined — мандата нет; "fail" — журнал не читается. */
  mandate: { client: string | undefined | "fail" };
}

let ctx: Ctx;

async function setup(over: Partial<ConfirmationStore> = {}): Promise<Ctx> {
  let t = T0;
  const store = new MemoryConfirmationStore();
  const mandate: Ctx["mandate"] = { client: emu.participant_code };
  const consent = {
    async adpMandate(id: string, agent_code: string) {
      if (mandate.client === "fail") throw new Error("журнал недоступен");
      if (id !== M || agent_code !== AGENT || mandate.client === undefined) return undefined;
      return { client: { participant_code: mandate.client, principal_ref: "prn_7f3c9a" } };
    },
  } as unknown as ConsentJournal;
  const logs: string[] = [];
  const app = Fastify({
    logger: { level: "info", stream: { write: (l: string) => void logs.push(l) } },
  });
  const wrapped = new Proxy(store, {
    get(target, p, r) {
      const v = (over as Record<string | symbol, unknown>)[p] ?? Reflect.get(target, p, r);
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
  await participantRoutes(app, {
    trusted: new TrustedParticipants([emu.trustedKey, live.key], { stand: true }),
    consent,
    params: { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 },
    now: () => new Date(t),
    confirmations: { store: wrapped, skewSec: SKEW_SEC },
  });
  await app.ready();
  return { app, store, logs, setNow: (ms) => (t = ms), mandate };
}

beforeEach(async () => {
  ctx = await setup();
});
afterEach(async () => {
  await ctx.app.close();
});

async function request(over: Partial<ConfirmationRecord> = {}): Promise<ConfirmationRecord> {
  return ctx.store.create({
    confirmation_id: newConfirmationId(),
    agent_code: AGENT,
    mandate_id: M,
    merchant_id: "MER-1042",
    amount: 340_000,
    currency: "RUB",
    order_ref: "ORD-77a1",
    split_detected: false,
    status: "PENDING",
    created_at: new Date(T0).toISOString(),
    expires_at: new Date(T0 + HOLD_MS).toISOString(),
    confirmation_ref: null,
    decision: null,
    op_ref: null,
    ...over,
  });
}

/** Тело решения банка эмулятора (или боевого) с верной подписью над записью. */
function body(r: ConfirmationRecord, over: Partial<Omit<ConfirmationDecision, "signature">> = {}, bank: "emu" | "live" = "emu") {
  const record = {
    participant_code: bank === "emu" ? emu.participant_code : live.key.participant_code,
    kid: bank === "emu" ? emu.trustedKey.kid : live.key.kid,
    confirmation_id: r.confirmation_id,
    decision: "APPROVE" as const,
    totals_hash: totalsHash(r),
    decided_at: new Date(T0 + 60_000).toISOString(),
    ...over,
  };
  const signature = bank === "emu" ? emu.signConfirmation(record) : live.sign(record);
  const { confirmation_id: _id, ...rest } = { ...record, signature };
  void _id;
  return rest;
}

const post = async (id: string, payload: unknown) => {
  const res = await ctx.app.inject({ method: "POST", url: `/participants/v1/confirmations/${id}`, payload: payload as object });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
};

describe("ПИ-8: решение человека по запросу подтверждения (РП50 п. 4–6)", () => {
  it("APPROVE банка клиента → 200 APPROVED и однократная ссылка cr_…; запись решения — доказательство", async () => {
    ctx.setNow(T0 + 60_000);
    const r = await request();
    const res = await post(r.confirmation_id, body(r));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ confirmation_id: r.confirmation_id, status: "APPROVED" });
    expect(res.body.confirmation_ref).toMatch(CONFIRMATION_REF);
    expect(res.body.confirmation_ref).not.toBe(r.confirmation_id);
    const stored = await ctx.store.get(r.confirmation_id);
    expect(stored).toMatchObject({ status: "APPROVED", confirmation_ref: res.body.confirmation_ref, decision: { participant_code: emu.participant_code, decision: "APPROVE" } });
  });

  it("REJECT → 200 REJECTED без ссылки", async () => {
    const r = await request();
    const res = await post(r.confirmation_id, body(r, { decision: "REJECT" }));
    expect(res).toEqual({ status: 200, body: { confirmation_id: r.confirmation_id, status: "REJECTED" } });
  });

  it("повтор той же записи — 200 с текущим статусом и той же ссылкой, второй записи нет; другое решение — 409", async () => {
    const r = await request();
    const b = body(r);
    const first = await post(r.confirmation_id, b);
    expect(await post(r.confirmation_id, b)).toEqual(first);
    const other = await post(r.confirmation_id, body(r, { decision: "REJECT" }));
    expect(other).toEqual({ status: 409, body: { code: "CONFIRMATION_NOT_PENDING", status: "APPROVED" } });
  });

  it("после погашения: повтор — 200 USED без ссылки; новое решение — 409 со статусом USED", async () => {
    const r = await request();
    const b = body(r);
    const ref = (await post(r.confirmation_id, b)).body.confirmation_ref as string;
    expect(await ctx.store.consume(ref, "OPKC-1", new Date(T0 + 1).toISOString())).toBe(true);
    expect(await post(r.confirmation_id, b)).toEqual({ status: 200, body: { confirmation_id: r.confirmation_id, status: "USED" } });
    expect((await post(r.confirmation_id, body(r, { decided_at: new Date(T0 + 1_000).toISOString() }))).body).toEqual({ code: "CONFIRMATION_NOT_PENDING", status: "USED" });
  });

  it("totals_hash не того итога — 409 CONFIRMATION_TOTALS_MISMATCH, решение не записано", async () => {
    const r = await request();
    const wrong = totalsHash({ ...r, amount: 339_000 });
    expect((await post(r.confirmation_id, body(r, { totals_hash: wrong }))).body).toEqual({ code: "CONFIRMATION_TOTALS_MISMATCH" });
    expect((await ctx.store.get(r.confirmation_id))?.status).toBe("PENDING");
  });

  it("подпись не над этой записью, чужой confirmation_id в подписи, неизвестный ключ — 401 SIGNATURE_INVALID", async () => {
    const r = await request();
    const other = await request({ order_ref: "ORD-other" });
    const tampered = { ...body(r), decided_at: new Date(T0 + 61_000).toISOString() };
    expect((await post(r.confirmation_id, tampered)).status).toBe(401);
    expect((await post(r.confirmation_id, body(other))).status, "подпись другого запроса").toBe(401);
    expect((await post(r.confirmation_id, { ...body(r), kid: "unknown-kid" })).status).toBe(401);
    expect((await ctx.store.get(r.confirmation_id))?.status).toBe("PENDING");
  });

  it("верная подпись не банка клиента корневого INTENT — 401 SIGNATURE_INVALID", async () => {
    const r = await request();
    const res = await post(r.confirmation_id, body(r, {}, "live"));
    expect(res).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
    expect((await ctx.store.get(r.confirmation_id))?.status).toBe("PENDING");
  });

  it("decided_at позже часов Платформы больше допуска — 401; в пределах допуска — принято", async () => {
    const r = await request();
    const far = new Date(T0 + SKEW_SEC * 1000 + 1).toISOString();
    expect((await post(r.confirmation_id, body(r, { decided_at: far }))).status).toBe(401);
    const near = new Date(T0 + SKEW_SEC * 1000).toISOString();
    expect((await post(r.confirmation_id, body(r, { decided_at: near }))).status).toBe(200);
  });

  it("срок: запись в момент expires_at и позже — 409 EXPIRED и запрос истёк; decided_at позже expires_at — 409 EXPIRED", async () => {
    const r = await request();
    ctx.setNow(Date.parse(r.expires_at));
    expect(await post(r.confirmation_id, body(r, { decided_at: r.expires_at }))).toEqual({ status: 409, body: { code: "CONFIRMATION_NOT_PENDING", status: "EXPIRED" } });
    expect((await ctx.store.get(r.confirmation_id))?.status).toBe("EXPIRED");

    const r2 = await request({ order_ref: "ORD-2", expires_at: new Date(T0 + 60_000).toISOString() });
    ctx.setNow(T0 + 59_000);
    const after = new Date(T0 + 61_000).toISOString();
    expect((await post(r2.confirmation_id, body(r2, { decided_at: after }))).body).toEqual({ code: "CONFIRMATION_NOT_PENDING", status: "EXPIRED" });
    expect((await ctx.store.get(r2.confirmation_id))?.decision, "решение после срока не записано").toBeNull();
  });

  it("за миллисекунду до expires_at — принято (граница строгая, Дополнения РП50 п. 3)", async () => {
    const r = await request();
    ctx.setNow(Date.parse(r.expires_at) - 1);
    expect((await post(r.confirmation_id, body(r, { decided_at: new Date(Date.parse(r.expires_at) - 1).toISOString() }))).status).toBe(200);
  });

  it("неизвестный запрос — 404; id не по форме и тело не по форме — 400", async () => {
    const r = await request();
    expect((await post(newConfirmationId(), body(r))).status).toBe(401);
    // Подпись над неизвестным id верна — тогда 404.
    const ghost = { ...r, confirmation_id: newConfirmationId() };
    expect(await post(ghost.confirmation_id, body(ghost))).toEqual({ status: 404, body: { code: "CONFIRMATION_NOT_FOUND" } });
    expect((await post("cnf_bad", body(r))).status).toBe(400);
    expect((await post(r.confirmation_id, { ...body(r), extra: 1 })).status, "лишнее поле не подписано").toBe(400);
    expect((await post(r.confirmation_id, { ...body(r), decision: "MAYBE" })).status).toBe(400);
    expect((await post(r.confirmation_id, { ...body(r), totals_hash: "ABC" })).status).toBe(400);
  });

  it("сбой: запрос или журнал не прочитаны, мандата запроса нет, запись не удалась — 503 STATE_UNAVAILABLE с Retry-After", async () => {
    const r = await request();
    ctx.mandate.client = "fail";
    const a = await ctx.app.inject({ method: "POST", url: `/participants/v1/confirmations/${r.confirmation_id}`, payload: body(r) });
    expect([a.statusCode, a.json(), a.headers["retry-after"]]).toEqual([503, { code: "STATE_UNAVAILABLE" }, "1"]);
    ctx.mandate.client = undefined;
    expect((await post(r.confirmation_id, body(r))).body).toEqual({ code: "STATE_UNAVAILABLE" });
    await ctx.app.close();
    ctx = await setup({ decide: async () => Promise.reject(new Error("ECONNRESET")) });
    const r2 = await request();
    expect((await post(r2.confirmation_id, body(r2))).body).toEqual({ code: "STATE_UNAVAILABLE" });
  });

  it("журнал процесса: ни ссылки, ни подписи банка", async () => {
    const r = await request();
    const b = body(r);
    const ref = (await post(r.confirmation_id, b)).body.confirmation_ref as string;
    const all = ctx.logs.join("\n");
    expect(all).not.toContain(ref);
    expect(all).not.toContain(b.signature);
  });
});
