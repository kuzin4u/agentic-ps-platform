// Знак готовности продавца (PS-30 ч. 2 К1, РП57 п. 1–3, 7; A5 п. 5; инварианты 3, 5, 6): роль ACQUIRER с перечнем
// продавцов, записи эквайрера и оператора только вставкой, статус в два шага — приостановление оператора не обходится
// записями эквайрера (З1); чтение продавцом без подписи, эквайрером с подписью и причиной, агентом через ПАО (no-store).
import { generateKeyPairSync, randomUUID, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signRequest } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { participantConfirmationSigningInput } from "../../src/confirm/model.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryParticipantNotificationStore } from "../../src/participants/notifications.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { MemoryLimitsStore, participantLimitsSigningInput, type LimitsRecord } from "../../src/participants/limits.js";
import { MemoryReadinessStore, readinessOf } from "../../src/participants/readiness.js";
import {
  ACQUIRER_ONLY,
  loadTrustedParticipants,
  participantPrincipalRevocationSigningInput,
  participantReadinessSigningInput,
  participantRevocationSigningInput,
  participantSigningInput,
  STAND_ACQUIRER_CODE,
  STAND_ISSUER_CODE,
  STAND_UPK_CODE,
  TrustedParticipants,
  type ParticipantSignedRecord,
  type ReadinessSignedRecord,
  type TrustedParticipantKey,
} from "../../src/participants/trusted.js";
import { PARTICIPANT_COMPONENTS, ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buildServer, MAX_PATH_PARAM_LENGTH } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { SHOPS } from "../../src/env/merchants/shops.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { letters } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";

const params = loadParams();
const T = new Date("2026-10-24T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1, event_page_max: 100 };
const readinessPath = (id: string) => `/participants/v1/merchants/${encodeURIComponent(id)}/readiness`;

/** Участник теста с закрытым ключом: подписывает любые записи, чтобы проверить отказ по роли, а не по подписи. */
function participant(code: string, extra: Partial<TrustedParticipantKey>) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  const key: TrustedParticipantKey = { participant_code: code, kid: jwkThumbprint({ crv, kty, x }), alg: "ed25519", public_key, ...extra };
  const s = (b: Buffer) => edSign(null, b, privateKey).toString("base64url");
  return {
    key,
    s,
    read: (path: string, at = T) =>
      signRequest(
        { method: "GET", path, query: "", body: "", headers: { "x-participant-code": code, "x-timestamp": at.toISOString(), "x-nonce": randomUUID() } },
        { kid: key.kid, alg: "ed25519", sign: (data) => edSign(null, data, privateKey) },
        PARTICIPANT_COMPONENTS,
      ).headers,
    /** Тело POST знака: запись без merchant_id (он в пути) и подпись этим ключом. */
    readiness: (merchant_id: string, status: "ACTIVE" | "WITHDRAWN", opts: { ref?: string; at?: Date } = {}) => {
      const r: ReadinessSignedRecord = {
        participant_code: code,
        kid: key.kid,
        merchant_id,
        readiness_ref: opts.ref ?? `rdy-${letters()}`,
        status,
        issued_at: (opts.at ?? T).toISOString(),
      };
      const { merchant_id: _id, ...rest } = r;
      void _id;
      return { ...rest, signature: s(participantReadinessSigningInput(r)) };
    },
  };
}

const acquirerTest = (code = "acq:live", merchants = ["MER-A", "MER-B"]) => participant(code, { role: "ACQUIRER", merchants });
const bankTest = (code = "bank:live") => participant(code, { revocation_order: `bank:${code}:revocation:v1` });
const upkTest = () => participant(STAND_UPK_CODE, { role: "UPK" });

/** Сервер ПИ-8 с эквайрером, банком и УПК; хранилище знака — снаружи (тест гонки пишет в обход 409). */
function server() {
  const acq = acquirerTest();
  const bank = bankTest();
  const upk = upkTest();
  const trusted = new TrustedParticipants([acq.key, bank.key, upk.key], { stand: true });
  const store = new MemoryReadinessStore();
  const consent = new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1", now: () => T });
  const app = buildServer({
    env: "dev",
    participants: {
      trusted,
      consent,
      params: POLICY,
      now: () => T,
      limits: new MemoryLimitsStore(),
      requests: new ParticipantRequestVerifier(trusted, { skewSec: 300, now: () => T }),
      notifications: new MemoryParticipantNotificationStore(new MemoryOperationStore()),
      readiness: { store, skewSec: 300 },
    },
  });
  const post = (merchant_id: string, body: unknown) =>
    app.inject({ method: "POST", url: readinessPath(merchant_id), payload: body as Record<string, unknown> });
  return { app, acq, bank, upk, store, post, trusted };
}

describe("Доверенные участники: роль ACQUIRER (РП57 п. 1)", () => {
  it("один продавец — один эквайрер: merchant_id в перечнях двух участников — отказ запуска", () => {
    const a = acquirerTest("acq:one", ["MER-1", "MER-2"]);
    const b = acquirerTest("acq:two", ["MER-3", "MER-2"]);
    expect(() => new TrustedParticipants([a.key, b.key], { stand: false })).toThrow(/MER-2 в перечнях двух эквайреров/);
    const c = acquirerTest("acq:two", ["MER-3"]);
    const t = new TrustedParticipants([a.key, c.key], { stand: false });
    expect([t.serves("acq:one", "MER-2"), t.serves("acq:two", "MER-2"), t.serves("acq:two", "MER-3"), t.serves("bank:x", "MER-1")]).toEqual([
      true,
      false,
      true,
      false,
    ]);
  });

  it("перечень обязателен и только у ACQUIRER; у эквайрера нет порядка отзыва и вебхука; разные перечни в ключах одного участника — отказ", () => {
    expect(() => new TrustedParticipants([participant("acq:x", { role: "ACQUIRER" }).key], { stand: false })).toThrow(/перечень merchants/);
    expect(() => new TrustedParticipants([acquirerTest("acq:x", []).key], { stand: false })).toThrow(/перечень merchants/);
    expect(() => new TrustedParticipants([acquirerTest("acq:x", ["M", "M"]).key], { stand: false })).toThrow(/без повторов/);
    const bank = participant("bank:x", { revocation_order: "bank:x:revocation:v1", merchants: ["MER-1"] });
    expect(() => new TrustedParticipants([bank.key], { stand: false })).toThrow(/только у роли ACQUIRER/);
    const withOrder = participant("acq:x", { role: "ACQUIRER", merchants: ["MER-1"], revocation_order: "bank:x:revocation:v1" });
    expect(() => new TrustedParticipants([withOrder.key], { stand: false })).toThrow(/нет revocation_order и notify_url/);
    const k1 = acquirerTest("acq:x", ["MER-1"]);
    const k2 = acquirerTest("acq:x", ["MER-2"]);
    expect(() => new TrustedParticipants([k1.key, k2.key], { stand: false })).toThrow(/разные перечни merchants/);
  });

  it("боевой ACQUIRER допустим и не считается в пределе банков; код эмулятора эквайрера — только на стенде", () => {
    const t = new TrustedParticipants([acquirerTest().key, bankTest().key], { stand: false });
    expect([t.role("acq:live"), t.role("bank:live")]).toEqual(["ACQUIRER", "ISSUER"]);
    const emu = acquirerTest(STAND_ACQUIRER_CODE, ["MER-1"]);
    expect(() => new TrustedParticipants([emu.key], { stand: false })).toThrow(/только на стенде/);
    expect(new TrustedParticipants([emu.key], { stand: true }).role(STAND_ACQUIRER_CODE)).toBe("ACQUIRER");
    // Ревью КТ1 № 11: код эмулятора стенда вне стенда — отказ при любой роли.
    for (const c of [STAND_ISSUER_CODE, STAND_UPK_CODE]) {
      expect(() => new TrustedParticipants([acquirerTest(c, ["MER-1"]).key], { stand: false }), c).toThrow(/только на стенде/);
    }
  });

  it("файл PARTICIPANT_KEYS_PATH: у ACQUIRER — merchants вместо revocation_order; иначе — отказ", () => {
    const dir = mkdtempSync(join(tmpdir(), "acq-"));
    const file = (list: unknown[]) => {
      const p = join(dir, `${randomUUID()}.json`);
      writeFileSync(p, JSON.stringify({ participants: list }));
      return p;
    };
    const acq = acquirerTest("acq:file", ["MER-1"]);
    expect(loadTrustedParticipants(file([acq.key]), { stand: false }).serves("acq:file", "MER-1")).toBe(true);
    const { role: _r, ...noRole } = acq.key;
    void _r;
    expect(() => loadTrustedParticipants(file([noRole]), { stand: false })).toThrow(/merchants вместо revocation_order/);
  });

  it("подписи: ACQUIRER — только запись знака; решения, отзыв, лимиты и чтения эмитента — false; ISSUER и UPK над записью знака — false", () => {
    const acq = acquirerTest();
    const bank = bankTest();
    const upk = upkTest();
    const t = new TrustedParticipants([acq.key, bank.key, upk.key], { stand: true });
    const rec = (p: typeof acq): ReadinessSignedRecord => ({
      participant_code: p.key.participant_code,
      kid: p.key.kid,
      merchant_id: "MER-A",
      readiness_ref: "r-1",
      status: "ACTIVE",
      issued_at: T.toISOString(),
    });
    expect(t.verifyReadiness(rec(acq), acq.s(participantReadinessSigningInput(rec(acq))))).toBe(true);
    expect(t.verifyReadiness(rec(bank), bank.s(participantReadinessSigningInput(rec(bank))))).toBe(false);
    expect(t.verifyReadiness(rec(upk), upk.s(participantReadinessSigningInput(rec(upk))))).toBe(false);
    const mandate: ParticipantSignedRecord = {
      participant_code: "acq:live",
      kid: acq.key.kid,
      mandate_id: `mnd_${randomUUID()}`,
      mandate_hash: "a".repeat(64),
      decision: "SIGN",
      signature_type: "simple",
      signature_ref: "sig-1",
      token_consent: true,
      signed_at: T.toISOString(),
    };
    expect(t.verify("acq:live", acq.key.kid, mandate, acq.s(participantSigningInput(mandate)))).toBe(false);
    const lim: LimitsRecord = { participant_code: "acq:live", kid: acq.key.kid, principal_ref: "prn_7f3c9a", version: 1, limits: {}, issued_at: T.toISOString() };
    expect(t.verifyLimits(lim, acq.s(participantLimitsSigningInput(lim)))).toBe(false);
    // Ревью КТ1 № 8: отзыв мандата, revoke-all и решение по подтверждению — тоже не эквайрера.
    const rev = { participant_code: "acq:live", kid: acq.key.kid, mandate_id: mandate.mandate_id, mandate_hash: "a".repeat(64), revocation_ref: "r-1", revoked_at: T.toISOString() };
    expect(t.verifyRevocation(rev, acq.s(participantRevocationSigningInput(rev)))).toBe(false);
    const all = { participant_code: "acq:live", kid: acq.key.kid, principal_ref: "prn_7f3c9a", revocation_ref: "r-2", revoked_at: T.toISOString() };
    expect(t.verifyPrincipalRevocation(all, acq.s(participantPrincipalRevocationSigningInput(all)))).toBe(false);
    const cnf = {
      participant_code: "acq:live",
      kid: acq.key.kid,
      confirmation_id: `cnf_${randomUUID()}`,
      decision: "APPROVE" as const,
      totals_hash: "b".repeat(64),
      decided_at: T.toISOString(),
    };
    expect(t.verifyConfirmation(cnf, acq.s(participantConfirmationSigningInput(cnf)))).toBe(false);
    const bankCnf = { ...cnf, participant_code: "bank:live", kid: bank.key.kid };
    expect(t.verifyConfirmation(bankCnf, bank.s(participantConfirmationSigningInput(bankCnf))), "банк — та же запись проходит").toBe(true);
    const raw = Buffer.from("основа подписи");
    const sig = Buffer.from(acq.s(raw), "base64url");
    expect([t.verifyRaw("acq:live", acq.key.kid, raw, sig), t.verifyRaw("acq:live", acq.key.kid, raw, sig, ACQUIRER_ONLY)]).toEqual([false, true]);
  });
});

describe("ПИ-8 POST /participants/v1/merchants/{id}/readiness (РП57 п. 2)", () => {
  it("подача ACTIVE → ACTIVE, снятие WITHDRAWN → NONE; since — время записи Платформы", async () => {
    const { app, acq, post } = server();
    try {
      const r1 = await post("MER-A", acq.readiness("MER-A", "ACTIVE"));
      expect([r1.statusCode, r1.json()]).toEqual([200, { merchant_id: "MER-A", status: "ACTIVE", since: T.toISOString() }]);
      const r2 = await post("MER-A", acq.readiness("MER-A", "WITHDRAWN"));
      expect([r2.statusCode, r2.json().status]).toEqual([200, "NONE"]);
    } finally {
      await app.close();
    }
  });

  it("З1: SUSPENDED → WITHDRAWN (409) → ACTIVE (409) → итог SUSPENDED; запись эквайрера в обход 409 статус не меняет; REINSTATED — по записям эквайрера", async () => {
    const { app, acq, post, store } = server();
    try {
      expect((await post("MER-A", acq.readiness("MER-A", "ACTIVE"))).statusCode).toBe(200);
      await store.putOperator({ merchant_id: "MER-A", action: "SUSPENDED", reason: "DISCREPANCY", received_at: T.toISOString() });
      const w = await post("MER-A", acq.readiness("MER-A", "WITHDRAWN"));
      expect([w.statusCode, w.json()]).toEqual([409, { code: "READINESS_SUSPENDED" }]);
      const a = await post("MER-A", acq.readiness("MER-A", "ACTIVE"));
      expect([a.statusCode, a.json()]).toEqual([409, { code: "READINESS_SUSPENDED" }]);
      expect(await store.current("MER-A")).toEqual({ merchant_id: "MER-A", status: "SUSPENDED", since: T.toISOString(), reason: "DISCREPANCY" });
      // Гонка «подача ↔ приостановление» (РП57 п. 2, шаг 1): запись эквайрера легла после приостановления — статус прежний.
      // В памяти гонки нет (вставка с проверкой — одним шагом); на PostgreSQL — readiness-pg.test.ts.
      const op = { seq: 2, status: "SUSPENDED", reason: "DISCREPANCY" as const, received_at: T.toISOString() };
      for (const status of ["WITHDRAWN", "ACTIVE"]) {
        const raced = { seq: 3, status, reason: null, received_at: T.toISOString() };
        expect(readinessOf("MER-A", raced, op).status, `запись ${status} после приостановления`).toBe("SUSPENDED");
      }
      await store.putOperator({ merchant_id: "MER-A", action: "REINSTATED", reason: null, received_at: T.toISOString() });
      expect((await store.current("MER-A")).status, "после снятия — по последней записи эквайрера (ACTIVE до приостановления)").toBe("ACTIVE");
      const after = await post("MER-A", acq.readiness("MER-A", "WITHDRAWN"));
      expect([after.statusCode, after.json().status]).toEqual([200, "NONE"]);
    } finally {
      await app.close();
    }
  });

  it("повтор старой ACTIVE после WITHDRAWN — 200 без записи, статус NONE; та же ссылка с другой записью — 409 READINESS_CONFLICT", async () => {
    const { app, acq, post } = server();
    try {
      const old = acq.readiness("MER-A", "ACTIVE", { ref: "r-old" });
      expect((await post("MER-A", old)).json().status).toBe("ACTIVE");
      expect((await post("MER-A", acq.readiness("MER-A", "WITHDRAWN", { ref: "r-new" }))).json().status).toBe("NONE");
      const replay = await post("MER-A", old);
      expect([replay.statusCode, replay.json().status]).toEqual([200, "NONE"]);
      const other = await post("MER-A", acq.readiness("MER-A", "WITHDRAWN", { ref: "r-old" }));
      expect([other.statusCode, other.json()]).toEqual([409, { code: "READINESS_CONFLICT" }]);
    } finally {
      await app.close();
    }
  });

  it("since — received_at последней записи любого источника, в том числе не менявшей статус (ревью КТ1 № 7)", async () => {
    const store = new MemoryReadinessStore();
    const at = (min: number) => new Date(T.getTime() + min * 60_000).toISOString();
    const acq = (ref: string, status: "ACTIVE" | "WITHDRAWN", received_at: string) => ({
      participant_code: "acq:live",
      kid: "k",
      merchant_id: "MER-A",
      readiness_ref: ref,
      status,
      issued_at: T.toISOString(),
      signature: "s".repeat(86),
      received_at,
    });
    expect(await store.current("MER-A")).toEqual({ merchant_id: "MER-A", status: "NONE", since: null });
    await store.putAcquirer(acq("a", "ACTIVE", at(1)));
    expect((await store.current("MER-A")).since).toBe(at(1));
    await store.putAcquirer(acq("b", "ACTIVE", at(2)));
    expect(await store.current("MER-A"), "ACTIVE поверх ACTIVE — since новой записи").toEqual({ merchant_id: "MER-A", status: "ACTIVE", since: at(2) });
    await store.putOperator({ merchant_id: "MER-A", action: "SUSPENDED", reason: "DISCREPANCY", received_at: at(3) });
    expect((await store.current("MER-A")).since).toBe(at(3));
    await store.putOperator({ merchant_id: "MER-A", action: "REINSTATED", reason: null, received_at: at(4) });
    expect(await store.current("MER-A"), "снятие — since снятия").toEqual({ merchant_id: "MER-A", status: "ACTIVE", since: at(4) });
  });

  it("issued_at позже часов Платформы сверх signature_skew_sec — 401; в пределе допуска — 200", async () => {
    const { app, acq, post } = server();
    try {
      const late = await post("MER-A", acq.readiness("MER-A", "ACTIVE", { at: new Date(T.getTime() + 301_000) }));
      expect([late.statusCode, late.json()]).toEqual([401, { code: "SIGNATURE_INVALID" }]);
      const ok = await post("MER-A", acq.readiness("MER-A", "ACTIVE", { at: new Date(T.getTime() + 299_000) }));
      expect(ok.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it("чужой продавец: POST — 403 MERCHANT_NOT_SERVED, GET — 404 MERCHANT_NOT_FOUND (различие намеренное, З7)", async () => {
    const { app, acq, post } = server();
    try {
      const p = await post("MER-Z", acq.readiness("MER-Z", "ACTIVE"));
      expect([p.statusCode, p.json()]).toEqual([403, { code: "MERCHANT_NOT_SERVED" }]);
      const g = await app.inject({ method: "GET", url: readinessPath("MER-Z"), headers: acq.read(readinessPath("MER-Z")) });
      expect([g.statusCode, g.json()]).toEqual([404, { code: "MERCHANT_NOT_FOUND" }]);
      const own = await app.inject({ method: "GET", url: readinessPath("MER-B"), headers: acq.read(readinessPath("MER-B")) });
      expect([own.statusCode, own.json()]).toEqual([200, { merchant_id: "MER-B", status: "NONE", since: null }]);
    } finally {
      await app.close();
    }
  });

  it("ISSUER и UPK на маршрутах эквайрера — 401; ACQUIRER на маршрутах эмитента — 401 (запись и чтение)", async () => {
    const { app, acq, bank, upk, post } = server();
    try {
      for (const p of [bank, upk]) {
        const w = await post("MER-A", p.readiness("MER-A", "ACTIVE"));
        expect([w.statusCode, w.json()], `${p.key.participant_code}: POST знака`).toEqual([401, { code: "SIGNATURE_INVALID" }]);
        const r = await app.inject({ method: "GET", url: readinessPath("MER-A"), headers: p.read(readinessPath("MER-A")) });
        expect(r.statusCode, `${p.key.participant_code}: GET знака`).toBe(401);
      }
      const feed = "/participants/v1/notifications";
      expect((await app.inject({ method: "GET", url: feed, headers: acq.read(feed) })).statusCode, "ACQUIRER: лента уведомлений").toBe(401);
      expect((await app.inject({ method: "GET", url: feed, headers: bank.read(feed) })).statusCode, "банк: лента").toBe(200);
      const lim = "/participants/v1/principals/prn_7f3c9a/limits";
      const asAcq = await app.inject({ method: "GET", url: lim, headers: acq.read(lim) });
      expect(asAcq.statusCode, "ACQUIRER: GET лимитов эмитента").toBe(401);
      const asBank = await app.inject({ method: "GET", url: lim, headers: bank.read(lim) });
      expect(asBank.statusCode, "банк: тот же запрос проходит подпись").toBe(404);
      const limRec = { participant_code: "acq:live", kid: acq.key.kid, principal_ref: "prn_7f3c9a", version: 1, limits: {}, issued_at: T.toISOString() } satisfies LimitsRecord;
      const { principal_ref: _ref, ...body } = { ...limRec, signature: acq.s(participantLimitsSigningInput(limRec)) };
      void _ref;
      const put = await app.inject({ method: "PUT", url: lim, payload: body });
      expect([put.statusCode, put.json()], "ACQUIRER: PUT лимитов").toEqual([401, { code: "SIGNATURE_INVALID" }]);
    } finally {
      await app.close();
    }
  });

  it("GET эквайрера — с причиной приостановления; тело не по форме — 400", async () => {
    const { app, acq, post, store } = server();
    try {
      await store.putOperator({ merchant_id: "MER-B", action: "SUSPENDED", reason: "AGENT_REFUSALS", received_at: T.toISOString() });
      const g = await app.inject({ method: "GET", url: readinessPath("MER-B"), headers: acq.read(readinessPath("MER-B")) });
      expect(g.json()).toEqual({ merchant_id: "MER-B", status: "SUSPENDED", since: T.toISOString(), reason: "AGENT_REFUSALS" });
      const { signature: _s, ...noSig } = acq.readiness("MER-A", "ACTIVE");
      void _s;
      expect((await post("MER-A", noSig)).statusCode).toBe(400);
      expect((await post("MER-A", { ...acq.readiness("MER-A", "ACTIVE"), amount: 1 })).statusCode).toBe(400);
      expect((await post("MER-A", acq.readiness("MER-A", "SUSPENDED" as "ACTIVE"))).statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });
});

describe("Стенд: знаки витрин и три представления статуса (РП57 п. 3, 7)", () => {
  async function standWithAgent(): Promise<{ s: Stand; side: ReturnType<typeof newAgentSide>; code: string }> {
    const s = createStand();
    const side = newAgentSide();
    const code = `nspk:agent:rdy-${letters()}:v1`;
    expect((await s.admit(buyerApplication(code, side), "op-rdy")).admitted).toBe(true);
    return { s, side, code };
  }

  it("эквайрер стенда подал знаки витринам с readiness_mark; у MKT-77 — NONE; продавец и агент видят одно и то же", async () => {
    const { s, side, code } = await standWithAgent();
    try {
      for (const shop of SHOPS) {
        const expected = shop.readiness_mark ? "ACTIVE" : "NONE";
        const m = await s.app.inject({ method: "GET", url: `/merchants/v1/merchants/${shop.merchant_id}/readiness` });
        expect([m.statusCode, m.json().status], `${shop.id}: продавец`).toEqual([200, expected]);
        const a = await signedInject(s.app, side, code, { path: `/pao/v1/merchants/${shop.merchant_id}/readiness` });
        expect([a.statusCode, a.json()], `${shop.id}: агент`).toEqual([200, m.json()]);
        const q = await s.acquirerParticipant.getReadiness(shop.merchant_id);
        expect([q.statusCode, (q.body as { status: string }).status], `${shop.id}: эквайрер`).toEqual([200, expected]);
      }
      expect(SHOPS.find((x) => x.id === "MKT-77")?.readiness_mark).toBe(false);
    } finally {
      await s.close();
    }
  });

  it("Cache-Control: продавцу — public, max-age = merchant_readiness_max_age_sec; агенту через ПАО — no-store", async () => {
    const { s, side, code } = await standWithAgent();
    try {
      const m = await s.app.inject({ method: "GET", url: "/merchants/v1/merchants/MER-1042/readiness" });
      expect(m.headers["cache-control"]).toBe(`public, max-age=${params.merchant_readiness_max_age_sec}`);
      expect(params.merchant_readiness_max_age_sec, "на стенде 1 с (РП57, вопрос 6)").toBe(1);
      const a = await signedInject(s.app, side, code, { path: "/pao/v1/merchants/MER-1042/readiness" });
      expect(a.headers["cache-control"]).toBe("no-store");
    } finally {
      await s.close();
    }
  });

  it("приостановление оператором: продавец и агент — SUSPENDED без причины, эквайрер — с причиной; снятие — снова ACTIVE", async () => {
    const { s, side, code } = await standWithAgent();
    try {
      await s.suspendReadiness("MER-1042", "SYSTEMATIC_CANCELLATION");
      const m = (await s.app.inject({ method: "GET", url: "/merchants/v1/merchants/MER-1042/readiness" })).json();
      expect([m.status, "reason" in m]).toEqual(["SUSPENDED", false]);
      const a = (await signedInject(s.app, side, code, { path: "/pao/v1/merchants/MER-1042/readiness" })).json();
      expect([a.status, "reason" in a]).toEqual(["SUSPENDED", false]);
      expect(((await s.acquirerParticipant.getReadiness("MER-1042")).body as { reason?: string }).reason).toBe("SYSTEMATIC_CANCELLATION");
      const w = await s.acquirerParticipant.submitReadiness("MER-1042", "WITHDRAWN");
      expect([w.statusCode, w.body]).toEqual([409, { code: "READINESS_SUSPENDED" }]);
      await s.reinstateReadiness("MER-1042");
      expect((await signedInject(s.app, side, code, { path: "/pao/v1/merchants/MER-1042/readiness" })).json().status).toBe("ACTIVE");
    } finally {
      await s.close();
    }
  });

  it("неизвестный продавец — 200 NONE, since null; приостановленный агент на ПАО — 403 AGENT_SUSPENDED", async () => {
    const { s, side, code } = await standWithAgent();
    try {
      const m = await s.app.inject({ method: "GET", url: "/merchants/v1/merchants/MER-UNKNOWN/readiness" });
      expect([m.statusCode, m.json()]).toEqual([200, { merchant_id: "MER-UNKNOWN", status: "NONE", since: null }]);
      await s.suspendAgent(code, "KEY_COMPROMISE");
      const susp = await signedInject(s.app, side, code, { path: "/pao/v1/merchants/MER-1042/readiness" });
      expect([susp.statusCode, susp.json().code]).toEqual([403, "AGENT_SUSPENDED"]);
    } finally {
      await s.close();
    }
  });

  it("снятие знака сразу после createStand — NONE: публичная подача ждёт начальной (ревью КТ1 № 2)", async () => {
    const s = createStand();
    try {
      const w = await s.acquirerParticipant.submitReadiness("MER-4401", "WITHDRAWN");
      expect([w.statusCode, (w.body as { status: string }).status]).toEqual([200, "NONE"]);
      const m = await s.app.inject({ method: "GET", url: "/merchants/v1/merchants/MER-4401/readiness" });
      expect(m.json().status).toBe("NONE");
    } finally {
      await s.close();
    }
  });
});

describe("Длина параметра пути: транспортный предел 256 (РП57 доп. 1)", () => {
  it(`MAX_PATH_PARAM_LENGTH = 256; merchant_id: 128 — обработчик, 129 и 256 — 400 по форме, 257 — 414 Fastify (продавец, эквайрер, ПАО)`, async () => {
    expect(MAX_PATH_PARAM_LENGTH).toBe(256);
    const { s, side, code } = await (async () => {
      const st = createStand();
      const sd = newAgentSide();
      const c = `nspk:agent:len-${letters()}:v1`;
      expect((await st.admit(buyerApplication(c, sd), "op-len")).admitted).toBe(true);
      return { s: st, side: sd, code: c };
    })();
    try {
      for (const [n, merchantHttp, paoHttp] of [
        [128, 200, 200],
        [129, 400, 400],
        [256, 400, 400],
        [257, 414, 414],
      ] as const) {
        const id = "M".repeat(n);
        const m = await s.app.inject({ method: "GET", url: `/merchants/v1/merchants/${id}/readiness` });
        expect(m.statusCode, `продавец, ${n} знаков`).toBe(merchantHttp);
        if (merchantHttp === 400) expect(m.json()).toEqual({ code: "REQUEST_INVALID" });
        const a = await signedInject(s.app, side, code, { path: `/pao/v1/merchants/${id}/readiness` });
        expect(a.statusCode, `агент, ${n} знаков`).toBe(paoHttp);
        if (paoHttp === 400) expect(a.json().code).toBe("REQUEST_INVALID");
      }
    } finally {
      await s.close();
    }
  });

  it("ПИ-8 эквайрера: merchant_id 128 — обработчик (403 чужой / 404), 129 — 400, 257 — 414", async () => {
    const { app, acq, post } = server();
    try {
      for (const [n, postHttp, getHttp] of [
        [128, 403, 404],
        [129, 400, 400],
        [257, 414, 414],
      ] as const) {
        const id = "M".repeat(n);
        expect((await post(id, acq.readiness(id, "ACTIVE"))).statusCode, `POST, ${n} знаков`).toBe(postHttp);
        const g = await app.inject({ method: "GET", url: readinessPath(id), headers: acq.read(readinessPath(id)) });
        expect(g.statusCode, `GET, ${n} знаков`).toBe(getHttp);
      }
    } finally {
      await app.close();
    }
  });

  it("код агента в статусе для продавца (№ 43): 256 знаков — обработчик (404 AGENT_UNKNOWN), 257 — 414; было 101+ — 414", async () => {
    const s = createStand();
    try {
      const at = (n: number) => `nspk:agent:${"a".repeat(n - "nspk:agent::v1".length)}:v1`;
      expect(at(256)).toHaveLength(256);
      const ok = await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${at(256)}` });
      expect([ok.statusCode, ok.json()]).toEqual([404, { code: "AGENT_UNKNOWN" }]);
      const at101 = await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${at(101)}` });
      expect(at101.statusCode, "101 знак — до обработчика").toBe(404);
      expect((await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${at(257)}` })).statusCode).toBe(414);
    } finally {
      await s.close();
    }
  });

  it("№ 43 закрыт (РП63 п. 11): допущенный с кодом 256 знаков читается продавцом — 200; 257 знаков не допускается", async () => {
    const s = createStand();
    try {
      const at = (n: number) => `nspk:agent:${"a".repeat(n - "nspk:agent::v1".length)}:v1`;
      expect((await s.admit(buyerApplication(at(256), newAgentSide()), "op")).admitted).toBe(true);
      const r = await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${at(256)}` });
      expect([r.statusCode, r.json()]).toEqual([200, { agent_code: at(256), status: "ACTIVE", class: "BUYER" }]);
      const long = await s.admit(buyerApplication(at(257), newAgentSide()), "op");
      expect(long.admitted ? [] : long.reasons).toEqual(["CODE_INVALID"]);
    } finally {
      await s.close();
    }
  });
});
