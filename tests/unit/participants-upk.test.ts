// Роль участника UPK (PS-19 ч. 3 К1.1, РП51 п. 12; инварианты 5, 7): оператор страницы УПК подписывает только решения
// по подтверждению. Мандат, отзыв, revoke-all, лимиты и чтения ПИ-8 с его верной подписью — 401 SIGNATURE_INVALID, как
// чужой банк; тот же запрос от банка проходит проверку подписи. Боевой UPK — отказ запуска; роль — из списка доверенных.
import { createHash, generateKeyPairSync, randomUUID, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signRequest } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { participantConfirmationSigningInput } from "../../src/confirm/model.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { createUpkEmulator } from "../../src/env/upk/index.js";
import { MemoryLimitsStore, participantLimitsSigningInput, type LimitsRecord } from "../../src/participants/limits.js";
import { MemoryParticipantNotificationStore } from "../../src/participants/notifications.js";
import {
  loadTrustedParticipants,
  participantPrincipalRevocationSigningInput,
  participantRevocationSigningInput,
  participantSigningInput,
  STAND_ISSUER_CODE,
  STAND_REVOCATION_ORDER,
  STAND_UPK_CODE,
  TrustedParticipants,
  type ParticipantSignedRecord,
  type TrustedParticipantKey,
} from "../../src/participants/trusted.js";
import { PARTICIPANT_COMPONENTS, ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buildServer } from "../../src/server.js";

const T = new Date("2026-10-22T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1, event_page_max: 100 };

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
    read: (path: string, query = "") =>
      signRequest(
        { method: "GET", path, query, body: "", headers: { "x-participant-code": code, "x-timestamp": T.toISOString(), "x-nonce": randomUUID() } },
        { kid: key.kid, alg: "ed25519", sign: (data) => edSign(null, data, privateKey) },
        PARTICIPANT_COMPONENTS,
      ).headers,
  };
}

const upkTest = () => participant(STAND_UPK_CODE, { role: "UPK" });
const bankTest = (code = "bank:live") => participant(code, { revocation_order: `bank:${code}:revocation:v1` });

describe("Доверенные участники: роль UPK (РП51 п. 12)", () => {
  it("UPK вне стенда — отказ запуска; на стенде — только у stand:upk-emulator; у UPK порядка отзыва нет", () => {
    const upk = upkTest();
    expect(() => new TrustedParticipants([upk.key], { stand: false })).toThrow(/UPK допустим только на стенде/);
    expect(() => new TrustedParticipants([upk.key], { stand: true })).not.toThrow();
    const other = participant("upk:operator", { role: "UPK" });
    expect(() => new TrustedParticipants([other.key], { stand: true })).toThrow(/роль UPK — только у эмулятора/);
    expect(() => new TrustedParticipants([other.key], { stand: false })).toThrow(/UPK допустим только на стенде/);
    const fake = participant(STAND_UPK_CODE, { revocation_order: "bank:x:revocation:v1" });
    expect(() => new TrustedParticipants([fake.key], { stand: true }), "код эмулятора УПК с ролью банка").toThrow(/роль UPK/);
    expect(() => new TrustedParticipants([{ ...upk.key, revocation_order: "bank:x:revocation:v1" }], { stand: true })).toThrow(/порядка отзыва нет/);
    expect(() => new TrustedParticipants([{ ...upk.key, role: "BANK" as never }], { stand: true })).toThrow(/недопустимая role/);
    // Ключ role есть — только ISSUER или UPK: null и undefined не становятся банком по умолчанию (КТ1 № 2).
    const bank = bankTest();
    for (const role of [null, undefined, ""]) {
      expect(() => new TrustedParticipants([{ ...bank.key, role: role as never }], { stand: true }), `role: ${String(role)}`).toThrow(/недопустимая role/);
    }
  });

  it("UPK не боевой банк: не считается в пределе участников и не даёт порядок отзыва", () => {
    const emu = createIssuerEmulator();
    const upk = upkTest();
    const live = bankTest();
    expect(new TrustedParticipants([emu.trustedKey, upk.key], { stand: true }).revocationOrder()).toBe(STAND_REVOCATION_ORDER);
    expect(new TrustedParticipants([upk.key, emu.trustedKey, live.key], { stand: true }).revocationOrder()).toBe("bank:bank:live:revocation:v1");
    expect(new TrustedParticipants([upk.key], { stand: true }).revocationOrder()).toBeUndefined();
    const t = new TrustedParticipants([emu.trustedKey, upk.key], { stand: true });
    expect([t.role(STAND_UPK_CODE), t.role(STAND_ISSUER_CODE), t.role("bank:unknown")]).toEqual(["UPK", "ISSUER", undefined]);
  });

  it("файл PARTICIPANT_KEYS_PATH: role необязательное; UPK в рабочем сервере — отказ запуска; лишнее поле — отказ", () => {
    const dir = mkdtempSync(join(tmpdir(), "upk-"));
    const file = (participants: unknown[]) => {
      const p = join(dir, `${randomUUID()}.json`);
      writeFileSync(p, JSON.stringify({ participants }));
      return p;
    };
    const live = bankTest();
    expect(loadTrustedParticipants(file([{ ...live.key, role: "ISSUER" }]), { stand: false }).role("bank:live")).toBe("ISSUER");
    expect(loadTrustedParticipants(file([live.key]), { stand: false }).role("bank:live")).toBe("ISSUER");
    expect(() => loadTrustedParticipants(file([upkTest().key]), { stand: false })).toThrow(/UPK допустим только на стенде/);
    expect(() => loadTrustedParticipants(file([{ ...live.key, extra: 1 }]), { stand: false })).toThrow(/ровно/);
    expect(() => loadTrustedParticipants(file([{ ...live.key, role: null }]), { stand: false }), "role: null — не банк по умолчанию").toThrow(/недопустимая role/);
    const { revocation_order: _ro, ...noOrder } = live.key;
    void _ro;
    expect(() => loadTrustedParticipants(file([noOrder]), { stand: false }), "банк без порядка отзыва").toThrow(/ровно/);
  });

  it("проверки подписи: UPK — только решение по подтверждению; мандат, отзыв, revoke-all, лимиты, чтения — false", () => {
    const upk = upkTest();
    const t = new TrustedParticipants([upk.key], { stand: true });
    const mandate: ParticipantSignedRecord = {
      participant_code: STAND_UPK_CODE,
      kid: upk.key.kid,
      mandate_id: `mnd_${randomUUID()}`,
      mandate_hash: "a".repeat(64),
      decision: "SIGN",
      signature_type: "simple",
      signature_ref: "sig-1",
      token_consent: true,
      signed_at: T.toISOString(),
    };
    expect(t.verify(STAND_UPK_CODE, upk.key.kid, mandate, upk.s(participantSigningInput(mandate)))).toBe(false);
    const rev = { participant_code: STAND_UPK_CODE, kid: upk.key.kid, mandate_id: mandate.mandate_id, mandate_hash: mandate.mandate_hash, revocation_ref: "r-1", revoked_at: T.toISOString() };
    expect(t.verifyRevocation(rev, upk.s(participantRevocationSigningInput(rev)))).toBe(false);
    const all = { participant_code: STAND_UPK_CODE, kid: upk.key.kid, principal_ref: "prn_7f3c9a", revocation_ref: "r-2", revoked_at: T.toISOString() };
    expect(t.verifyPrincipalRevocation(all, upk.s(participantPrincipalRevocationSigningInput(all)))).toBe(false);
    const lim: LimitsRecord = { participant_code: STAND_UPK_CODE, kid: upk.key.kid, principal_ref: "prn_7f3c9a", version: 1, limits: { per_operation: 100_000, currency: "RUB" }, issued_at: T.toISOString() };
    expect(t.verifyLimits(lim, upk.s(participantLimitsSigningInput(lim)))).toBe(false);
    const raw = Buffer.from("основа подписи");
    expect(t.verifyRaw(STAND_UPK_CODE, upk.key.kid, raw, edSignRaw(upk, raw))).toBe(false);
    const cnf = {
      participant_code: STAND_UPK_CODE,
      kid: upk.key.kid,
      confirmation_id: `cnf_${randomUUID()}`,
      decision: "APPROVE" as const,
      totals_hash: createHash("sha256").update("итог").digest("hex"),
      decided_at: T.toISOString(),
    };
    expect(t.verifyConfirmation(cnf, upk.s(participantConfirmationSigningInput(cnf)))).toBe(true);
    // Эмулятор УПК стенда подписывает тем же входом.
    const emu = createUpkEmulator();
    const t2 = new TrustedParticipants([emu.trustedKey], { stand: true });
    const rec = { ...cnf, participant_code: emu.participant_code, kid: emu.trustedKey.kid };
    expect(t2.verifyConfirmation(rec, emu.signConfirmation(rec))).toBe(true);
  });
});

/** Подпись основы (base64url → Buffer) ключом участника теста. */
const edSignRaw = (p: ReturnType<typeof participant>, data: Buffer): Buffer => Buffer.from(p.s(data), "base64url");

describe("ПИ-8: верная подпись UPK на маршрутах банка — 401 SIGNATURE_INVALID, как чужой банк (РП51 п. 12)", () => {
  function server() {
    const upk = upkTest();
    const bank = bankTest();
    const trusted = new TrustedParticipants([upk.key, bank.key], { stand: true });
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
      },
    });
    return { app, upk, bank };
  }

  it("мандат: подпись и отзыв; клиент: revoke-all и лимиты — 401 от UPK, от банка — не 401", async () => {
    const { app, upk, bank } = server();
    try {
      const id = `mnd_${randomUUID()}`;
      const signRec = (p: typeof upk) => {
        const r: ParticipantSignedRecord = {
          participant_code: p.key.participant_code,
          kid: p.key.kid,
          mandate_id: id,
          mandate_hash: "a".repeat(64),
          decision: "SIGN",
          signature_type: "simple",
          signature_ref: "sig-1",
          token_consent: true,
          signed_at: T.toISOString(),
        };
        const { mandate_id: _id, ...rest } = r;
        void _id;
        return { ...rest, signature: p.s(participantSigningInput(r)) };
      };
      const revRec = (p: typeof upk) => {
        const r = { participant_code: p.key.participant_code, kid: p.key.kid, mandate_id: id, mandate_hash: "a".repeat(64), revocation_ref: "rev-1", revoked_at: T.toISOString() };
        const { mandate_id: _id, ...rest } = r;
        void _id;
        return { ...rest, signature: p.s(participantRevocationSigningInput(r)) };
      };
      const allRec = (p: typeof upk) => {
        const r = { participant_code: p.key.participant_code, kid: p.key.kid, principal_ref: "prn_7f3c9a", revocation_ref: "rev-all-1", revoked_at: T.toISOString() };
        const { principal_ref: _ref, ...rest } = r;
        void _ref;
        return { ...rest, signature: p.s(participantPrincipalRevocationSigningInput(r)) };
      };
      const limRec = (p: typeof upk) => {
        const r = {
          participant_code: p.key.participant_code,
          kid: p.key.kid,
          principal_ref: "prn_7f3c9a",
          version: 1,
          limits: { per_operation: 100_000, currency: "RUB" },
          issued_at: T.toISOString(),
        } satisfies LimitsRecord;
        const { principal_ref: _ref, ...rest } = r;
        void _ref;
        return { ...rest, signature: p.s(participantLimitsSigningInput(r)) };
      };
      const calls = [
        { method: "POST" as const, url: `/participants/v1/mandates/${id}/sign`, body: signRec },
        { method: "POST" as const, url: `/participants/v1/mandates/${id}/revoke`, body: revRec },
        { method: "POST" as const, url: "/participants/v1/principals/prn_7f3c9a/revoke-all", body: allRec },
        { method: "PUT" as const, url: "/participants/v1/principals/prn_7f3c9a/limits", body: limRec },
      ];
      for (const c of calls) {
        const asBank = await app.inject({ method: c.method, url: c.url, payload: c.body(bank) });
        expect(asBank.statusCode, `${c.url}: тело теста не по форме — проверка роли не доказана`).not.toBe(400);
        expect(asBank.statusCode, `${c.url}: банк`).not.toBe(401);
        const asUpk = await app.inject({ method: c.method, url: c.url, payload: c.body(upk) });
        expect([asUpk.statusCode, asUpk.json()], `${c.url}: UPK`).toEqual([401, { code: "SIGNATURE_INVALID" }]);
      }
    } finally {
      await app.close();
    }
  });

  it("чтения ПИ-8 (лента уведомлений, лимиты клиента) с подписанным запросом UPK — 401; банка — 200 / 404", async () => {
    const { app, upk, bank } = server();
    try {
      for (const path of ["/participants/v1/notifications", "/participants/v1/principals/prn_7f3c9a/limits"]) {
        const asBank = await app.inject({ method: "GET", url: path, headers: bank.read(path) });
        expect([200, 404], `${path}: банк`).toContain(asBank.statusCode);
        const asUpk = await app.inject({ method: "GET", url: path, headers: upk.read(path) });
        expect(asUpk.statusCode, `${path}: UPK`).toBe(401);
      }
    } finally {
      await app.close();
    }
  });
});
