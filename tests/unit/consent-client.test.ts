// П2 Клиент мандата для лимитов (PS-20 К1.4, РП45 п. 1): банк, подписавший корневой мандат (у CART — INTENT), и
// principal_ref записи — из журнала (инвариант 5); CART подписывает банк корневого INTENT, другой участник — 401.
import { createHash, generateKeyPairSync, randomUUID, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { participantSigningInput, TrustedParticipants, type ParticipantSignedRecord } from "../../src/participants/trusted.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buildServer } from "../../src/server.js";
import type { MandateRequest } from "../../src/shared/pao.js";

const A = "nspk:agent:client-a:v1";
const T0 = new Date("2026-10-19T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 };
const key = (): string => createHash("sha256").update(randomUUID()).digest("hex");

const intent: MandateRequest = {
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
};
const cart = (parent_id: string): MandateRequest => ({
  ...intent,
  type: "CART",
  parent_id,
  subject: "корзина SHOP-1042",
  amount_limit: 12_900,
  cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
});

function bank(code: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  return {
    code,
    trustedKey: { participant_code: code, kid: jwkThumbprint({ crv, kty, x }), alg: "ed25519", public_key, revocation_order: `bank:${code}:revocation:v1` },
    signRecord: (r: ParticipantSignedRecord) => edSign(null, participantSigningInput(r), privateKey).toString("base64url"),
  };
}

describe("клиент мандата из журнала (РП45 п. 1)", () => {
  it("INTENT — банк своей подписи; CART — банк корня; CART чужим банком — 401 SIGNATURE_INVALID без записи", async () => {
    const consent = new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
    const emu = createIssuerEmulator();
    const other = bank("bank-b");
    const trusted = new TrustedParticipants([emu.trustedKey, other.trustedKey], { stand: true });
    const app = buildServer({ env: "dev", participants: { trusted, consent, params: POLICY } });
    const sign = async (id: string, hash: string, b: { trustedKey: { participant_code: string; kid: string }; signRecord: (r: ParticipantSignedRecord) => string }) => {
      const r: ParticipantSignedRecord = {
        participant_code: b.trustedKey.participant_code,
        kid: b.trustedKey.kid,
        mandate_id: id,
        mandate_hash: hash,
        decision: "SIGN",
        signature_type: "simple",
        signature_ref: `sig-${id.slice(-6)}`,
        token_consent: true,
        signed_at: T0.toISOString(),
      };
      const { mandate_id: _id, ...rest } = r;
      void _id;
      const res = await app.inject({ method: "POST", url: `/participants/v1/mandates/${id}/sign`, payload: { ...rest, signature: b.signRecord(r) } });
      return { status: res.statusCode, body: res.json() as Record<string, unknown> };
    };
    try {
      const p = await consent.request(A, key(), intent);
      expect((await consent.adpMandate(p.id!, A))?.client).toBeNull();
      expect((await sign(p.id!, p.hash!, emu)).status).toBe(200);
      const view = await consent.adpMandate(p.id!, A);
      expect(view?.client).toEqual({ participant_code: emu.participant_code, principal_ref: "prn_7f3c9a" });
      expect(view?.status).toBe("ACTIVE");
      const c = await consent.request(A, key(), cart(p.id!));
      expect(await sign(c.id!, c.hash!, other)).toEqual({ status: 401, body: { code: "SIGNATURE_INVALID" } });
      expect((await consent.get(c.id!, A))?.status).toBe("PENDING_SIGNATURE");
      expect((await sign(c.id!, c.hash!, emu)).status).toBe(200);
      expect((await consent.adpMandate(c.id!, A))?.client).toEqual({ participant_code: emu.participant_code, principal_ref: "prn_7f3c9a" });
      // Чужой агент — как неизвестный.
      expect(await consent.adpMandate(c.id!, "nspk:agent:other:v1")).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});
