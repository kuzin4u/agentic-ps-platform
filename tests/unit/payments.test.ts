// Метаданные пакета и сверка credential_ref → op_ref (PS-30 ч. 2 К2, РП22 п. 6, РП57 п. 5–6; инварианты 1, 3, 5, 6):
// эквайрер за продавца присылает подписанную запись ПИ-8; ответ — сверка по записи реквизита П5: MATCHED с op_ref после
// погашения ADP (и после реверсала), MISMATCH с полями, PENDING, NOT_USED с причиной (EXPIRED, MANDATE_REVOKED — отзыв и
// revoke-all, AGENT_SUSPENDED); без aoi — aoi_checked: false. Статус агента для эквайрера — путь ПИ-8 с подписью.
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { createAcquirerParticipant } from "../../src/env/acquirer/participant.js";
import { maskRef, MemoryPaymentMetadataStore } from "../../src/participants/payments.js";
import { participantRoutes } from "../../src/participants/routes.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";

const MER = "MER-1042";

interface Issued {
  readonly cart: string;
  readonly credential: Credential;
  readonly order_ref: string;
  readonly msg: CanonicalMessage;
}

describe("ПИ-8 POST /participants/v1/merchants/{id}/payments — сверка credential_ref → op_ref (РП57 п. 5)", () => {
  let s: Stand;
  let valid_to: string;
  let side: AgentSide;
  let code: string;
  let principal: string;

  const post = (path: string, body: unknown) =>
    signedInject(s.app, side, code, { method: "POST", path, body: JSON.stringify(body), headers: { "idempotency-key": randomUUID() }, now: s.now() });

  async function mandate(over: Record<string, unknown>): Promise<string> {
    const res = await post("/pao/v1/mandates", {
      type: "INTENT",
      subject: "продукты",
      amount_limit: 100_000,
      currency: "RUB",
      valid_to,
      merchant_scope: [MER],
      principal_ref: principal,
      mode: "IMMEDIATE",
      ...over,
    });
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await s.issuer.sign(id)).statusCode).toBe(200);
    return id;
  }

  /** CART под новым INTENT и реквизит заказа через ПАО; сообщение авторизации — как у эквайрера с aoi. */
  async function issue(amount = 10_000): Promise<Issued> {
    const intent = await mandate({});
    const cart = await mandate({
      type: "CART",
      parent_id: intent,
      subject: "корзина SHOP-1042",
      amount_limit: amount,
      cart: { merchant_id: MER, items: [{ sku: "milk-2l", qty: 1, price: amount }], total: amount },
    });
    const order_ref = `ORD-${randomUUID()}`;
    const res = await post("/pao/v1/credentials", { mandate_id: cart, order_ref, merchant_id: MER, amount_max: amount, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const credential = res.json() as Credential;
    const msg: CanonicalMessage = {
      op_ref: `OPKC-RCN-${randomUUID()}`,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount,
      currency: "RUB",
      merchant: { id: MER, mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: credential.payload.token_ref as string, cryptogram: credential.payload.cryptogram as string },
      aoi: credential.aoi,
    } as CanonicalMessage;
    return { cart, credential, order_ref, msg };
  }

  const decide = async (m: CanonicalMessage) => (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const meta = (i: Issued, over: { order_ref?: string; aoi?: { agent_code: string; mandate_id: string } | null; metadata_ref?: string } = {}) => ({
    credential_ref: i.credential.credential_ref,
    order_ref: over.order_ref ?? i.order_ref,
    ...(over.aoi === null ? {} : { aoi: over.aoi ?? { agent_code: code, mandate_id: i.cart } }),
    ...(over.metadata_ref ? { metadata_ref: over.metadata_ref } : {}),
  });
  const submit = (i: Issued, over: Parameters<typeof meta>[1] = {}, merchant = MER) => s.acquirerParticipant.submitPaymentMetadata(merchant, meta(i, over));

  beforeEach(async () => {
    s = createStand();
    // От часов стенда, не литералом: стенд сверяет срок по настоящим часам (К1.2 MER-62-45). Один на тест — срок CART
    // не позже родителя, иначе MANDATE_SCOPE.
    valid_to = new Date(s.now().getTime() + 7 * 86_400_000).toISOString();
    side = newAgentSide();
    code = `nspk:agent:rcn-${letters()}:v1`;
    principal = opaquePrincipalRef("prn_rcn_");
    expect(s.admit(buyerApplication(code, side), "op-rcn").admitted).toBe(true);
    expect((await s.issuer.setLimits(principal, { per_period: 1_000_000, period: "DAY", currency: "RUB" }, 1)).statusCode).toBe(200);
  });
  afterEach(async () => {
    await s.close();
  });

  it("PENDING до авторизации → MATCHED с op_ref после одобрения ADP; повтор той же записи — 200 с пересчётом; op_ref не вход", async () => {
    const i = await issue();
    const first = await submit(i, { metadata_ref: "m-1" });
    expect([first.statusCode, first.body]).toEqual([200, { credential_ref: i.credential.credential_ref, result: "PENDING", aoi_checked: true }]);
    expect((await decide(i.msg)).decision).toBe("APPROVE");
    const again = await submit(i, { metadata_ref: "m-1" });
    // Повтор подписан заново с другим submitted_at — та же ссылка с другой записью; повтор той же записи — через GET.
    expect([again.statusCode, again.body]).toEqual([409, { code: "METADATA_CONFLICT" }]);
    const g = await s.acquirerParticipant.getReconciliation(MER, i.credential.credential_ref);
    expect([g.statusCode, g.body]).toEqual([200, { credential_ref: i.credential.credential_ref, result: "MATCHED", aoi_checked: true, op_ref: i.msg.op_ref }]);
  });

  it("повтор той же записи — 200, сверка на момент ответа", async () => {
    const i = await issue();
    const fixed = { metadata_ref: "m-rep", submitted_at: s.now().toISOString() };
    const r1 = await s.acquirerParticipant.submitPaymentMetadata(MER, { ...meta(i), ...fixed });
    expect((r1.body as { result: string }).result).toBe("PENDING");
    await decide(i.msg);
    const r2 = await s.acquirerParticipant.submitPaymentMetadata(MER, { ...meta(i), ...fixed });
    expect([r2.statusCode, (r2.body as { result: string }).result]).toEqual([200, "MATCHED"]);
  });

  it("MATCHED после реверсала — тот же op_ref; состояние операции в ответ не входит", async () => {
    const i = await issue();
    await decide(i.msg);
    const ev = await s.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref: i.msg.op_ref, msg_type: "REVERSAL", amount: 10_000, currency: "RUB" } });
    expect(ev.statusCode).toBe(202);
    const r = await submit(i);
    expect(r.body).toEqual({ credential_ref: i.credential.credential_ref, result: "MATCHED", aoi_checked: true, op_ref: i.msg.op_ref });
  });

  it("MISMATCH с полями: order_ref, aoi.agent_code, aoi.mandate_id — при любом статусе реквизита; без aoi сравнения aoi нет", async () => {
    const i = await issue();
    const r1 = await submit(i, { order_ref: "ORD-other", aoi: { agent_code: "nspk:agent:other:v1", mandate_id: "mnd_other" } });
    expect(r1.body).toEqual({ credential_ref: i.credential.credential_ref, result: "MISMATCH", aoi_checked: true, fields: ["order_ref", "aoi.agent_code", "aoi.mandate_id"] });
    await decide(i.msg);
    const r2 = await submit(i, { aoi: { agent_code: code, mandate_id: "mnd_other" } });
    expect((r2.body as { fields: string[] }).fields).toEqual(["aoi.mandate_id"]);
    const r3 = await submit(i, { aoi: null, order_ref: "ORD-other" });
    expect(r3.body).toEqual({ credential_ref: i.credential.credential_ref, result: "MISMATCH", aoi_checked: false, fields: ["order_ref"] });
  });

  it("без aoi — aoi_checked: false, сверка по merchant_id и order_ref", async () => {
    const i = await issue();
    expect((await submit(i, { aoi: null })).body).toEqual({ credential_ref: i.credential.credential_ref, result: "PENDING", aoi_checked: false });
    await decide(i.msg);
    expect((await submit(i, { aoi: null })).body).toEqual({ credential_ref: i.credential.credential_ref, result: "MATCHED", aoi_checked: false, op_ref: i.msg.op_ref });
  });

  it("NOT_USED EXPIRED — valid_to реквизита прошёл без погашения", async () => {
    const i = await issue();
    s.setClock(new Date(Date.parse(i.credential.payload.valid_to as string) + 1000));
    expect((await submit(i)).body).toEqual({ credential_ref: i.credential.credential_ref, result: "NOT_USED", aoi_checked: true, reason: "EXPIRED" });
  });

  it("NOT_USED MANDATE_REVOKED — отзыв мандата клиентом", async () => {
    const i = await issue();
    expect((await s.issuer.revoke(i.cart)).statusCode).toBe(200);
    expect((await submit(i)).body).toEqual({ credential_ref: i.credential.credential_ref, result: "NOT_USED", aoi_checked: true, reason: "MANDATE_REVOKED" });
  });

  it("NOT_USED MANDATE_REVOKED — отзыв всех полномочий клиента (revoke-all)", async () => {
    const i = await issue();
    expect((await s.issuer.revokeAll(principal, `rva-${letters()}`)).statusCode).toBe(200);
    expect((await submit(i)).body).toEqual({ credential_ref: i.credential.credential_ref, result: "NOT_USED", aoi_checked: true, reason: "MANDATE_REVOKED" });
  });

  it("порядок причин — настоящая причина (РП57 доп. 5 (б)): отозван и истёк → MANDATE_REVOKED; приостановлен и истёк → AGENT_SUSPENDED; отозван и приостановлен → MANDATE_REVOKED", async () => {
    const revoked = await issue();
    expect((await s.issuer.revoke(revoked.cart)).statusCode).toBe(200);
    const suspended = await issue();
    const both = await issue();
    expect((await s.issuer.revoke(both.cart)).statusCode).toBe(200);
    s.setClock(new Date(Date.now() + 1000));
    await s.suspendAgent(code, "KEY_COMPROMISE");
    s.setClock(new Date(Date.parse(revoked.credential.payload.valid_to as string) + 60_000));
    expect((await submit(revoked)).body).toMatchObject({ result: "NOT_USED", reason: "MANDATE_REVOKED" });
    expect((await submit(suspended)).body).toMatchObject({ result: "NOT_USED", reason: "AGENT_SUSPENDED" });
    expect((await submit(both)).body).toMatchObject({ result: "NOT_USED", reason: "MANDATE_REVOKED" });
  });

  it("NOT_USED AGENT_SUSPENDED — выдан до приостановления агента, и после снятия тоже (РП54 п. 5)", async () => {
    const i = await issue();
    s.setClock(new Date(Date.now() + 1000));
    await s.suspendAgent(code, "KEY_COMPROMISE");
    expect((await submit(i)).body).toEqual({ credential_ref: i.credential.credential_ref, result: "NOT_USED", aoi_checked: true, reason: "AGENT_SUSPENDED" });
    await s.reinstateAgent(code);
    expect((await submit(i)).body).toMatchObject({ result: "NOT_USED", reason: "AGENT_SUSPENDED" });
  });

  it("реквизит другого продавца и неизвестный — 404 CREDENTIAL_NOT_FOUND без записи; продавец не из перечня — 403", async () => {
    const i = await issue();
    const other = await submit(i, {}, "MER-4401");
    expect([other.statusCode, other.body]).toEqual([404, { code: "CREDENTIAL_NOT_FOUND" }]);
    const g = await s.acquirerParticipant.getReconciliation("MER-4401", i.credential.credential_ref);
    expect(g.statusCode, "метаданные по чужому реквизиту не записаны").toBe(404);
    const unknown = await s.acquirerParticipant.submitPaymentMetadata(MER, { credential_ref: "crd_unknown", order_ref: "ORD-x" });
    expect([unknown.statusCode, unknown.body]).toEqual([404, { code: "CREDENTIAL_NOT_FOUND" }]);
    const foreign = await submit(i, {}, "MER-ZZZ");
    expect([foreign.statusCode, foreign.body]).toEqual([403, { code: "MERCHANT_NOT_SERVED" }]);
    const gf = await s.acquirerParticipant.getReconciliation("MER-ZZZ", i.credential.credential_ref);
    expect([gf.statusCode, gf.body]).toEqual([404, { code: "CREDENTIAL_NOT_FOUND" }]);
  });

  it("GET сверки: нет метаданных — 404; подпись ISSUER — 401", async () => {
    const i = await issue();
    expect((await s.acquirerParticipant.getReconciliation(MER, i.credential.credential_ref)).statusCode).toBe(404);
    await submit(i);
    const path = `/participants/v1/merchants/${MER}/payments/${i.credential.credential_ref}`;
    const asBank = await s.app.inject({ method: "GET", url: path, headers: s.issuer.signRequest("GET", path, "", s.now()) });
    expect(asBank.statusCode).toBe(401);
  });

  it("credential_ref в пути: 128 знаков — обработчик (404), 129 — 400, 257 — 414 транспорта (РП57 доп. 1)", async () => {
    for (const [n, http] of [
      [128, 404],
      [129, 400],
      [257, 414],
    ] as const) {
      const r = await s.acquirerParticipant.getReconciliation(MER, "c".repeat(n));
      expect(r.statusCode, `${n} знаков`).toBe(http);
    }
  });
});

describe("Попытка по неизвестному или чужому реквизиту — в журнал процесса (РП57 доп. 5 (г))", () => {
  it("404 без записи; в журнале — код участника, merchant_id и маска credential_ref, без тела записи", async () => {
    const acq = createAcquirerParticipant(["MER-1042"]);
    const trusted = new TrustedParticipants([acq.trustedKey], { stand: true });
    const lines: Record<string, unknown>[] = [];
    const app = Fastify({ logger: { level: "info", stream: { write: (l: string) => void lines.push(JSON.parse(l)) } } });
    const store = new MemoryPaymentMetadataStore();
    await participantRoutes(app, {
      trusted,
      consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
      params: { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 },
      payments: {
        store,
        reconcile: { credentials: { credentialForMerchant: async () => undefined }, mandateStatus: async () => "ACTIVE", suspendedAt: () => null, now: () => new Date() },
        skewSec: 300,
      },
    });
    try {
      const credential_ref = "crd_secretsecretsecretsecret";
      const record = {
        participant_code: acq.participant_code,
        kid: acq.trustedKey.kid,
        merchant_id: "MER-1042",
        metadata_ref: "m-unknown",
        credential_ref,
        order_ref: "ORD-private-42",
        submitted_at: new Date().toISOString(),
      };
      const { merchant_id: _m, ...body } = { ...record, signature: acq.signPaymentMetadata(record) };
      void _m;
      const r = await app.inject({ method: "POST", url: "/participants/v1/merchants/MER-1042/payments", payload: body });
      expect([r.statusCode, r.json()]).toEqual([404, { code: "CREDENTIAL_NOT_FOUND" }]);
      expect(await store.latest("MER-1042", credential_ref), "в сверку не записано").toBeUndefined();
      const line = lines.find((l) => String(l.msg).includes("неизвестному реквизиту"));
      expect(line).toMatchObject({ participant_code: acq.participant_code, merchant_id: "MER-1042", credential_ref: maskRef(credential_ref) });
      expect(maskRef(credential_ref)).toBe("crd_…cret(28)");
      const raw = JSON.stringify(lines);
      for (const leak of [credential_ref, "ORD-private-42", body.signature]) expect(raw.includes(leak), leak).toBe(false);
    } finally {
      await app.close();
    }
  });
});

describe("ПИ-8 GET /participants/v1/agents/{code}/status — статус агента для эквайрера (РП57 п. 6)", () => {
  it("эквайрер — {agent_code, status, class}, как API продавцов; неизвестный — 404; подпись ISSUER — 401", async () => {
    const s = createStand();
    try {
      const side = newAgentSide();
      const code = `nspk:agent:sts-${letters()}:v1`;
      expect(s.admit(buyerApplication(code, side), "op-sts").admitted).toBe(true);
      const r = await s.acquirerParticipant.getAgentStatus(code);
      const pub = await s.app.inject({ method: "GET", url: `/merchants/v1/agents/${code}` });
      expect([r.statusCode, r.body]).toEqual([200, pub.json()]);
      expect(r.body).toEqual({ agent_code: code, status: "ACTIVE", class: "BUYER" });
      expect((await s.acquirerParticipant.getAgentStatus("nspk:agent:none:v1")).body).toEqual({ code: "AGENT_UNKNOWN" });
      const path = `/participants/v1/agents/${code}/status`;
      const asBank = await s.app.inject({ method: "GET", url: path, headers: s.issuer.signRequest("GET", path, "", s.now()) });
      expect(asBank.statusCode).toBe(401);
      await s.suspendAgent(code, "KEY_COMPROMISE");
      expect(((await s.acquirerParticipant.getAgentStatus(code)).body as { status: string }).status).toBe("SUSPENDED");
    } finally {
      await s.close();
    }
  });
});
