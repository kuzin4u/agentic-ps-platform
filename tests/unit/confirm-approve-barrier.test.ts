// Второй барьер ПИ-8 (РП76 «Дополнение — второй барьер ПИ-8»; остаточный риск 2; Р-1440, Р-1443): APPROVE банка при
// отозванном мандате не пишется — проход отзыва закрывает запрос, ответ 409 CONFIRMATION_NOT_PENDING со статусом REJECTED.
// Гонка с воротами: отзыв CART записан в журнал, проход отзыва стоит на воротах (pendingByAgent) — в это окно банк
// одобряет. Проверки — после g.open() и allSettled (РП71 нюанс 5). REJECT в том же окне пишется как прежде; сбой прохода
// барьера — 503, повтор — 409. Путь «витрина → ADP → подтверждение» — без подмены, как tests/unit/confirm-revoke.test.ts.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryConfirmationStore } from "../../src/confirm/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:approve-barrier:v1";
const PRINCIPAL = "prn_approve_barrier";
const T0 = new Date("2026-11-10T12:00:00Z");
const SKU = "BRD-1042-02"; // 1 890 ₽
const QTY = 2;
const TOTAL = 378_000; // выше порога подтверждения стенда (300 000) — CONFIRMATION_REQUIRED

let st: Stand | undefined;
let mm: MerchantsStand | undefined;
afterEach(async () => {
  vi.restoreAllMocks();
  await mm?.close();
  await st?.close();
  mm = undefined;
  st = undefined;
});

/** Ворота: вход отмечается, выход — после open(). */
function gate() {
  let entered!: () => void;
  let release!: () => void;
  const inside = new Promise<void>((r) => (entered = r));
  const opened = new Promise<void>((r) => (release = r));
  return { inside, enter: async () => (entered(), opened), open: () => release() };
}

async function setup() {
  const s = createStand();
  st = s;
  s.setClock(T0);
  const side = newAgentSide();
  expect((await s.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  const m = createMerchants(s, {
    decide: async (msg: CanonicalMessage) => {
      const d = (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
      return d.decision === "APPROVE" ? { approved: true, reason: null } : { approved: false, reason: d.reason ?? null };
    },
  });
  mm = m;
  const pao = (method: "GET" | "POST", path: string, body?: unknown) =>
    signedInject(s.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: s.now(),
    });
  const shop = (path: string, body?: unknown) => merchantCall(m.app, { side, agentCode: CODE, now: s.now(), path, ...(body === undefined ? {} : { body }) });
  const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-11-13T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await pao("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await s.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "хлеб" });
  type Feed = { readonly type: string; readonly data: Record<string, unknown> }[];
  const feed = async (): Promise<Feed> => (await pao("GET", "/pao/v1/events")).json() as Feed;
  /** CART, заказ, реквизит, оплата: витрина ждёт подтверждения, П6 — запрос PENDING. */
  const awaiting = async () => {
    const cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: TOTAL,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: SKU, qty: QTY, price: TOTAL / QTY }], total: TOTAL },
    });
    const o = (await shop("/v1/shops/SHOP-1042/orders", { items: [{ sku: SKU, qty: QTY }], cart_mandate_id: cartId })).json() as { id: string };
    const res = await pao("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: o.id, merchant_id: "MER-1042", amount_max: TOTAL, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const paid = await shop(`/v1/shops/SHOP-1042/orders/${o.id}/payment`, {
      credential_ref: cred.credential_ref,
      kind: cred.kind,
      payload: cred.payload,
      aoi: cred.aoi,
      cart_mandate_id: cartId,
      order_ref: o.id,
    });
    expect(paid.json()).toMatchObject({ status: "AWAITING_CONFIRMATION" });
    const confirmation_id = (await feed()).filter((e) => e.type === "confirmation.required").at(-1)!.data.confirmation_id as string;
    return { cartId, confirmation_id };
  };
  const record = async (id: string) => s.confirmations.get(id);
  const rejectedEvents = async (id: string) => (await feed()).filter((e) => e.type === "confirmation.rejected" && e.data.confirmation_id === id);
  /**
   * Отзыв CART через ПИ-8, проход отзыва — на воротах (первый вызов pendingByAgent); `during` — действие банка в окне
   * «отзыв в журнале, проход не прошёл». Остальные вызовы pendingByAgent — как есть, или по `next`.
   */
  const revokeWithGate = async <T>(cartId: string, during: () => Promise<T>, next?: () => Promise<never>) => {
    const g = gate();
    const orig = MemoryConfirmationStore.prototype.pendingByAgent;
    let calls = 0;
    vi.spyOn(MemoryConfirmationStore.prototype, "pendingByAgent").mockImplementation(async function (this: MemoryConfirmationStore, ...args) {
      calls += 1;
      if (calls === 1) await g.enter();
      else if (calls === 2 && next) return next();
      return orig.apply(this, args);
    });
    const revoke = s.issuer.revoke(cartId);
    await g.inside;
    let mid: T | undefined;
    try {
      mid = await during();
    } finally {
      g.open();
    }
    const [rv] = await Promise.allSettled([revoke]);
    return { mid: mid as T, revoke: rv };
  };
  return { s, pao, awaiting, record, rejectedEvents, revokeWithGate };
}

describe("РП76 «Дополнение — второй барьер ПИ-8»", () => {
  it("гонка: отзыв в журнале, проход на воротах — APPROVE банка → 409 REJECTED, запрос закрыт, одно событие, ссылки нет", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const { mid: approve, revoke } = await t.revokeWithGate(a.cartId, () => t.s.issuer.confirm(a.confirmation_id));
    expect(revoke).toMatchObject({ status: "fulfilled", value: { statusCode: 200 } });
    expect(approve).toMatchObject({ statusCode: 409, body: { code: "CONFIRMATION_NOT_PENDING", status: "REJECTED" } });
    expect(await t.record(a.confirmation_id)).toMatchObject({
      status: "REJECTED",
      decision: null,
      confirmation_ref: null,
      closed: { reason: "MANDATE_REVOKED", at: t.s.now().toISOString() },
    });
    expect(await t.rejectedEvents(a.confirmation_id)).toHaveLength(1);
    expect((await t.pao("GET", `/pao/v1/confirmations/${a.confirmation_id}`)).json()).toMatchObject({ status: "REJECTED", confirmation_ref: null });
  });

  it("REJECT банка в том же окне пишется как прежде — решение человека, без closed", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const { mid: reject, revoke } = await t.revokeWithGate(a.cartId, () => t.s.issuer.confirm(a.confirmation_id, { decision: "REJECT" }));
    expect(revoke).toMatchObject({ status: "fulfilled", value: { statusCode: 200 } });
    expect(reject).toMatchObject({ statusCode: 200, body: { status: "REJECTED" } });
    const rec = await t.record(a.confirmation_id);
    expect(rec).toMatchObject({ status: "REJECTED", confirmation_ref: null });
    expect(rec?.decision).toMatchObject({ decision: "REJECT" });
    expect(rec?.closed).toBeUndefined();
  });

  it("сбой прохода барьера — 503 STATE_UNAVAILABLE, запрос PENDING; повтор того же решения — 409 REJECTED", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const { mid: first } = await t.revokeWithGate(
      a.cartId,
      async () => {
        const r = await t.s.issuer.confirm(a.confirmation_id);
        return { r, status: (await t.record(a.confirmation_id))?.status };
      },
      () => Promise.reject(new Error("ECONNRESET")),
    );
    expect(first.r).toMatchObject({ statusCode: 503, body: { code: "STATE_UNAVAILABLE" } });
    expect(first.status).toBe("PENDING");
    // Проход отзыва после ворот уже закрыл запрос; повтор банка — 409 с тем же статусом.
    const again = await t.s.issuer.confirm(a.confirmation_id);
    expect(again).toMatchObject({ statusCode: 409, body: { code: "CONFIRMATION_NOT_PENDING", status: "REJECTED" } });
    expect(await t.rejectedEvents(a.confirmation_id)).toHaveLength(1);
  });

  it("APPROVE при действующем мандате — 200 APPROVED со ссылкой, как прежде", async () => {
    const t = await setup();
    const a = await t.awaiting();
    const r = await t.s.issuer.confirm(a.confirmation_id);
    expect(r).toMatchObject({ statusCode: 200, body: { status: "APPROVED" } });
    expect((await t.record(a.confirmation_id))?.confirmation_ref).toMatch(/^cr_/);
  });
});
