// РП72 (#58 ч. 1–2) на стенде: подтверждение человеком через продавца — сквозной путь «витрина → ADP → подтверждение →
// витрина» без подмены. Решение заглушки ОПКЦ асинхронное (п. 10): сообщение эквайрера уходит в ADP стенда
// (POST /adp/v1/decide); ответ эмитента после APPROVE — ПИ-3 ISSUER_RESPONSE из теста (путь через ОПКЦ — PS-11).
// Заказ 3 780 ₽ при пороге 3 000 ₽: AWAITING_CONFIRMATION → confirmation.required → приложение банка → GET со ссылкой →
// POST …/confirmation → новая операция с confirmation_ref → APPROVE → PAID, operation.authorized по новому op_ref;
// сверка метаданных эквайрера — PENDING после первой авторизации, MATCHED после одобрения (Р-1083).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:rp72-stand:v1";
const PRINCIPAL = "prn_rp72_stand";
const SKU = "BRD-1042-02"; // 1 890 ₽ — по цене продавца
const QTY = 2;
const TOTAL = 378_000;

describe("РП72 на стенде: витрина → ADP → подтверждение → витрина", () => {
  let stand: Stand;
  let side: AgentSide;
  let m: MerchantsStand;
  let intentId: string;
  /** Решения ADP по сообщениям эквайрера — по порядку авторизаций. */
  const decisions: { op_ref: string; decision: Decision }[] = [];

  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-11-01T10:00:00Z"));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "хлеб" });
    m = createMerchants(stand, {
      decide: async (msg: CanonicalMessage) => {
        const decision = (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
        decisions.push({ op_ref: msg.op_ref, decision });
        if (decision.decision !== "APPROVE") return { approved: false, reason: decision.reason ?? null };
        // Эмитент одобрил — ответ эмитента Платформе по ПИ-3 (в пути ОПКЦ это делает процессинг, PS-11).
        const r = await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref: msg.op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved: true } });
        expect(r.statusCode).toBe(202);
        return { approved: true, reason: null };
      },
    });
  });
  afterAll(async () => {
    await m.close();
    await stand.close();
  });

  const pao = (method: "GET" | "POST", path: string, body?: unknown) =>
    signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });
  const shop = (path: string, body?: unknown) => merchantCall(m.app, { side, agentCode: CODE, now: stand.now(), path, ...(body === undefined ? {} : { body }) });

  async function mandate(over: Partial<MandateRequest>): Promise<string> {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-11-05T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await pao("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  }

  type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];
  const feed = async (): Promise<Feed> => (await pao("GET", "/pao/v1/events")).json() as Feed;

  /** Заказ продавца, мандат корзины на него и реквизит на заказ; оплата пакетом — ответ витрины. */
  async function orderAndPay() {
    const cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: TOTAL,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: SKU, qty: QTY, price: TOTAL / QTY }], total: TOTAL },
    });
    const o = (await shop("/v1/shops/SHOP-1042/orders", { items: [{ sku: SKU, qty: QTY }], cart_mandate_id: cartId })).json() as { id: string; total: number };
    expect(o.total).toBe(TOTAL);
    const res = await pao("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: o.id, merchant_id: "MER-1042", amount_max: TOTAL, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const pkg = { credential_ref: cred.credential_ref, kind: cred.kind, payload: cred.payload, aoi: cred.aoi, cart_mandate_id: cartId, order_ref: o.id };
    const paid = await shop(`/v1/shops/SHOP-1042/orders/${o.id}/payment`, pkg);
    return { cartId, o, cred, paid };
  }

  it("доказательный: AWAITING_CONFIRMATION → банк подтверждает → ссылка продавцу → новая операция → APPROVE → PAID; сверка PENDING → MATCHED", async () => {
    const before = decisions.length;
    const repliesBefore = m.reconciliationReplies.length;
    const { o, cred, paid } = await orderAndPay();

    // Ч. 1: ADP — CONFIRMATION_REQUIRED, витрина — «ждёт» и признак; событий operation.* нет.
    expect(decisions.slice(before).map((d) => d.decision.decision)).toEqual(["CONFIRMATION_REQUIRED"]);
    expect(paid.statusCode).toBe(200);
    expect(paid.json()).toMatchObject({ status: "AWAITING_CONFIRMATION", payment: { approved: false, confirmation_required: true } });
    const firstOp = decisions[before]!.op_ref;

    // Агент: confirmation.required → GET; confirmation_id — из события, не от продавца.
    const required = (await feed()).filter((e) => e.type === "confirmation.required").at(-1)!;
    const id = required.data.confirmation_id as string;
    expect(paid.body).not.toContain(id);
    expect((await pao("GET", `/pao/v1/confirmations/${id}`)).json()).toMatchObject({ status: "PENDING", confirmation_ref: null });

    // Человек подтверждает в приложении банка; агент читает ссылку.
    expect((await stand.issuer.confirm(id)).statusCode).toBe(200);
    const { confirmation_ref } = (await pao("GET", `/pao/v1/confirmations/${id}`)).json() as { confirmation_ref: string };
    expect(confirmation_ref).toMatch(/^cr_/);

    // Ч. 2: ссылка продавцу — повтор новой операцией с тем же реквизитом (новый POST /credentials не нужен).
    const done = await shop(`/v1/shops/SHOP-1042/orders/${o.id}/confirmation`, { confirmation_ref });
    expect(done.statusCode).toBe(200);
    expect(done.json()).toMatchObject({ id: o.id, status: "PAID" });
    expect(done.json().payment).toEqual({ approved: true, confirmation_required: false });
    const retry = decisions[before + 1]!;
    expect(retry.decision).toMatchObject({ decision: "APPROVE", reason: null });
    expect(retry.op_ref).not.toBe(firstOp);
    const [, second] = m.opkc.messages.filter((x) => x.order_ref === o.id);
    expect(second).toMatchObject({ op_ref: retry.op_ref, confirmation_ref, order_ref: o.id, amount: TOTAL });
    expect(second!.instrument).toMatchObject({ kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref, cryptogram: cred.payload.cryptogram });
    expect((await stand.confirmations.get(id))?.status).toBe("USED");

    // Итог — событием Платформы по новому op_ref; по первой попытке operation.* нет.
    const events = await feed();
    expect(events.filter((e) => e.type === "operation.authorized" && e.data.op_ref === retry.op_ref)).toHaveLength(1);
    expect(events.filter((e) => e.type.startsWith("operation.") && e.data.op_ref === firstOp)).toEqual([]);
    expect((await pao("GET", `/pao/v1/operations/${retry.op_ref}`)).json()).toMatchObject({ op_ref: retry.op_ref, status: "AUTHORIZED" });

    // Сверка метаданных эквайрера после каждой авторизации (Р-1083, РП57 п. 7): PENDING, затем MATCHED с новым op_ref.
    expect(m.reconciliationReplies.slice(repliesBefore)).toEqual([
      { statusCode: 200, body: { credential_ref: cred.credential_ref, result: "PENDING", aoi_checked: true } },
      { statusCode: 200, body: { credential_ref: cred.credential_ref, result: "MATCHED", aoi_checked: true, op_ref: retry.op_ref } },
    ]);

    // Потерян ответ — повтор той же ссылки: 200 с текущим заказом, без новой авторизации.
    const again = await shop(`/v1/shops/SHOP-1042/orders/${o.id}/confirmation`, { confirmation_ref });
    expect(again.json()).toEqual(done.json());
    expect(decisions.length).toBe(before + 2);
  });

  it("погашенная ссылка к другому заказу — ADP снова CONFIRMATION_REQUIRED, заказ DECLINED (однократность, РП50 п. 8–9)", async () => {
    const first = await orderAndPay();
    const id = ((await feed()).filter((e) => e.type === "confirmation.required").at(-1)!.data.confirmation_id) as string;
    expect((await stand.issuer.confirm(id)).statusCode).toBe(200);
    const { confirmation_ref } = (await pao("GET", `/pao/v1/confirmations/${id}`)).json() as { confirmation_ref: string };
    expect((await shop(`/v1/shops/SHOP-1042/orders/${first.o.id}/confirmation`, { confirmation_ref })).json().status).toBe("PAID");

    const second = await orderAndPay();
    expect(second.paid.json().status).toBe("AWAITING_CONFIRMATION");
    const before = decisions.length;
    const r = await shop(`/v1/shops/SHOP-1042/orders/${second.o.id}/confirmation`, { confirmation_ref });
    expect(decisions.slice(before).map((d) => d.decision.decision)).toEqual(["CONFIRMATION_REQUIRED"]);
    expect(r.json()).toMatchObject({ status: "DECLINED" });
    expect(r.json().payment).toEqual({ approved: false, confirmation_required: false });
  });
});
