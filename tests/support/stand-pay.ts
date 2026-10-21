// Агентская оплата на стенде настоящим путём (РП47, РП48 (а)): CART под INTENT, реквизит — POST /pao/v1/credentials,
// авторизация — AGENT_TOKEN с криптограммой реквизита. Для стендовых тестов бюджета и лимитов, где реквизит — не предмет.
import { randomUUID } from "node:crypto";
import { expect } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import type { Stand } from "../../src/stand/index.js";
import type { AgentSide } from "./agent.js";
import { signedInject } from "./signed-inject.js";

/**
 * Номер заказа — короткий счётчик, а не UUID: цифры UUID через дефисы иногда складываются в серию 13–19 цифр с верной
 * суммой Луна — 422 CREDENTIALS_FORBIDDEN (РП47 доп. п. 2, ложные 422 по order_ref; плавающий отказ CI run 39585729745).
 */
let orders = 0;

export interface StandPay {
  /** Мандат (INTENT или CART под parent_id), подписанный банком стенда; id. */
  mandate(req: Partial<MandateRequest>): Promise<string>;
  /** CART под INTENT с пределом amount_limit на продавца MER-1042; id. */
  cart(parent: string, amount_limit: number): Promise<string>;
  /** Авторизация на сумму по новому реквизиту заказа этого CART (amount_max = сумма). */
  auth(cart: string, amount: number, op_ref?: string): Promise<CanonicalMessage>;
}

export function standPay(stand: Stand, side: AgentSide, code: string, principal_ref: string): StandPay {
  const post = (path: string, body: unknown) =>
    signedInject(stand.app, side, code, {
      method: "POST",
      path,
      body: JSON.stringify(body),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });
  const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "продукты",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await post("/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  return {
    mandate,
    cart: (parent, amount_limit) =>
      mandate({
        type: "CART",
        parent_id: parent,
        subject: "корзина SHOP-1042",
        amount_limit,
        cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: amount_limit }], total: amount_limit },
      }),
    async auth(cart, amount, op_ref = `OPKC-PAY-${randomUUID()}`) {
      const res = await post("/pao/v1/credentials", {
        mandate_id: cart,
        order_ref: `ORD-pay-${++orders}`,
        merchant_id: "MER-1042",
        amount_max: amount,
        currency: "RUB",
        kind: "CARD",
      });
      expect(res.statusCode).toBe(201);
      const c = res.json() as Credential;
      return {
        op_ref,
        msg_type: "AUTH_REQUEST",
        channel: "CARD",
        amount,
        currency: "RUB",
        merchant: { id: "MER-1042", mcc: "5411" },
        instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
        aoi: c.aoi,
      };
    },
  };
}
