// ПС13 «Реверсал освобождает резерв» на стенде (РП11, РП55 п. 1; ФП7): авторизация одобрена → REVERSAL от процессинга
// по ПИ-3 → резерв освобождён на всех счетах операции (CART, родитель INTENT, счёт периода клиента), остаток восстановлен;
// повтор события не меняет состояние. Сообщения процессинга — прямо в ADP и ПИ-3 стенда; путь через ОПКЦ — PS-11.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps13:v1";

describe("ПС13 на стенде: реверсал освобождает резерв (РП55)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_ps13_");
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-10-23T15:00:00Z"));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    const limits = await stand.issuer.setLimits(principal, { per_period: 100_000, period: "DAY", currency: "RUB" }, 1);
    expect(limits.statusCode, JSON.stringify(limits.body)).toBe(200);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, principal);
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (id: string) => ((await signedGet(`/pao/v1/mandates/${id}/verify`)).json() as { amount_left: number }).amount_left;

  it("авторизация одобрена → REVERSAL: резерв освобождён на CART, INTENT и у клиента; остаток восстановлен; повтор не меняет состояние", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    const op = `OPKC-PS13-${letters(12)}`;
    expect(await decide(await pay().auth(cart, 70_000, op))).toMatchObject({ decision: "APPROVE" });
    expect(await pi3({ op_ref: op, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect([await left(cart), await left(intent)]).toEqual([30_000, 30_000]);

    expect(await pi3({ op_ref: op, msg_type: "REVERSAL", amount: 70_000, currency: "RUB" })).toBe(202);
    expect([await left(cart), await left(intent)]).toEqual([100_000, 100_000]);
    expect(((await signedGet(`/pao/v1/operations/${op}`)).json() as { status: string; reason: string }).status).toBe("REVERSED");

    // Повтор события — состояние то же.
    expect(await pi3({ op_ref: op, msg_type: "REVERSAL", amount: 70_000, currency: "RUB" })).toBe(202);
    expect([await left(cart), await left(intent)]).toEqual([100_000, 100_000]);

    // Остаток клиента за период восстановлен: новая операция на весь лимит клиента одобрена.
    const second = await pay().cart(await pay().mandate({ amount_limit: 100_000 }), 100_000);
    expect(await decide(await pay().auth(second, 100_000, `OPKC-PS13-${letters(12)}`))).toMatchObject({ decision: "APPROVE" });
  });
});
