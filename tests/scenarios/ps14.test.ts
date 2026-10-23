// ПС14 «Клиринг закрепляет и формирует запись об исполнении» на стенде (A1 п. 6; РП53; ФП7, ФП11): авторизация одобрена →
// PRESENTMENT → резерв закреплён, запись об исполнении формирует Платформа по сообщению процессинга, событие
// operation.settled, fulfilment_ref — в GET; во втором случае частичное PRESENTMENT — остаток резерва освобождён.
// Сообщения процессинга — прямо в ADP и ПИ-3 стенда; путь через ОПКЦ — PS-11. Подробные ветки — tests/unit/pao-presentment.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fulfilmentRefFor } from "../../src/fulfilment/records.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps14:v1";

type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];

describe("ПС14 на стенде: клиринг закрепляет и формирует запись об исполнении (РП53)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_ps14s_");
  beforeAll(() => {
    stand = createStand();
    stand.setClock(new Date("2026-10-23T15:10:00Z"));
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, principal);
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (id: string) => ((await signedGet(`/pao/v1/mandates/${id}/verify`)).json() as { amount_left: number }).amount_left;
  const settled = async (op: string) => ((await signedGet("/pao/v1/events")).json() as Feed).filter((e) => e.type === "operation.settled" && e.data.op_ref === op);
  const authorized = async (cart: string, amount: number): Promise<string> => {
    const op = `OPKC-PS14S-${letters(12)}`;
    expect(await decide(await pay().auth(cart, amount, op))).toMatchObject({ decision: "APPROVE" });
    expect(await pi3({ op_ref: op, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    return op;
  };

  it("полное PRESENTMENT: резерв закреплён, запись об исполнении Платформы, одно operation.settled; fulfilment_ref — в GET", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    const op = await authorized(cart, 60_000);
    expect(await pi3({ op_ref: op, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    expect((await settled(op)).map((e) => e.data)).toEqual([{ op_ref: op }]);
    expect((await signedGet(`/pao/v1/operations/${op}`)).json()).toMatchObject({
      status: "SETTLED",
      fulfilment: { fulfilment_ref: fulfilmentRefFor(op), final_amount: 60_000, scope_check: "WITHIN_LIMITS", spent_position: 60_000 },
    });
    expect([await left(cart), await left(intent)]).toEqual([40_000, 40_000]);
  });

  it("частичное PRESENTMENT: закреплено 45 000 из 60 000, остаток резерва освобождён", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    const op = await authorized(cart, 60_000);
    expect([await left(cart), await left(intent)]).toEqual([40_000, 40_000]);
    expect(await pi3({ op_ref: op, msg_type: "PRESENTMENT", amount: 45_000, currency: "RUB" })).toBe(202);
    expect([await left(cart), await left(intent)]).toEqual([55_000, 55_000]);
    expect(await settled(op)).toHaveLength(1);
    expect((await signedGet(`/pao/v1/operations/${op}`)).json()).toMatchObject({ status: "SETTLED", fulfilment: { final_amount: 45_000 } });
  });
});
