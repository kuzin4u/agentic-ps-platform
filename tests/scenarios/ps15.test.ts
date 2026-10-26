// ПС15 «Возврат продавцом» на стенде (A4 п. 4.1; В8; РП9, РП55 п. 3; ФП7): операция в клиринге → REFUND по ПИ-3 →
// возврат проведён (запись Платформы), бюджет мандата не восстановлен при restore_budget_on_refund = false, событие
// operation.refunded. Сообщения процессинга — прямо в ADP и ПИ-3 стенда; путь через ОПКЦ — PS-11. Ветки — pao-refund.
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps15:v1";

type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];

describe("ПС15 на стенде: возврат продавцом (РП55)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_ps15_");
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-10-23T15:20:00Z"));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, principal);
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (id: string) => ((await signedGet(`/pao/v1/mandates/${id}/verify`)).json() as { amount_left: number }).amount_left;

  it("стендовый параметр restore_budget_on_refund = false", () => {
    const params = JSON.parse(readFileSync(new URL("../../config/params.stand.json", import.meta.url), "utf8")) as { restore_budget_on_refund: boolean };
    expect(params.restore_budget_on_refund).toBe(false);
  });

  it("операция в клиринге → REFUND: возврат записан, бюджет не восстановлен, одно operation.refunded; GET — REFUNDED", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    const op = `OPKC-PS15-${letters(12)}`;
    expect(await decide(await pay().auth(cart, 60_000, op))).toMatchObject({ decision: "APPROVE" });
    expect(await pi3({ op_ref: op, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await pi3({ op_ref: op, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    expect([await left(cart), await left(intent)]).toEqual([40_000, 40_000]);

    expect(await pi3({ op_ref: op, msg_type: "REFUND", amount: 60_000, currency: "RUB" })).toBe(202);
    expect([await left(cart), await left(intent)], "бюджет не восстановлен (РП9)").toEqual([40_000, 40_000]);
    const feed = (await signedGet("/pao/v1/events")).json() as Feed;
    expect(feed.filter((e) => e.type === "operation.refunded").map((e) => e.data)).toEqual([{ op_ref: op }]);
    expect((await signedGet(`/pao/v1/operations/${op}`)).json()).toMatchObject({ status: "REFUNDED", fulfilment: { final_amount: 60_000 } });
  });
});
