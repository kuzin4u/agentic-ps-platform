// Стенд: лимит клиента за сутки по часам стенда (PS-20 К1.7, РП45 п. 1, /audit № 3): ADP стенда считает период по
// setClock — те же часы, что резервы, подписи и записи лимитов. Граница суток — 00:00 по client_limit_period_tz.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:limits-stand:v1";
const T_EVENING = new Date("2026-10-19T20:59:00Z"); // 23:59 МСК
const T_MIDNIGHT = new Date("2026-10-19T21:00:00Z"); // 00:00 МСК 20.10

describe("лимит клиента на стенде по часам стенда (РП45 п. 1)", () => {
  let stand: Stand;
  let side: AgentSide;
  beforeAll(() => {
    stand = createStand();
    stand.setClock(new Date("2026-10-19T20:00:00Z"));
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, "prn_stand_day");
  const decide = async (m: CanonicalMessage) =>
    parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json(), "adp");

  it("23:59 МСК — счёт 19.10 исчерпан; 00:00 МСК — новый счёт 20.10 (setClock, не системные часы)", async () => {
    const p = pay();
    const m = await p.cart(await p.mandate({ amount_limit: 500_000 }), 500_000);
    expect((await stand.issuer.setLimits("prn_stand_day", { per_period: 200_000, period: "DAY", currency: "RUB" }, 1)).statusCode).toBe(200);
    stand.setClock(T_EVENING);
    expect(await decide(await p.auth(m, 150_000))).toEqual({ decision: "APPROVE", reason: null });
    expect(await decide(await p.auth(m, 100_000))).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    stand.setClock(T_MIDNIGHT);
    expect(await decide(await p.auth(m, 100_000))).toEqual({ decision: "APPROVE", reason: null });
  });
});
