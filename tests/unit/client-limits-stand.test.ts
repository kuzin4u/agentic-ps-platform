// Стенд: лимит клиента за сутки по часам стенда (PS-20 К1.7, РП45 п. 1, /audit № 3): ADP стенда считает период по
// setClock — те же часы, что резервы, подписи и записи лимитов. Граница суток — 00:00 по client_limit_period_tz.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

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

  const mandate = async (): Promise<string> => {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "продукты",
      amount_limit: 500_000,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: "prn_stand_day",
      mode: "IMMEDIATE",
    };
    const res = await signedInject(stand.app, side, CODE, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(req),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  };
  const auth = (mandate_id: string, amount: number): CanonicalMessage => ({
    op_ref: `OPKC-STAND-DAY-${randomUUID()}`,
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5411" },
    instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
    aoi: { indicator: true, agent_code: CODE, mandate_id },
  });
  const decide = async (m: CanonicalMessage) =>
    parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json(), "adp");

  it("23:59 МСК — счёт 19.10 исчерпан; 00:00 МСК — новый счёт 20.10 (setClock, не системные часы)", async () => {
    const m = await mandate();
    expect((await stand.issuer.setLimits("prn_stand_day", { per_period: 200_000, period: "DAY", currency: "RUB" }, 1)).statusCode).toBe(200);
    stand.setClock(T_EVENING);
    expect(await decide(auth(m, 150_000))).toEqual({ decision: "APPROVE", reason: null });
    expect(await decide(auth(m, 100_000))).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    stand.setClock(T_MIDNIGHT);
    expect(await decide(auth(m, 100_000))).toEqual({ decision: "APPROVE", reason: null });
  });
});
