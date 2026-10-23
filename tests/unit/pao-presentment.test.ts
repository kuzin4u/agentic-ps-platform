// Клиринг на стенде (PS-16 ч. 2, РП53 п. 2–10; ПС14): ПИ-3 PRESENTMENT по операции с итогом AUTHORIZED — закрепление
// каждого удержания записи операции (CART и родитель INTENT) суммой представления, остаток освобождается; запись об
// исполнении и одно operation.settled; GET — SETTLED с fulfilment. Раньше ответа эмитента — 503; по отказу — 202 без
// записи; больше одобренной — закреплена одобренная, EXCEEDS_AUTHORIZATION; удержание освобождено — NOT_RESERVED.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fulfilmentRefFor } from "../../src/fulfilment/records.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-fourteen:v1";
const PRINCIPAL = "prn_ps_fourteen";
const T0 = new Date("2026-10-23T09:00:00Z");

type Feed = readonly { readonly event_id: string; readonly type: string; readonly data: Record<string, unknown> }[];
interface Mandates {
  readonly intent: string;
  readonly cart: string;
}

describe("клиринг PRESENTMENT → закрепление, запись об исполнении, operation.settled на стенде (РП53, ПС14)", () => {
  let stand: Stand;
  let side: AgentSide;
  beforeAll(() => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, PRINCIPAL);
  const mandates = async (limit: number): Promise<Mandates> => {
    const p = pay();
    const intent = await p.mandate({ amount_limit: limit });
    return { intent, cart: await p.cart(intent, limit) };
  };
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const issuer = (op_ref: string, issuer_approved: boolean) => pi3({ op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved });
  const present = (op_ref: string, amount: number, currency = "RUB") => pi3({ op_ref, msg_type: "PRESENTMENT", amount, currency });
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (mandate_id: string): Promise<number> => ((await signedGet(`/pao/v1/mandates/${mandate_id}/verify`)).json() as { amount_left: number }).amount_left;
  const op = async (op_ref: string) => (await signedGet(`/pao/v1/operations/${op_ref}`)).json() as Record<string, unknown>;
  const settled = async (op_ref: string) =>
    ((await signedGet("/pao/v1/events")).json() as Feed).filter((e) => e.type === "operation.settled" && e.data.op_ref === op_ref);
  /** Одобрено ADP и эмитентом: итог AUTHORIZED. */
  const authorized = async (m: Mandates, amount: number): Promise<string> => {
    const op_ref = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pay().auth(m.cart, amount, op_ref))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(op_ref, true)).toBe(202);
    return op_ref;
  };

  it("ПС14 полное: закреплены CART и INTENT, запись WITHIN_LIMITS, одно operation.settled; GET — SETTLED; повтор — без второго закрепления и события", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await present(o, 60_000)).toBe(202);
    const evs = await settled(o);
    expect(evs.map((e) => [e.type, e.data])).toEqual([["operation.settled", { op_ref: o }]]);
    expect(evs[0]!.event_id).toBe(operationEventIdFor(o, "operation.settled"));
    expect(await op(o)).toMatchObject({
      op_ref: o,
      status: "SETTLED",
      reason: null,
      amount: 60_000,
      fulfilment: { fulfilment_ref: fulfilmentRefFor(o), final_amount: 60_000, scope_check: "WITHIN_LIMITS", spent_position: 60_000, at: stand.now().toISOString() },
    });
    expect(fulfilmentRefFor(o)).toMatch(/^ful_[0-9a-f]{24}$/);
    expect(await left(m.cart)).toBe(40_000);
    expect(await left(m.intent)).toBe(40_000);
    expect(await present(o, 60_000)).toBe(202);
    expect(await settled(o)).toHaveLength(1);
    expect(await left(m.cart)).toBe(40_000);
  });

  it("ПС14 частичное: закреплено 45 000 из 60 000, остаток освобождён на CART и INTENT; spent_position — накопленная по CART", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await present(o, 45_000)).toBe(202);
    expect(await left(m.cart)).toBe(55_000);
    expect(await left(m.intent)).toBe(55_000);
    expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { final_amount: 45_000, scope_check: "WITHIN_LIMITS", spent_position: 45_000 } });
    // Освобождённый остаток доступен: вторая операция того же CART на весь остаток — одобрена и закреплена.
    const o2 = await authorized(m, 55_000);
    expect(await present(o2, 55_000)).toBe(202);
    expect(await op(o2)).toMatchObject({ fulfilment: { spent_position: 100_000 } });
    expect(await left(m.cart)).toBe(0);
  });

  it("раньше ответа эмитента — 503 без закрепления; после одобрения — принято (РП53 п. 3 (б))", async () => {
    const m = await mandates(100_000);
    const o = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pay().auth(m.cart, 30_000, o))).toMatchObject({ decision: "APPROVE" });
    expect(await present(o, 30_000)).toBe(503);
    expect(await left(m.cart)).toBe(70_000);
    expect(await settled(o)).toEqual([]);
    expect(await issuer(o, true)).toBe(202);
    expect(await present(o, 30_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "SETTLED" });
  });

  it("по отказу эмитента и по отказу ADP — 202 без записи и без события (инцидент); BYPASS — 202 без действий", async () => {
    const m = await mandates(100_000);
    const no = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pay().auth(m.cart, 30_000, no))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(no, false)).toBe(202);
    expect(await present(no, 30_000)).toBe(202);
    expect(await op(no)).toMatchObject({ status: "DECLINED", reason: "ISSUER_DECLINED", fulfilment: null });
    expect(await settled(no)).toEqual([]);
    expect(await left(m.cart), "отказ эмитента освободил удержание, представление его не закрепило").toBe(100_000);
    const adpNo = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pay().auth(m.cart, 60_000))).toMatchObject({ decision: "APPROVE" });
    expect(await decide(await pay().auth(m.cart, 60_000, adpNo))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect(await present(adpNo, 60_000)).toBe(202);
    expect(await settled(adpNo)).toEqual([]);
    expect(await present(`OPKC-BYPASS-${randomUUID()}`, 1_000)).toBe(202);
  });

  it("больше одобренной — закреплена одобренная (удержание целиком), final_amount — представления, EXCEEDS_AUTHORIZATION, settled (РП53 п. 5)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await present(o, 70_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { final_amount: 70_000, scope_check: "EXCEEDS_AUTHORIZATION", spent_position: 60_000 } });
    expect(await left(m.cart)).toBe(40_000);
    expect(await settled(o)).toHaveLength(1);
  });

  it("форма — 400; валюта не операции — 400 без закрепления; второе представление с другой суммой — 202, запись прежняя", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await pi3({ op_ref: o, msg_type: "PRESENTMENT", amount: 0, currency: "RUB" })).toBe(400);
    expect(await pi3({ op_ref: o, msg_type: "PRESENTMENT", amount: 1.5, currency: "RUB" })).toBe(400);
    expect(await pi3({ op_ref: o, msg_type: "PRESENTMENT", amount: 60_000, currency: "rub" })).toBe(400);
    expect(await pi3({ op_ref: o, msg_type: "PRESENTMENT", amount: 60_000 })).toBe(400);
    expect(await present(o, 60_000, "USD")).toBe(400);
    expect(await left(m.cart)).toBe(40_000);
    expect(await present(o, 50_000)).toBe(202);
    expect(await present(o, 60_000)).toBe(202);
    expect(await op(o)).toMatchObject({ fulfilment: { final_amount: 50_000 } });
    expect(await left(m.cart)).toBe(50_000);
    expect(await settled(o)).toHaveLength(1);
  });

  it("позднее представление: удержание освобождено проходом срока — запись NOT_RESERVED, бюджет не меняется, settled (РП53 п. 6)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    // Срок резерва (reservation_ttl_sec — 7 дней) больше срока мандата: остаток verify после него — 0 по статусу мандата,
    // поэтому «бюджет не изменился» проверяется закреплённым по мандату (spent_position 0) — нового резерва нет.
    stand.setClock(new Date(stand.now().getTime() + 7 * 86_400_000 + 1_000));
    try {
      expect(await stand.expireReservations()).toBeGreaterThanOrEqual(2);
      expect(await present(o, 60_000)).toBe(202);
      expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { final_amount: 60_000, scope_check: "NOT_RESERVED", spent_position: 0 } });
      expect(await settled(o)).toHaveLength(1);
    } finally {
      stand.setClock(T0);
    }
  });
});
