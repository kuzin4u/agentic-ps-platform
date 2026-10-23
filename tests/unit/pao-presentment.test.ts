// Клиринг на стенде (PS-16 ч. 2, РП53 п. 2–10; ПС14): ПИ-3 PRESENTMENT по операции с итогом AUTHORIZED — закрепление
// каждого удержания записи операции (CART и родитель INTENT) суммой представления, остаток освобождается; запись об
// исполнении и одно operation.settled; GET — SETTLED с fulfilment. Раньше ответа эмитента — 503; по отказу — 202 без
// записи; больше одобренной — закреплена одобренная, EXCEEDS_AUTHORIZATION; удержание освобождено — NOT_RESERVED.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { MemoryOperationStore, type OperationRecord } from "../../src/adp/operations.js";
import { MemoryOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { acceptPresentment, fulfilmentRefFor, MemoryFulfilmentStore } from "../../src/fulfilment/records.js";
import type { StateResult } from "../../src/state/index.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-fourteen:v1";
const PRINCIPAL = "prn_ps_fourteen";
const T0 = new Date("2026-10-23T09:00:00Z");
/** Срок резерва стенда (reservation_ttl_sec) и секунда сверху — после него проход срока освобождает удержания. */
const PAST_TTL_MS =
  (JSON.parse(readFileSync(new URL("../../config/params.stand.json", import.meta.url), "utf8")) as { reservation_ttl_sec: number }).reservation_ttl_sec * 1000 + 1_000;

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

  it("одобрение эмитента после прохода срока: итог AUTHORIZED и событие пишутся (эмитент одобрил), нового резерва нет; клиринг — NOT_RESERVED (РП53 п. 11)", async () => {
    const m = await mandates(100_000);
    const o = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pay().auth(m.cart, 60_000, o))).toMatchObject({ decision: "APPROVE" });
    stand.setClock(new Date(stand.now().getTime() + PAST_TTL_MS));
    try {
      expect(await stand.expireReservations()).toBeGreaterThanOrEqual(2);
      expect(await issuer(o, true)).toBe(202);
      expect(await op(o)).toMatchObject({ status: "AUTHORIZED" });
      expect(await present(o, 60_000)).toBe(202);
      expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { scope_check: "NOT_RESERVED", spent_position: 0 } });
    } finally {
      stand.setClock(T0);
    }
  });

  it("spent_position — только по CART операции: два CART под одним INTENT, второй клиринг не включает первый (ревью КТ1 № 5)", async () => {
    const p = pay();
    const intent = await p.mandate({ amount_limit: 200_000 });
    const a: Mandates = { intent, cart: await p.cart(intent, 100_000) };
    const b: Mandates = { intent, cart: await p.cart(intent, 100_000) };
    const oa = await authorized(a, 60_000);
    expect(await present(oa, 60_000)).toBe(202);
    const ob = await authorized(b, 30_000);
    expect(await present(ob, 30_000)).toBe(202);
    expect(await op(oa)).toMatchObject({ fulfilment: { spent_position: 60_000 } });
    expect(await op(ob)).toMatchObject({ fulfilment: { spent_position: 30_000 } });
    expect(await left(intent)).toBe(110_000);
  });

  it("частичное с лимитом клиента: остаток освобождён и на счёте периода клиента (ревью КТ1 № 8)", async () => {
    const principal = `prn_ps14_${randomUUID().slice(0, 8)}`;
    expect((await stand.issuer.setLimits(principal, { per_period: 100_000, period: "DAY", currency: "RUB" }, 1)).statusCode).toBe(200);
    const pp = standPay(stand, side, CODE, principal);
    const cartOf = async () => pp.cart(await pp.mandate({ amount_limit: 100_000 }), 100_000);
    const first = await cartOf();
    const o = `OPKC-PS14-${randomUUID()}`;
    expect(await decide(await pp.auth(first, 60_000, o))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(o, true)).toBe(202);
    expect(await present(o, 45_000)).toBe(202);
    // У клиента за период осталось 55 000: без освобождения остатка клиента — только 40 000.
    const second = await cartOf();
    expect(await decide(await pp.auth(second, 55_001))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect(await decide(await pp.auth(second, 55_000))).toMatchObject({ decision: "APPROVE" });
  });

  it("сбой записи после закрепления, повтор с другой суммой — запись по сумме повтора, событие; бюджет — по первой (решение КТ1 № 1)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    const spy = vi.spyOn(MemoryFulfilmentStore.prototype, "record").mockRejectedValueOnce(new Error("П8 недоступно"));
    try {
      expect(await present(o, 50_000)).toBe(503);
    } finally {
      spy.mockRestore();
    }
    expect(await settled(o)).toEqual([]);
    expect(await left(m.cart), "закреплено 50 000 до сбоя записи").toBe(50_000);
    expect(await present(o, 40_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { final_amount: 40_000, scope_check: "WITHIN_LIMITS", spent_position: 50_000 } });
    expect(await settled(o)).toHaveLength(1);
    expect(await left(m.cart)).toBe(50_000);
    // Тот же сбой и повтор той же суммой — обычный повтор.
    const o2 = await authorized(m, 30_000);
    const spy2 = vi.spyOn(MemoryFulfilmentStore.prototype, "record").mockRejectedValueOnce(new Error("П8 недоступно"));
    try {
      expect(await present(o2, 30_000)).toBe(503);
    } finally {
      spy2.mockRestore();
    }
    expect(await present(o2, 30_000)).toBe(202);
    expect(await op(o2)).toMatchObject({ fulfilment: { final_amount: 30_000, spent_position: 80_000 } });
  });

  it("одновременные представления с разными суммами — одна запись, одно событие, каждое удержание закреплено один раз (ревью КТ1 № 6)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    const codes = await Promise.all([present(o, 50_000), present(o, 40_000)]);
    expect(codes).toEqual([202, 202]);
    expect(await settled(o)).toHaveLength(1);
    const f = (await op(o)).fulfilment as { final_amount: number };
    expect([50_000, 40_000]).toContain(f.final_amount);
    // Каждое удержание закреплено одной из сумм: остаток — 100 000 минус она, не меньше 50 000.
    expect([50_000, 60_000]).toContain(await left(m.cart));
    expect([50_000, 60_000]).toContain(await left(m.intent));
  });

  it("позднее представление: удержание освобождено проходом срока — запись NOT_RESERVED, бюджет не меняется, settled (РП53 п. 6)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    // Срок резерва (reservation_ttl_sec — 7 дней) больше срока мандата: остаток verify после него — 0 по статусу мандата,
    // поэтому «бюджет не изменился» проверяется закреплённым по мандату (spent_position 0) — нового резерва нет.
    stand.setClock(new Date(stand.now().getTime() + PAST_TTL_MS));
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

describe("acceptPresentment — смешанное состояние удержаний и записи до sql/114 (решение КТ1 № 3, ревью № 4)", () => {
  const AT = "2026-10-23T09:00:00.000Z";
  const approve = { decision: "APPROVE", reason: null, decided_in_ms: 1 } as const;
  const hold = (id: string, committed = 0) => ({ id, account: "a", ref: "r", currency: "RUB", amount: 60_000, committed, released: 0, state: "RESERVED", expires_at: null });

  const setup = (rec: OperationRecord, released: readonly string[], committed: number) => {
    const outcomes = new MemoryOutcomeStore(new MemoryOperationStore());
    const fulfilments = new MemoryFulfilmentStore();
    const commits: string[] = [];
    const logs: { msg: string; fields: Record<string, unknown> }[] = [];
    const deps = {
      operations: { get: () => rec },
      outcomes,
      fulfilments,
      state: {
        hold: async (id: string): Promise<StateResult> =>
          released.includes(id) ? { ok: false, code: "RESERVATION_RELEASED" } : ({ ok: true, hold: hold(id) } as StateResult),
        commit: async (id: string): Promise<StateResult> => {
          commits.push(id);
          return { ok: true, hold: hold(id, 1) } as StateResult;
        },
        committed: async () => committed,
      },
      now: () => new Date(AT),
      log: (_l: "info" | "warn", fields: Record<string, unknown>, msg: string) => void logs.push({ msg, fields }),
    };
    return { deps, outcomes, fulfilments, commits, logs };
  };
  const rec = (over: Partial<OperationRecord> = {}): OperationRecord => ({
    op_ref: "OP-mix",
    msg_hash: "h",
    decision: approve,
    mandate_id: "cart",
    holds: ["h-cart", "h-intent", "h-client"],
    at: AT,
    facts: { agent_code: CODE, order_ref: "ORD-1", channel: "CARD", merchant_id: "MER-1042", amount: 60_000, currency: "RUB", aoi: null },
    ...over,
  });

  it("CART освобождён, INTENT и клиент открыты: открытые закреплены, NOT_RESERVED перекрывает EXCEEDS_AUTHORIZATION, spent_position — как прочитано", async () => {
    const s = setup(rec(), ["h-cart"], 0);
    await s.outcomes.record({ op_ref: "OP-mix", agent_code: CODE, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    expect(await acceptPresentment(s.deps, { op_ref: "OP-mix", msg_type: "PRESENTMENT", amount: 70_000, currency: "RUB" })).toBe(202);
    expect(s.commits).toEqual(["h-intent", "h-client"]);
    expect(await s.fulfilments.get("OP-mix")).toMatchObject({ scope_check: "NOT_RESERVED", final_amount: 70_000, spent_position: 0 });
  });

  it("CART закреплён, INTENT освобождён: NOT_RESERVED при ненулевом spent_position", async () => {
    const s = setup(rec(), ["h-intent"], 60_000);
    await s.outcomes.record({ op_ref: "OP-mix", agent_code: CODE, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    expect(await acceptPresentment(s.deps, { op_ref: "OP-mix", msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    expect(s.commits).toEqual(["h-cart", "h-client"]);
    expect(await s.fulfilments.get("OP-mix")).toMatchObject({ scope_check: "NOT_RESERVED", spent_position: 60_000 });
  });

  it("запись до sql/114 без фактов, первое удержание освобождено — 202 и инцидент, без записи (не бесконечный 503)", async () => {
    const s = setup(rec({ facts: undefined }), ["h-cart"], 0);
    await s.outcomes.record({ op_ref: "OP-mix", agent_code: CODE, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    expect(await acceptPresentment(s.deps, { op_ref: "OP-mix", msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    expect(s.commits).toEqual([]);
    expect(await s.fulfilments.get("OP-mix")).toBeUndefined();
    expect(s.logs.some((l) => l.fields.incident === true)).toBe(true);
  });
});
