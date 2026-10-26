// Реверсал и истечение авторизации (PS-16 ч. 3, РП55 п. 1–2, 5; ПС13): ПИ-3 REVERSAL / AUTH_EXPIRED по операции с APPROVE
// ADP без клиринга — освобождение каждого удержания записи операции (CART и родитель INTENT), запись, GET — REVERSED с
// reason; событий operation.* нет до ПАО 1.5.0. До ответа эмитента — тоже, ответ эмитента после — инцидент без итога.
// После клиринга — 202 без изменения. Перестановка — 503 и инцидент за event_reorder_window_ms.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { acceptOperationEvent, MemoryFulfilmentStore } from "../../src/fulfilment/records.js";
import { MemoryOpLock } from "../../src/fulfilment/oplock.js";
import { acceptReversal, MemoryReversalStore } from "../../src/fulfilment/reversals.js";
import type { StateResult } from "../../src/state/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-thirteen:v1";
const T0 = new Date("2026-10-23T12:00:00Z");

type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];
interface Mandates {
  readonly intent: string;
  readonly cart: string;
}

const opRef = (): string => `OPKC-REV-${letters(12)}`;

describe("реверсал и истечение авторизации → освобождение и REVERSED на стенде (РП55, ПС13)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_rev_");
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, principal);
  const mandates = async (limit: number): Promise<Mandates> => {
    const p = pay();
    const intent = await p.mandate({ amount_limit: limit });
    return { intent, cart: await p.cart(intent, limit) };
  };
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const issuer = (op_ref: string, issuer_approved: boolean) => pi3({ op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved });
  const reverse = (op_ref: string, msg_type = "REVERSAL", extra: Record<string, unknown> = {}) => pi3({ op_ref, msg_type, ...extra });
  const present = (op_ref: string, amount: number) => pi3({ op_ref, msg_type: "PRESENTMENT", amount, currency: "RUB" });
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (mandate_id: string): Promise<number> => ((await signedGet(`/pao/v1/mandates/${mandate_id}/verify`)).json() as { amount_left: number }).amount_left;
  const op = async (op_ref: string) => (await signedGet(`/pao/v1/operations/${op_ref}`)).json() as Record<string, unknown>;
  const opEvents = async (op_ref: string) =>
    ((await signedGet("/pao/v1/events")).json() as Feed).filter((e) => e.type.startsWith("operation.") && e.data.op_ref === op_ref).map((e) => e.type);
  const approved = async (m: Mandates, amount: number): Promise<string> => {
    const op_ref = opRef();
    expect(await decide(await pay().auth(m.cart, amount, op_ref))).toMatchObject({ decision: "APPROVE" });
    return op_ref;
  };
  const authorized = async (m: Mandates, amount: number): Promise<string> => {
    const op_ref = await approved(m, amount);
    expect(await issuer(op_ref, true)).toBe(202);
    return op_ref;
  };

  it("ПС13: REVERSAL освобождает удержания CART и INTENT, остаток восстановлен; GET — REVERSED / REVERSAL; повтор не меняет состояние; события нет", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await left(m.cart)).toBe(40_000);
    expect(await reverse(o)).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
    expect(await left(m.intent)).toBe(100_000);
    expect(await op(o)).toMatchObject({ op_ref: o, status: "REVERSED", reason: "REVERSAL", amount: 60_000, fulfilment: null });
    expect(await reverse(o)).toBe(202);
    expect(await reverse(o, "AUTH_EXPIRED")).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
    expect(await op(o)).toMatchObject({ status: "REVERSED", reason: "REVERSAL" });
    expect(await opEvents(o), "operation.reversed — с ПАО 1.5.0 (РП55 п. 2)").toEqual(["operation.authorized"]);
    // Освобождённый бюджет доступен: новая операция на весь предел одобрена.
    expect(await decide(await pay().auth(m.cart, 100_000, opRef()))).toMatchObject({ decision: "APPROVE" });
  });

  it("AUTH_EXPIRED — так же, reason AUTH_EXPIRED", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 30_000);
    expect(await reverse(o, "AUTH_EXPIRED")).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
    expect(await op(o)).toMatchObject({ status: "REVERSED", reason: "AUTH_EXPIRED" });
  });

  it("реверсал до ответа эмитента: освобождено, REVERSED; ответ эмитента после — 202 без итога и без события", async () => {
    const m = await mandates(100_000);
    const o = await approved(m, 50_000);
    expect(await reverse(o)).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
    expect(await op(o)).toMatchObject({ status: "REVERSED", reason: "REVERSAL" });
    expect(await issuer(o, true)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "REVERSED" });
    expect(await opEvents(o)).toEqual([]);
  });

  it("после клиринга — 202, закреплённое не трогается, SETTLED; клиринг после реверсала — NOT_RESERVED, GET — SETTLED (клиринг старше, КТ1 п. 3)", async () => {
    const m = await mandates(100_000);
    const s = await authorized(m, 40_000);
    expect(await present(s, 40_000)).toBe(202);
    expect(await reverse(s)).toBe(202);
    expect(await left(m.cart)).toBe(60_000);
    expect(await op(s)).toMatchObject({ status: "SETTLED" });
    const r = await authorized(m, 20_000);
    expect(await reverse(r)).toBe(202);
    expect(await present(r, 20_000)).toBe(202);
    expect(await left(m.cart)).toBe(60_000);
    expect(await op(r)).toMatchObject({ status: "SETTLED", reason: null, fulfilment: { final_amount: 20_000, scope_check: "NOT_RESERVED" } });
    expect(await opEvents(r)).toEqual(["operation.authorized", "operation.settled"]);
  });

  it("реверсал до ответа эмитента, затем ответ эмитента и клиринг — клиринг не ждёт итога: NOT_RESERVED, без бесконечного 503 (КТ1 п. 3)", async () => {
    const m = await mandates(100_000);
    const o = await approved(m, 30_000);
    expect(await reverse(o)).toBe(202);
    expect(await issuer(o, true)).toBe(202);
    expect(await present(o, 30_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "SETTLED", fulfilment: { scope_check: "NOT_RESERVED" } });
    expect(await opEvents(o)).toEqual(["operation.settled"]);
    expect(await left(m.cart), "бюджет не учёл списание — NOT_RESERVED, основание для спора").toBe(100_000);
  });

  it("валюта реверсала не валюта операции — 400 без освобождения (КТ1 п. 4)", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await reverse(o, "REVERSAL", { amount: 60_000, currency: "USD" })).toBe(400);
    expect(await reverse(o, "REVERSAL", { currency: "rub" })).toBe(400);
    expect(await left(m.cart)).toBe(40_000);
    expect(await reverse(o, "REVERSAL", { currency: "RUB" })).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
  });

  it("ПС13 с лимитом клиента: реверсал восстанавливает и остаток счёта периода клиента (КТ1 п. 5)", async () => {
    const p = opaquePrincipalRef("prn_rev_cl_");
    const limits = await stand.issuer.setLimits(p, { per_period: 100_000, period: "DAY", currency: "RUB" }, 1);
    expect(limits.statusCode, `setLimits ${p}: ${JSON.stringify(limits.body)}`).toBe(200);
    const pp = standPay(stand, side, CODE, p);
    const cartOf = async () => pp.cart(await pp.mandate({ amount_limit: 100_000 }), 100_000);
    const first = await cartOf();
    const o = opRef();
    expect(await decide(await pp.auth(first, 70_000, o))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(o, true)).toBe(202);
    const second = await cartOf();
    expect(await decide(await pp.auth(second, 30_001)), "до реверсала у клиента 30 000").toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect(await reverse(o)).toBe(202);
    expect(await decide(await pp.auth(second, 100_000)), "после реверсала у клиента снова 100 000").toMatchObject({ decision: "APPROVE" });
  });

  it("по отказу эмитента и по отказу ADP — 202 без действий; BYPASS — 202", async () => {
    const m = await mandates(100_000);
    const no = await approved(m, 30_000);
    expect(await issuer(no, false)).toBe(202);
    expect(await reverse(no)).toBe(202);
    expect(await op(no)).toMatchObject({ status: "DECLINED", reason: "ISSUER_DECLINED" });
    const adpNo = opRef();
    expect(await decide(await pay().auth(m.cart, 60_000))).toMatchObject({ decision: "APPROVE" });
    expect(await decide(await pay().auth(m.cart, 60_000, adpNo))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect(await reverse(adpNo)).toBe(202);
    expect(await reverse(`OPKC-BYPASS-${letters(12)}`)).toBe(202);
  });

  it("частичного реверсала нет: amount ≠ одобренной — 400 без освобождения; amount не по форме — 400; равная — освобождено", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 60_000);
    expect(await reverse(o, "REVERSAL", { amount: 30_000, currency: "RUB" })).toBe(400);
    expect(await reverse(o, "REVERSAL", { amount: 0 })).toBe(400);
    expect(await reverse(o, "REVERSAL", { amount: "60000" })).toBe(400);
    expect(await left(m.cart)).toBe(40_000);
    expect(await op(o)).toMatchObject({ status: "AUTHORIZED" });
    expect(await reverse(o, "REVERSAL", { amount: 60_000, currency: "RUB" })).toBe(202);
    expect(await left(m.cart)).toBe(100_000);
  });

  it("CHARGEBACK — 503 до PS-22", async () => {
    const m = await mandates(100_000);
    const o = await authorized(m, 10_000);
    expect(await pi3({ op_ref: o, msg_type: "CHARGEBACK" })).toBe(503);
  });
});

describe("ПИ-3 без стенда: перестановка, гонка с клирингом, сбой П3 (РП55 п. 1, 5)", () => {
  const AT = "2026-10-23T12:00:00.000Z";
  const OP = "OPKC-REV-UNIT";
  const setup = async () => {
    const operations = new MemoryOperationStore();
    await operations.begin(OP, "a".repeat(64), AT);
    await operations.finish({
      op_ref: OP,
      msg_hash: "a".repeat(64),
      decision: { decision: "APPROVE", reason: null, reservation_id: "h1", decided_in_ms: 1 },
      mandate_id: "mnd_u",
      holds: ["h1", "h2"],
      at: AT,
      facts: { agent_code: CODE, order_ref: "ORD-u", channel: "CARD", merchant_id: "MER-1", amount: 10_000, currency: "RUB", aoi: null },
    });
    return { operations, outcomes: new MemoryOutcomeStore(operations), fulfilments: new MemoryFulfilmentStore(), reversals: new MemoryReversalStore() };
  };
  const logs = () => {
    const out: { level: string; fields: Record<string, unknown> }[] = [];
    return { out, log: (level: "info" | "warn", fields: Record<string, unknown>) => void out.push({ level, fields }) };
  };
  const hold = (id: string, committed = 0): StateResult => ({ ok: true, hold: { id, account: "a", ref: "r", currency: "RUB", amount: 10_000, committed, released: 10_000 - committed, state: "RELEASED", expires_at: null } }) as StateResult;

  it("PRESENTMENT раньше ответа эмитента: в окне — 503 без инцидента, за окном — 503 и инцидент", async () => {
    const s = await setup();
    const state = { release: async () => hold("h"), hold: async () => hold("h"), commit: async () => hold("h"), committed: async () => 0 };
    const msg = { op_ref: OP, msg_type: "PRESENTMENT", amount: 10_000, currency: "RUB" };
    const inWindow = logs();
    const at = (ms: number) => () => new Date(Date.parse(AT) + ms);
    expect(await acceptOperationEvent({ ...s, store: s.outcomes, state, now: at(5_000), log: inWindow.log, reorder_window_ms: 5_000 }, msg)).toBe(503);
    expect(inWindow.out.filter((l) => l.fields.incident === true)).toEqual([]);
    const late = logs();
    expect(await acceptOperationEvent({ ...s, store: s.outcomes, state, now: at(5_001), log: late.log, reorder_window_ms: 5_000 }, msg)).toBe(503);
    expect(late.out).toEqual([expect.objectContaining({ level: "warn", fields: expect.objectContaining({ op_ref: OP, missing: "ISSUER_RESPONSE", incident: true }) })]);
  });

  /** Открытое удержание: ничего не закреплено и не освобождено. */
  const open = (id: string): StateResult => ({ ok: true, hold: { id, account: "a", ref: "r", currency: "RUB", amount: 10_000, committed: 0, released: 0, state: "RESERVED", expires_at: null } }) as StateResult;

  it("CART закреплён, INTENT свободен — ничего не освобождено, реверсал не записан, инцидент (КТ1 п. 2; блокер № 1)", async () => {
    const s = await setup();
    const l = logs();
    const released: string[] = [];
    const state = {
      hold: async (id: string) => (id === "h1" ? hold(id, 10_000) : open(id)),
      release: async (id: string) => {
        released.push(id);
        return hold(id);
      },
    };
    expect(await acceptReversal({ ...s, state, log: l.log }, { op_ref: OP, msg_type: "REVERSAL" })).toBe(202);
    expect(released, "освобождение INTENT вернуло бы бюджет списанной операции (инвариант 4)").toEqual([]);
    expect(await s.reversals.get(OP)).toBeUndefined();
    expect(l.out.some((x) => x.fields.incident === true)).toBe(true);
  });

  it("сначала запись, затем освобождение: сбой П3 — 503, запись есть; ответ эмитента после — без итога; повтор освобождает снова (КТ1 п. 2; № 4)", async () => {
    const s = await setup();
    const released: string[] = [];
    let fail = true;
    const state = {
      hold: async (id: string) => open(id),
      release: async (id: string): Promise<StateResult> => {
        if (fail && id === "h2") return { ok: false, code: "STATE_UNAVAILABLE" } as StateResult;
        released.push(id);
        return released.filter((x) => x === id).length > 1 ? ({ ok: false, code: "RESERVATION_RELEASED" } as StateResult) : hold(id);
      },
    };
    const deps = { ...s, state, now: () => new Date(AT) };
    expect(await acceptReversal(deps, { op_ref: OP, msg_type: "AUTH_EXPIRED" })).toBe(503);
    expect(await s.reversals.get(OP)).toEqual({ op_ref: OP, kind: "AUTH_EXPIRED", agent_code: CODE, mandate_id: "mnd_u", at: AT });
    // Ответ эмитента между сбоем и повтором видит реверсал: итог не пишется (№ 4).
    const full = { ...state, commit: async (id: string) => hold(id), committed: async () => 0 };
    expect(await acceptOperationEvent({ ...s, store: s.outcomes, state: full }, { op_ref: OP, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await s.outcomes.get(OP)).toBeUndefined();
    fail = false;
    expect(await acceptReversal(deps, { op_ref: OP, msg_type: "AUTH_EXPIRED" })).toBe(202);
    expect(released).toEqual(["h1", "h1", "h2"]);
  });

  it("очередь по op_ref: обработчики одной операции не пересекаются, разных — идут параллельно (КТ1 п. 1)", async () => {
    const lock = new MemoryOpLock();
    const trace: string[] = [];
    const step = (name: string, ms: number) => async () => {
      trace.push(`${name}:start`);
      await new Promise((r) => setTimeout(r, ms));
      trace.push(`${name}:end`);
      return name;
    };
    const [a, b, c] = await Promise.all([lock.run("op1", step("a", 20)), lock.run("op1", step("b", 1)), lock.run("op2", step("c", 1))]);
    expect([a, b, c]).toEqual(["a", "b", "c"]);
    expect(trace.indexOf("a:end")).toBeLessThan(trace.indexOf("b:start"));
    expect(trace.indexOf("c:end")).toBeLessThan(trace.indexOf("a:end"));
    // Сбой обработчика не останавливает очередь.
    await expect(lock.run("op1", async () => Promise.reject(new Error("сбой")))).rejects.toThrow("сбой");
    expect(await lock.run("op1", async () => "после")).toBe("после");
  });

  it("запись «в работе» — 503; без хранилища реверсалов (до ч. 3) — 503", async () => {
    const operations = new MemoryOperationStore();
    await operations.begin("OPKC-REV-WIP", "b".repeat(64), AT);
    const outcomes = new MemoryOutcomeStore(operations);
    const state = { release: async () => hold("h"), hold: async () => hold("h"), commit: async () => hold("h"), committed: async () => 0 };
    const reversals = new MemoryReversalStore();
    expect(await acceptOperationEvent({ operations, store: outcomes, state, reversals }, { op_ref: "OPKC-REV-WIP", msg_type: "REVERSAL" })).toBe(503);
    const s = await setup();
    expect(await acceptOperationEvent({ operations: s.operations, store: s.outcomes, state }, { op_ref: OP, msg_type: "REVERSAL" })).toBe(503);
  });
});

describe("ПИ-3 в main.ts — только вместе с SEC-1-кодом (РП55 п. 8)", () => {
  it("main.ts не подключает ПИ-3: поддельный REVERSAL освободил бы бюджет", async () => {
    const { readFileSync } = await import("node:fs");
    const main = readFileSync(new URL("../../src/main.ts", import.meta.url), "utf8");
    expect(main).not.toMatch(/adp\/v1\/events|acceptOperationEvent|acceptReversal|acceptPresentment|acceptIssuerResponse/);
    expect(main).not.toMatch(/ReversalStore|FulfilmentStore/);
    expect(main).not.toMatch(/\badp\s*:|adpRoutes/);
  });
});
