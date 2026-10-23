// П8 Итог операции и события operation.* (PS-16 ч. 1, РП52 п. 1–9, 12, «Дополнения» п. 1–2): сборщик по решённым отказам
// ADP вне пути авторизации, событие — только агенту, установленному по домену токена, data — только {op_ref}, перечень
// причин закрыт, CONFIRMATION_REQUIRED и APPROVE — без operation.*; горизонт ограничивает события, предел задержки —
// признак отставания. Стенд — память; PostgreSQL — operation-outcomes-pg.test.ts.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FACT_MAX_LENGTH, factsOf } from "../../src/adp/decide.js";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import {
  acceptIssuerResponse,
  DECLINE_EVENT_REASONS,
  eventFor,
  ISSUER_DECLINED,
  MemoryOutcomeStore,
  OperationOutcomeCollector,
  outcomeFromDecision,
  type OperationOutcome,
} from "../../src/fulfilment/outcomes.js";
import { confirmationEventIdFor, operationEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { DECISION_REASONS } from "../../src/shared/codes.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-sixteen:v1";
const OTHER = "nspk:agent:ps-sixteen-other:v1";
const PRINCIPAL = "prn_ps_sixteen";
const T0 = new Date("2026-10-22T09:00:00Z");

type Feed = readonly { readonly event_id: string; readonly type: string; readonly data: Record<string, unknown> }[];

describe("итог операции и operation.* на стенде (РП52)", () => {
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  beforeAll(() => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    other = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    expect(stand.admit(buyerApplication(OTHER, other), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, PRINCIPAL);
  const cart = async (limit: number): Promise<string> => {
    const p = pay();
    return p.cart(await p.mandate({ amount_limit: limit }), limit);
  };
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const feedOf = async (s: AgentSide, code: string) =>
    signedInject(stand.app, s, code, { method: "GET", path: "/pao/v1/events", headers: { "idempotency-key": randomUUID() }, now: stand.now() });
  const feed = async (): Promise<Feed> => (await feedOf(side, CODE)).json() as Feed;
  const opEvents = async (op_ref: string) => (await feed()).filter((e) => e.type.startsWith("operation.") && e.data.op_ref === op_ref);
  /** LIMIT_EXCEEDED: CART 100 000, одобрено 60 000, вторая операция на 60 000 — остатка нет (как ПС09). */
  const limitDecline = async (op_ref: string): Promise<void> => {
    const m = await cart(100_000);
    expect(await decide(await pay().auth(m, 60_000))).toMatchObject({ decision: "APPROVE" });
    expect(await decide(await pay().auth(m, 60_000, op_ref))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
  };

  it("LIMIT_EXCEEDED: события нет до прохода сборщика; после — одно operation.declined, data ровно {op_ref}; повтор прохода — без второго", async () => {
    const op = `OPKC-PS16-${randomUUID()}`;
    await limitDecline(op);
    expect(await opEvents(op), "вне пути авторизации: до прохода события нет").toEqual([]);
    const r = await stand.collectOperationOutcomes();
    expect(r.failed).toBe(0);
    const evs = await opEvents(op);
    expect(evs.map((e) => [e.type, e.data])).toEqual([["operation.declined", { op_ref: op }]]);
    expect(evs[0]!.event_id).toBe(operationEventIdFor(op, "operation.declined"));
    await stand.collectOperationOutcomes();
    expect(await opEvents(op)).toHaveLength(1);
    // Номер ленты общий: событие операции — после событий мандатов этого агента.
    const all = await feed();
    expect(all.findIndex((e) => e.data.op_ref === op)).toBeGreaterThan(all.findIndex((e) => e.type === "mandate.signed"));
    // Чужому агенту не видно.
    const theirs = (await feedOf(other, OTHER)).json() as Feed;
    expect(theirs.filter((e) => e.data.op_ref === op)).toEqual([]);
  });

  it("APPROVE — без итога и события (ждёт ответа эмитента, п. 2); CONFIRMATION_REQUIRED — итог без operation.* (п. 3)", async () => {
    const m = await cart(400_000);
    const ok = `OPKC-PS16-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 10_000, ok))).toMatchObject({ decision: "APPROVE" });
    const cr = `OPKC-PS16-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 350_000, cr))).toMatchObject({ decision: "CONFIRMATION_REQUIRED" });
    await stand.collectOperationOutcomes();
    expect(await opEvents(ok)).toEqual([]);
    expect(await opEvents(cr)).toEqual([]);
  });

  it("агент не установлен (токена нет в записях Платформы) — итог пишется, события нет никому (п. 5)", async () => {
    const m = await cart(50_000);
    const op = `OPKC-PS16-${randomUUID()}`;
    const msg = await pay().auth(m, 10_000, op);
    const forged = { ...msg, instrument: { ...msg.instrument, token_ref: "tok_unknown_ps16" } } as CanonicalMessage;
    expect(await decide(forged)).toMatchObject({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    const before = (await stand.collectOperationOutcomes()).recorded;
    expect(before).toBeGreaterThanOrEqual(1);
    expect(await opEvents(op)).toEqual([]);
    expect(((await feedOf(other, OTHER)).json() as Feed).filter((e) => e.data.op_ref === op)).toEqual([]);
  });

  it("AOI_MISMATCH — событие владельцу токена по записи Платформы, а не коду из признака (п. 5, инвариант 5)", async () => {
    const m = await cart(50_000);
    const op = `OPKC-PS16-${randomUUID()}`;
    const msg = await pay().auth(m, 10_000, op);
    const lie = { ...msg, aoi: { ...msg.aoi, agent_code: OTHER } } as CanonicalMessage;
    expect(await decide(lie)).toMatchObject({ decision: "DECLINE", reason: "AOI_MISMATCH" });
    await stand.collectOperationOutcomes();
    expect((await opEvents(op)).map((e) => e.type)).toEqual(["operation.declined"]);
    expect(((await feedOf(other, OTHER)).json() as Feed).filter((e) => e.data.op_ref === op)).toEqual([]);
  });

  it("AGENT_SUSPENDED — событие пишется; лента приостановленному — 403, после снятия событие в ленте (п. 4)", async () => {
    const m = await cart(50_000);
    const op = `OPKC-PS16-${randomUUID()}`;
    const msg = await pay().auth(m, 10_000, op);
    stand.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    try {
      expect(await decide(msg)).toMatchObject({ decision: "DECLINE", reason: "AGENT_SUSPENDED" });
      await stand.collectOperationOutcomes();
      expect((await feedOf(side, CODE)).statusCode).toBe(403);
    } finally {
      stand.registry.changeStatus(CODE, { to: "ACTIVE" });
    }
    expect((await opEvents(op)).map((e) => e.type)).toEqual(["operation.declined"]);
  });

  it("предел задержки: запись старше operation_outcome_max_delay_sec без прохода — признак в /health; проход — событие и признак снят", async () => {
    await stand.collectOperationOutcomes();
    const op = `OPKC-PS16-${randomUUID()}`;
    await limitDecline(op);
    const health = async () => ((await stand.app.inject({ method: "GET", url: "/health" })).json() as { operation_outcome: unknown }).operation_outcome;
    stand.setClock(new Date(stand.now().getTime() + 30_000 + 1));
    expect(await health()).toMatchObject({ lagging: true, code: "OPERATION_OUTCOME_LAGGING" });
    const r = await stand.collectOperationOutcomes();
    // Проход нашёл запись старше предела — признак держится до следующего прохода без отставания.
    expect(r.lagging).toBe(false);
    expect(await health()).toMatchObject({ lagging: false });
    expect(await opEvents(op)).toHaveLength(1);
  });

  const issuer = async (op_ref: string, issuer_approved: unknown, over: Record<string, unknown> = {}) =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved, ...over } })).statusCode;

  it("ПИ-3 ISSUER_RESPONSE одобрен — итог AUTHORIZED и одно operation.authorized сразу, без прохода сборщика; повтор — без второго (п. 2, 8)", async () => {
    const m = await cart(100_000);
    const op = `OPKC-PS16-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 60_000, op))).toMatchObject({ decision: "APPROVE" });
    expect(await opEvents(op), "по APPROVE ADP события нет").toEqual([]);
    expect(await issuer(op, true)).toBe(202);
    expect((await opEvents(op)).map((e) => [e.type, e.data])).toEqual([["operation.authorized", { op_ref: op }]]);
    expect(await issuer(op, true)).toBe(202);
    // Иной второй исход — инцидент, итог и события прежние; удержание не освобождается.
    expect(await issuer(op, false)).toBe(202);
    expect((await opEvents(op)).map((e) => e.type)).toEqual(["operation.authorized"]);
    expect(await decide(await pay().auth(m, 60_000))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
  });

  it("ПИ-3 отказ эмитента — operation.declined ISSUER_DECLINED и удержание освобождено: бюджет снова доступен (п. 3 (б), инвариант 4)", async () => {
    const m = await cart(100_000);
    const op = `OPKC-PS16-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 60_000, op))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(op, false)).toBe(202);
    expect((await opEvents(op)).map((e) => e.type)).toEqual(["operation.declined"]);
    expect(await decide(await pay().auth(m, 60_000))).toMatchObject({ decision: "APPROVE" });
    // Повтор отказа — 202, второго события нет, повторное освобождение не трогает новый резерв.
    expect(await issuer(op, false)).toBe(202);
    expect(await opEvents(op)).toHaveLength(1);
    expect(await decide(await pay().auth(m, 60_000))).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
  });

  it("ПИ-3: op_ref без записи ADP — 202 без действий (инвариант 2); ответ по отказу ADP — 202, итог ADP прежний; форма — 400; CHARGEBACK — 503", async () => {
    expect(await issuer(`OPKC-BYPASS-${randomUUID()}`, true)).toBe(202);
    const op = `OPKC-PS16-${randomUUID()}`;
    await limitDecline(op);
    expect(await issuer(op, true)).toBe(202);
    await stand.collectOperationOutcomes();
    expect((await opEvents(op)).map((e) => e.type)).toEqual(["operation.declined"]);
    expect(await issuer(op, "yes")).toBe(400);
    expect(await issuer("", true)).toBe(400);
    expect((await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload: [] })).statusCode).toBe(400);
    // PRESENTMENT — с ч. 2 (РП53, pao-presentment.test.ts); REVERSAL и AUTH_EXPIRED — с ч. 3 (РП55, pao-reversal.test.ts):
    // по отказу ADP — 202 без действий. REFUND (РП55, pao-refund.test.ts): без суммы — 400, по отказу ADP — 202 и инцидент.
    // CHARGEBACK — до PS-22: 503.
    for (const msg_type of ["REVERSAL", "AUTH_EXPIRED"]) expect(await issuer(op, true, { msg_type }), msg_type).toBe(202);
    expect(await issuer(op, true, { msg_type: "REFUND" })).toBe(400);
    expect(await issuer(op, true, { msg_type: "REFUND", amount: 1_000, currency: "RUB" })).toBe(202);
    expect(await issuer(op, true, { msg_type: "CHARGEBACK" })).toBe(503);
  });

  it("горизонт ограничивает только события: отказ старше operation_outcome_horizon_sec — события нет (итог — GET, К2)", async () => {
    await stand.collectOperationOutcomes();
    const op = `OPKC-PS16-${randomUUID()}`;
    await limitDecline(op);
    stand.setClock(new Date(stand.now().getTime() + 86_400_000 + 1_000));
    await stand.collectOperationOutcomes();
    expect(await opEvents(op)).toEqual([]);
  });
});

describe("правила итога и события (РП52 п. 3, 5–7)", () => {
  const AT = "2026-10-22T09:00:00.000Z";
  const op = (decision: Decision, agent_code: string | null = CODE) => ({ op_ref: "OPKC-1", decision, agent_code, at: AT });
  const declined = (reason: string, agent_code: string | null = CODE): OperationOutcome => ({ op_ref: "OPKC-1", agent_code, status: "DECLINED", reason, source: "ADP", at: AT });

  it("перечень причин — только из кодов ADP и ISSUER_DECLINED; AOI_MISSING, AGENT_UNKNOWN, ADP_UNAVAILABLE, CONFIRMATION_REQUIRED — вне", () => {
    for (const r of DECLINE_EVENT_REASONS) expect(r === ISSUER_DECLINED || (DECISION_REASONS as readonly string[]).includes(r), r).toBe(true);
    for (const r of ["AOI_MISSING", "AGENT_UNKNOWN", "ADP_UNAVAILABLE", "CONFIRMATION_REQUIRED"]) {
      expect(DECLINE_EVENT_REASONS as readonly string[], r).not.toContain(r);
      expect(eventFor(declined(r)), r).toBeUndefined();
    }
  });

  it("событие — только установленному агенту, data — ровно {op_ref}; AUTHORIZED — operation.authorized", () => {
    expect(eventFor(declined("LIMIT_EXCEEDED"))).toEqual({ agent_code: CODE, type: "operation.declined", data: { op_ref: "OPKC-1" }, push: false });
    expect(eventFor(declined("LIMIT_EXCEEDED", null))).toBeUndefined();
    expect(eventFor({ ...declined("x"), status: "AUTHORIZED", reason: null }, () => true)).toEqual({
      agent_code: CODE,
      type: "operation.authorized",
      data: { op_ref: "OPKC-1" },
      push: true,
    });
  });

  it("итог по решению: DECLINE → DECLINED с кодом, CONFIRMATION_REQUIRED — без события, APPROVE — нет итога", () => {
    expect(outcomeFromDecision(op({ decision: "DECLINE", reason: "MANDATE_REVOKED", decided_in_ms: 1 }), AT)).toMatchObject({ status: "DECLINED", reason: "MANDATE_REVOKED", source: "ADP" });
    const cr = outcomeFromDecision(op({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED", decided_in_ms: 1 }), AT)!;
    expect(cr).toMatchObject({ status: "CONFIRMATION_REQUIRED" });
    expect(eventFor(cr)).toBeUndefined();
    expect(outcomeFromDecision(op({ decision: "APPROVE", reason: null, decided_in_ms: 1 }), AT)).toBeUndefined();
  });

  it("event_id операции — своя метка: не совпадает с событием подтверждения того же id; разный у authorized и declined", () => {
    expect(operationEventIdFor("X-1", "operation.declined")).not.toBe(confirmationEventIdFor("X-1", "confirmation.required"));
    expect(operationEventIdFor("X-1", "operation.declined")).not.toBe(operationEventIdFor("X-1", "operation.authorized"));
  });

  it("второй итог по op_ref не пишется и события не даёт: возвращается прежний (п. 8)", async () => {
    const events = new MemoryConsentStore();
    const store = new MemoryOutcomeStore(new MemoryOperationStore(), events);
    const first = declined("LIMIT_EXCEEDED");
    expect(await store.record(first, eventFor(first))).toBeUndefined();
    const second: OperationOutcome = { ...first, status: "AUTHORIZED", reason: null, source: "ISSUER" };
    expect(await store.record(second, eventFor(second))).toEqual(first);
    expect((await events.listEvents(CODE, undefined, 10)).map((e) => e.type)).toEqual(["operation.declined"]);
  });

  it("ПИ-3: запись «в работе» — 503; сбой освобождения — итог записан, 503; повтор после восстановления П3 — освобождение и 202, события одно (РП52 п. 3)", async () => {
    const rec = { op_ref: "OPKC-1", msg_hash: "h", mandate_id: "m", at: AT };
    const events = new MemoryConsentStore();
    const store = new MemoryOutcomeStore(new MemoryOperationStore(), events);
    const logs: string[] = [];
    let p3up = false;
    const released: string[] = [];
    const deps = (decision: Decision | null) => ({
      operations: { get: () => ({ ...rec, decision, holds: ["hold-1"], facts: { agent_code: CODE, order_ref: null, channel: "CARD" as const, merchant_id: null, amount: 1, currency: "RUB", aoi: null } }) },
      store,
      state: {
        release: async (h: string) => {
          if (!p3up) return { ok: false as const, code: "STATE_UNAVAILABLE" as const };
          released.push(h);
          return { ok: false as const, code: "RESERVATION_RELEASED" as const };
        },
      },
      log: (_l: "info" | "warn", _f: Record<string, unknown>, msg: string) => void logs.push(msg),
    });
    const msg = { op_ref: "OPKC-1", msg_type: "ISSUER_RESPONSE", issuer_approved: false };
    expect(await acceptIssuerResponse(deps(null), msg)).toBe(503);
    expect(await store.get("OPKC-1")).toBeUndefined();
    const ok: Decision = { decision: "APPROVE", reason: null, decided_in_ms: 1 };
    expect(await acceptIssuerResponse(deps(ok), msg)).toBe(503);
    expect(await store.get("OPKC-1")).toMatchObject({ status: "DECLINED", reason: ISSUER_DECLINED, source: "ISSUER", agent_code: CODE });
    expect(logs.some((m) => m.includes("не освобождено"))).toBe(true);
    p3up = true;
    expect(await acceptIssuerResponse(deps(ok), msg)).toBe(202);
    expect(released).toEqual(["hold-1"]);
    expect((await events.listEvents(CODE, undefined, 10)).map((e) => e.type)).toEqual(["operation.declined"]);
  });

  it("одобрение эмитента по освобождённому удержанию — итог AUTHORIZED, инцидент; сбой чтения — итог, предупреждение; повтор — без проверки (РП53 п. 11)", async () => {
    const events = new MemoryConsentStore();
    const store = new MemoryOutcomeStore(new MemoryOperationStore(), events);
    const logs: { msg: string; fields: Record<string, unknown> }[] = [];
    const checked: string[] = [];
    const deps = (op_ref: string, hold: "RESERVATION_RELEASED" | "STATE_UNAVAILABLE" | "ok") => ({
      operations: {
        get: () => ({
          op_ref,
          msg_hash: "h",
          mandate_id: "m",
          at: AT,
          decision: { decision: "APPROVE", reason: null, decided_in_ms: 1 } as Decision,
          holds: ["hold-cart", "hold-intent"],
          facts: { agent_code: CODE, order_ref: null, channel: "CARD" as const, merchant_id: null, amount: 1, currency: "RUB", aoi: null },
        }),
      },
      store,
      state: {
        release: async () => ({ ok: false as const, code: "RESERVATION_RELEASED" as const }),
        hold: async (h: string) => {
          checked.push(h);
          return hold === "ok" ? ({ ok: true, hold: {} } as never) : { ok: false as const, code: hold };
        },
      },
      log: (_l: "info" | "warn", fields: Record<string, unknown>, msg: string) => void logs.push({ msg, fields }),
    });
    const msg = (op_ref: string) => ({ op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved: true });
    expect(await acceptIssuerResponse(deps("OP-late", "RESERVATION_RELEASED"), msg("OP-late"))).toBe(202);
    expect(await store.get("OP-late")).toMatchObject({ status: "AUTHORIZED" });
    expect(checked).toEqual(["hold-cart", "hold-intent"]);
    expect(logs.filter((l) => l.fields.incident === true && l.msg.includes("освобождённому")).map((l) => l.fields.hold_id)).toEqual(["hold-cart", "hold-intent"]);
    expect((await events.listEvents(CODE, undefined, 10)).map((e) => e.type)).toEqual(["operation.authorized"]);
    // Повтор того же одобрения — итог прежний, проверки нет.
    expect(await acceptIssuerResponse(deps("OP-late", "RESERVATION_RELEASED"), msg("OP-late"))).toBe(202);
    expect(checked).toHaveLength(2);
    // Сбой чтения — итог записан, предупреждение без инцидента.
    logs.length = 0;
    expect(await acceptIssuerResponse(deps("OP-unread", "STATE_UNAVAILABLE"), msg("OP-unread"))).toBe(202);
    expect(await store.get("OP-unread")).toMatchObject({ status: "AUTHORIZED" });
    expect(logs.some((l) => l.msg.includes("не проверено") && l.fields.incident === undefined)).toBe(true);
    // Удержание открыто — без записей в журнал.
    logs.length = 0;
    expect(await acceptIssuerResponse(deps("OP-held", "ok"), msg("OP-held"))).toBe(202);
    expect(logs).toEqual([]);
  });

  it("факты не по форме — null или поле признака опущено: NUL, одиночный суррогат, длиннее предела, не строка (ревью КТ1 № 1)", () => {
    const base = { op_ref: "OPKC-1", msg_type: "AUTH_REQUEST", channel: "CARD", amount: 1, currency: "RUB", instrument: { kind: "AGENT_TOKEN" } } as CanonicalMessage;
    const f = factsOf(
      {
        ...base,
        order_ref: "ORD-\u0000",
        merchant: { id: "\uDC00MER" } as CanonicalMessage["merchant"],
        aoi: { indicator: "true", agent_code: CODE, mandate_id: 7, fulfilment_ref: "\uD800x", deal_ref: "d".repeat(FACT_MAX_LENGTH + 1), extra: "x" } as unknown as CanonicalMessage["aoi"],
      },
      CODE,
    );
    expect(f).toEqual({ agent_code: CODE, order_ref: null, channel: "CARD", merchant_id: null, amount: 1, currency: "RUB", aoi: { agent_code: CODE } });
    // Пара суррогатов (эмодзи) и строка ровно предела — по форме.
    const ok = factsOf({ ...base, order_ref: "ORD-😀", aoi: { indicator: true, deal_ref: "d".repeat(FACT_MAX_LENGTH) } }, null);
    expect(ok).toMatchObject({ order_ref: "ORD-😀", aoi: { indicator: true, deal_ref: "d".repeat(FACT_MAX_LENGTH) } });
    expect(factsOf({ ...base, channel: "QR" as "CARD" }, null).channel).toBeNull();
  });

  it("проход без отставания: событие не позже предела; проход не завершался дольше предела — признак отставания", async () => {
    let now = Date.parse(AT);
    const c = new OperationOutcomeCollector(new MemoryOutcomeStore(new MemoryOperationStore()), { horizonSec: 86_400, maxDelaySec: 30, now: () => now });
    expect(c.health()).toMatchObject({ lagging: false, last_pass_at: null });
    now += 30_000 + 1;
    expect(c.health()).toMatchObject({ lagging: true, code: "OPERATION_OUTCOME_LAGGING" });
    await c.runOnce();
    expect(c.health()).toMatchObject({ lagging: false });
  });
});
