// ПС25 «Приостановление агента» на стенде (PS-17, РП54; ФП15; A2 п. 7, A3 п. 6.1–6.3, A4 п. 5.2): повторные выходы за
// мандат → оператор Системы приостанавливает агента одним действием → все токены агента блокированы в ADP
// (AGENT_SUSPENDED), выдача реквизитов — 403, событие agent.suspended; распространение до ADP и шлюза ПАО ≤
// revocation_propagation_max_ms (инвариант 8); неагентские операции не затронуты (инвариант 2); авторизованное до
// приостановления исполняется (A3 п. 6.2). После снятия — лента с накопленным, реквизит до приостановления не действует
// (РП54 п. 5, 10). Исключённому — тот же отказ ADP и шлюза (условие переноса исключения в PS-32, РП54 п. 12).
// Приостановление — действием оператора стенда (stand.suspendAgent, РП54 п. 1), не правкой реестра. Исключение —
// stand.registry.changeStatus: служба исключения и HTTP оператора — PS-32. Сообщения процессинга — прямо в ADP и ПИ-3
// стенда (путь эквайрер → ОПКЦ — PS-11).
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { agentStatusEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Event } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { STAND_AGENT_EMULATOR_HOST } from "../../src/stand/dns.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay, type StandPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-25:v1";
const OTHER = "nspk:agent:ps-25-other:v1";
const T0 = new Date("2026-10-23T09:00:00Z");
const URL_OK = `https://${STAND_AGENT_EMULATOR_HOST}/pao/events`;

describe("ПС25 на стенде: приостановление агента (РП54, ФП15)", () => {
  let stand: Stand;
  let side: AgentSide;
  let pay: StandPay;
  let carts: [string, string];
  let other: StandPay;
  let otherCart: string;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    const put = await call("PUT", "/pao/v1/subscription", { url: URL_OK, events: ["agent.suspended", "agent.reinstated", "operation.declined", "operation.settled"] });
    expect(put.statusCode).toBe(200);
    pay = standPay(stand, side, CODE, "prn_ps25");
    // Два мандата — два токена агента (по токену на CART, РП47 п. 2): блокируются оба.
    carts = [await pay.cart(await pay.mandate({ amount_limit: 200_000 }), 100_000), await pay.cart(await pay.mandate({ amount_limit: 200_000 }), 100_000)];
    // Другой агент того же оператора — приостановление его не касается.
    const otherSide = newAgentSide();
    expect((await stand.admit(buyerApplication(OTHER, otherSide), "op")).admitted).toBe(true);
    other = standPay(stand, otherSide, OTHER, "prn_ps25_other");
    otherCart = await other.cart(await other.mandate({ amount_limit: 200_000 }), 100_000);
  });
  afterAll(async () => stand.close());

  function call(method: "GET" | "POST" | "PUT", path: string, body?: unknown) {
    return signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: method === "GET" ? {} : { "idempotency-key": randomUUID() },
      now: stand.now(),
    });
  }
  const decide = async (m: CanonicalMessage) =>
    parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json(), "adp");
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const credential = (mandate_id: string) =>
    call("POST", "/pao/v1/credentials", { mandate_id, order_ref: `ORD-${randomUUID()}`, merchant_id: "MER-1042", amount_max: 10_000, currency: "RUB", kind: "CARD" });
  const plain = (op_ref: string): CanonicalMessage => ({
    op_ref,
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount: 10_000,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5462" },
    instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_ps25" },
  });
  const tick = (ms: number) => stand.setClock(new Date(stand.now().getTime() + ms));

  it("доказательный: приостановление одним действием — оба токена AGENT_SUSPENDED, реквизит 403, agent.suspended; ≤ revocation_propagation_max_ms; неагентские и другой агент не затронуты; авторизованное до — исполняется; после снятия — лента и отсечка", async () => {
    const max = stand.params.revocation_propagation_max_ms;
    // До приостановления: реквизиты на оба токена и одна авторизация одобрена ADP (ответа эмитента ещё нет).
    const pending = [await pay.auth(carts[0], 10_000), await pay.auth(carts[1], 10_000)];
    const authorizedOp = `OPKC-PS25-A-${randomUUID()}`;
    expect(await decide(await pay.auth(carts[0], 20_000, authorizedOp))).toEqual({ decision: "APPROVE", reason: null });

    // Действие оператора: основание A2 п. 7.1 — повторные операции вне мандатов (A4 п. 5.2).
    tick(1_000);
    const start = performance.now();
    const rec = await stand.suspendAgent(CODE, "OUT_OF_MANDATE");
    const [d0, d1] = [await decide({ ...pending[0]!, op_ref: "OPKC-PS25-1" }), await decide({ ...pending[1]!, op_ref: "OPKC-PS25-2" })];
    const adpMs = performance.now() - start;
    const issue = await credential(carts[1]);
    const gatewayMs = performance.now() - start;
    expect(rec).toMatchObject({ status: "SUSPENDED", status_ground: "OUT_OF_MANDATE" });
    expect([d0, d1]).toEqual([
      { decision: "DECLINE", reason: "AGENT_SUSPENDED" },
      { decision: "DECLINE", reason: "AGENT_SUSPENDED" },
    ]);
    expect(issue.statusCode).toBe(403);
    expect((issue.json() as { code: string }).code).toBe("AGENT_SUSPENDED");
    expect(adpMs, "приостановление → отказ ADP (инвариант 8)").toBeLessThanOrEqual(max);
    expect(gatewayMs, "приостановление → отказ шлюза ПАО (инвариант 8)").toBeLessThanOrEqual(max);

    // Приостановленному открыт только свой статус и отказ от полномочий (РП38 доп. п. 8).
    expect(((await call("GET", "/pao/v1/agent")).json() as { status: string }).status).toBe("SUSPENDED");
    expect((await call("GET", "/pao/v1/events")).statusCode).toBe(403);
    // agent.suspended — push-ем приостановленному (РП54 п. 9), data — только {agent_code}.
    await stand.collectOperationOutcomes();
    await stand.deliverEvents();
    expect(stand.agentReceiver.handled).toEqual([{ event_id: agentStatusEventIdFor(CODE, 2), type: "agent.suspended", at: stand.now().toISOString(), data: { agent_code: CODE } }]);

    // Неагентская операция и другой агент не затронуты (инвариант 2; приостановление — одного агента).
    expect(await decide(plain("OPKC-PS25-PLAIN"))).toEqual({ decision: "BYPASS", reason: null });
    expect(await decide(await other.auth(otherCart, 10_000))).toEqual({ decision: "APPROVE", reason: null });

    // Авторизованное до приостановления исполняется (A3 п. 6.2): ответ эмитента и клиринг — после.
    expect(await pi3({ op_ref: authorizedOp, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await pi3({ op_ref: authorizedOp, msg_type: "PRESENTMENT", amount: 20_000, currency: "RUB" })).toBe(202);

    // Снятие: действует сразу; лента с накопленным по порядку; push по накопленным не догоняет.
    tick(1_000);
    const back = performance.now();
    await stand.reinstateAgent(CODE);
    const fresh = await pay.auth(carts[1], 10_000, "OPKC-PS25-3");
    expect(await decide(fresh)).toEqual({ decision: "APPROVE", reason: null });
    expect(performance.now() - back, "снятие → одобрение (инвариант 8)").toBeLessThanOrEqual(max);
    const all = (await call("GET", "/pao/v1/events")).json() as Event[];
    const feed = all.slice(all.findIndex((e) => e.type === "agent.suspended"));
    expect(feed.map((e) => [e.type, e.data])).toEqual([
      ["agent.suspended", { agent_code: CODE }],
      ["operation.declined", { op_ref: "OPKC-PS25-1" }],
      ["operation.declined", { op_ref: "OPKC-PS25-2" }],
      ["operation.authorized", { op_ref: authorizedOp }],
      ["operation.settled", { op_ref: authorizedOp }],
      ["agent.reinstated", { agent_code: CODE }],
    ]);
    expect(((await call("GET", "/pao/v1/operations/OPKC-PS25-1")).json() as { reason: string }).reason).toBe("AGENT_SUSPENDED");
    await stand.deliverEvents();
    expect(stand.agentReceiver.handled.map((e) => e.type)).toEqual(["agent.suspended", "agent.reinstated"]);

    // Реквизит, выданный до приостановления, не действует и после снятия (РП54 п. 5, отсечка).
    expect(await decide({ ...pending[0]!, op_ref: "OPKC-PS25-4" })).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
  });

  it("исключённому — тот же отказ ADP и шлюза ПАО, что приостановленному (условие переноса в PS-32, РП54 п. 12): ADP — AGENT_UNKNOWN, 403 на реквизит и relinquish, push нет", async () => {
    const code = "nspk:agent:ps-25-excl:v1";
    const s = newAgentSide();
    expect((await stand.admit(buyerApplication(code, s), "op")).admitted).toBe(true);
    const p = standPay(stand, s, code, "prn_ps25_excl");
    const cart = await p.cart(await p.mandate({ amount_limit: 200_000 }), 100_000);
    const msg = await p.auth(cart, 10_000);
    const signed = (method: "GET" | "POST" | "PUT", path: string, body?: unknown) =>
      signedInject(stand.app, s, code, {
        method,
        path,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        headers: method === "GET" ? {} : { "idempotency-key": randomUUID() },
        now: stand.now(),
      });
    // Подписан на mandate.signed; мандат ждёт подписи банка до исключения — событие придёт уже после.
    expect((await signed("PUT", "/pao/v1/subscription", { url: URL_OK, events: ["mandate.signed"] })).statusCode).toBe(200);
    const unsigned = await signed("POST", "/pao/v1/mandates", {
      type: "INTENT",
      subject: "s",
      amount_limit: 1_000,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: "prn_ps25_excl",
      mode: "IMMEDIATE",
    });
    expect(unsigned.statusCode).toBe(201);
    const pendingId = (unsigned.json() as { id: string }).id;
    await stand.deliverEvents();
    // Исключение — служба PS-32; здесь — переход реестра по РП21 п. 4.
    await stand.registry.changeStatus(code, { to: "EXCLUDED", ground: "OUT_OF_MANDATE" });

    expect(await decide({ ...msg, op_ref: "OPKC-PS25-X1" })).toEqual({ decision: "DECLINE", reason: "AGENT_UNKNOWN" });
    const issue = await signed("POST", "/pao/v1/credentials", { mandate_id: cart, order_ref: "ORD-ps25-x", merchant_id: "MER-1042", amount_max: 10_000, currency: "RUB", kind: "CARD" });
    expect([issue.statusCode, (issue.json() as { code: string }).code]).toEqual([403, "AGENT_SUSPENDED"]);
    const relinquish = await signed("POST", `/pao/v1/mandates/${cart}/relinquish`);
    expect([relinquish.statusCode, (relinquish.json() as { code: string }).code]).toEqual([403, "AGENT_SUSPENDED"]);
    expect((await signed("GET", "/pao/v1/events")).statusCode).toBe(403);
    expect(((await signed("GET", "/pao/v1/agent")).json() as { status: string }).status).toBe("EXCLUDED");
    // Банк подписывает мандат уже после исключения: событие в ленте, push исключённому не выполняется (РП40 п. 7).
    expect((await stand.issuer.sign(pendingId)).statusCode).toBe(200);
    await stand.deliverEvents();
    expect(stand.agentReceiver.received.filter((d) => (d.event as Event | undefined)?.data.mandate_id === pendingId)).toEqual([]);
  });
});
