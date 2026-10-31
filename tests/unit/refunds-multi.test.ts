// Несколько возвратов по операции (PS-23 ч. 1, РП71 п. 1–6, нюанс 1): refund_ref в REFUND ПИ-3. Без ссылки — РП55 п. 3
// (ПС15 и pao-refund — без правки); со ссылкой — запись на пару (op_ref, refund_ref), повтор — без изменения, та же
// ссылка с другой суммой или валютой — инцидент, запись прежняя; смешение форм — инцидент без записи; сумма возвратов
// больше клиринга — запись и инцидент; событие — одно; бюджет не восстанавливается. В памяти и на стенде; PG —
// refunds-pg.test.ts.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { fulfilmentRefFor, MemoryFulfilmentStore, type FulfilmentRecord } from "../../src/fulfilment/records.js";
import { acceptRefund, classifyRefund, MemoryRefundStore, type RefundRecord } from "../../src/fulfilment/refunds.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:refund-multi:v1";
const AT = "2026-10-31T13:00:00.000Z";

describe("classifyRefund — ключ и форма (РП71 п. 2–3, нюанс 1)", () => {
  const r = (refund_ref: string | null, amount = 1_000, currency = "RUB"): RefundRecord => ({
    op_ref: "OP",
    refund_ref,
    agent_code: CODE,
    mandate_id: "mnd",
    amount,
    currency,
    at: AT,
  });

  it("пусто — вставлять; новая ссылка — вставлять; та же — повтор или конфликт; другая форма — mixed", () => {
    expect(classifyRefund([], r(null))).toBeUndefined();
    expect(classifyRefund([], r("R1"))).toBeUndefined();
    expect(classifyRefund([r("R1")], r("R2"))).toBeUndefined();
    expect(classifyRefund([r("R1")], r("R1"))).toEqual({ kind: "duplicate", prior: r("R1") });
    expect(classifyRefund([r("R1")], r("R1", 2_000))).toEqual({ kind: "conflict", prior: r("R1") });
    expect(classifyRefund([r("R1")], r("R1", 1_000, "USD"))).toEqual({ kind: "conflict", prior: r("R1") });
    expect(classifyRefund([r(null)], r(null))).toEqual({ kind: "duplicate", prior: r(null) });
    expect(classifyRefund([r(null)], r(null, 2_000))).toEqual({ kind: "conflict", prior: r(null) });
    expect(classifyRefund([r(null)], r("R1"))).toEqual({ kind: "mixed", first: r(null) });
    expect(classifyRefund([r("R1")], r(null))).toEqual({ kind: "mixed", first: r("R1") });
  });
});

describe("acceptRefund с refund_ref в памяти (РП71)", () => {
  const OP = "OPKC-REF-MULTI";
  const fulfilment = (final_amount: number): FulfilmentRecord => ({
    op_ref: OP,
    fulfilment_ref: fulfilmentRefFor(OP),
    agent_code: CODE,
    mandate_id: "mnd_m",
    order_ref: "ORD-m",
    merchant_id: "MER-1",
    authorized_amount: final_amount,
    final_amount,
    currency: "RUB",
    scope_check: "WITHIN_LIMITS",
    spent_position: final_amount,
    at: AT,
  });
  const setup = async (final_amount = 10_000) => {
    const operations = new MemoryOperationStore();
    await operations.begin(OP, "d".repeat(64), AT);
    await operations.finish({
      op_ref: OP,
      msg_hash: "d".repeat(64),
      decision: { decision: "APPROVE", reason: null, reservation_id: "h1", decided_in_ms: 1 },
      mandate_id: "mnd_m",
      holds: ["h1"],
      at: AT,
    });
    const outcomes = new MemoryOutcomeStore(operations);
    await outcomes.record({ op_ref: OP, agent_code: CODE, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    const fulfilments = new MemoryFulfilmentStore();
    await fulfilments.record(fulfilment(final_amount), undefined);
    const appended: unknown[] = [];
    const refunds = new MemoryRefundStore({ appendOperationEventNow: (e) => void appended.push(e) });
    const out: { msg: string; fields: Record<string, unknown> }[] = [];
    const log = (_level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void out.push({ msg, fields });
    const deps = { operations, outcomes, fulfilments, refunds, log, now: () => new Date(AT), reorder_window_ms: 5_000 };
    const send = (amount: number, extra: Record<string, unknown> = {}, currency = "RUB") => acceptRefund(deps, { op_ref: OP, msg_type: "REFUND", amount, currency, ...extra });
    const incidents = () => out.filter((x) => x.fields.incident === true);
    return { deps, refunds, appended, send, incidents };
  };

  it("две ссылки — две записи, одно событие; повтор ссылки — без изменения; сумма в пределах клиринга — без инцидента", async () => {
    const s = await setup();
    expect(await s.send(3_000, { refund_ref: "R1" })).toBe(202);
    expect(await s.send(4_000, { refund_ref: "R2" })).toBe(202);
    expect(await s.send(3_000, { refund_ref: "R1" })).toBe(202);
    expect((await s.refunds.list(OP)).map((x) => [x.refund_ref, x.amount])).toEqual([
      ["R1", 3_000],
      ["R2", 4_000],
    ]);
    expect(s.appended).toEqual([expect.objectContaining({ type: "operation.refunded", data: { op_ref: OP } })]);
    expect(s.incidents()).toEqual([]);
    expect(await s.refunds.get(OP)).toMatchObject({ refund_ref: "R1" });
  });

  it("та же ссылка с другой суммой — инцидент, запись прежняя", async () => {
    const s = await setup();
    expect(await s.send(3_000, { refund_ref: "R1" })).toBe(202);
    expect(await s.send(5_000, { refund_ref: "R1" })).toBe(202);
    expect((await s.refunds.list(OP)).map((x) => x.amount)).toEqual([3_000]);
    expect(s.incidents()).toEqual([expect.objectContaining({ fields: expect.objectContaining({ refund_ref: "R1", prior: 3_000, amount: 5_000 }) })]);
    expect(s.appended).toHaveLength(1);
  });

  it("смешение форм в обе стороны — инцидент без записи (нюанс 1)", async () => {
    const a = await setup();
    expect(await a.send(3_000)).toBe(202);
    expect(await a.send(3_000, { refund_ref: "R1" })).toBe(202);
    expect((await a.refunds.list(OP)).map((x) => x.refund_ref)).toEqual([null]);
    expect(a.incidents()).toEqual([expect.objectContaining({ fields: expect.objectContaining({ refund_ref: "R1", first_refund_ref: null }) })]);
    const b = await setup();
    expect(await b.send(3_000, { refund_ref: "R1" })).toBe(202);
    expect(await b.send(3_000)).toBe(202);
    expect((await b.refunds.list(OP)).map((x) => x.refund_ref)).toEqual(["R1"]);
    expect(b.incidents()).toEqual([expect.objectContaining({ fields: expect.objectContaining({ refund_ref: null, first_refund_ref: "R1" }) })]);
    expect(b.appended).toHaveLength(1);
  });

  it("сумма возвратов больше клиринга — запись и инцидент с суммой (п. 4)", async () => {
    const s = await setup(10_000);
    expect(await s.send(6_000, { refund_ref: "R1" })).toBe(202);
    expect(s.incidents()).toEqual([]);
    expect(await s.send(5_000, { refund_ref: "R2" })).toBe(202);
    expect((await s.refunds.list(OP)).map((x) => x.amount)).toEqual([6_000, 5_000]);
    expect(s.incidents()).toEqual([expect.objectContaining({ fields: expect.objectContaining({ total: 11_000, final_amount: 10_000, refund_ref: "R2" }) })]);
  });

  it("refund_ref не по форме — 400 без записи; валюта не операции — 400 и инцидент", async () => {
    const s = await setup();
    expect(await s.send(1_000, { refund_ref: null })).toBe(400);
    expect(await s.send(1_000, { refund_ref: "" })).toBe(400);
    expect(await s.send(1_000, { refund_ref: 7 })).toBe(400);
    expect(await s.send(1_000, { refund_ref: "R1" }, "USD")).toBe(400);
    expect(await s.refunds.list(OP)).toEqual([]);
    expect(s.incidents()).toHaveLength(1);
    expect(s.appended).toEqual([]);
  });
});

describe("несколько возвратов на стенде через ПИ-3 (РП71 п. 5–6)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_rfm_");
  beforeAll(async () => {
    stand = createStand();
    // Часы стенда — до valid_to мандата standPay (2026-10-26), как в pao-refund.
    stand.setClock(new Date("2026-10-23T13:00:00Z"));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, principal);
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });

  it("два возврата с разными refund_ref — одно operation.refunded, GET — REFUNDED, бюджет не восстановлен; null — 400", async () => {
    const p = pay();
    const intent = await p.mandate({ amount_limit: 100_000 });
    const cart = await p.cart(intent, 100_000);
    const op_ref = `OPKC-RFM-${letters(12)}`;
    const m: CanonicalMessage = await p.auth(cart, 60_000, op_ref);
    expect(((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision).decision).toBe("APPROVE");
    expect(await pi3({ op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await pi3({ op_ref, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    const left = async () => ((await signedGet(`/pao/v1/mandates/${cart}/verify`)).json() as { amount_left: number }).amount_left;
    expect(await left()).toBe(40_000);
    expect(await pi3({ op_ref, msg_type: "REFUND", amount: 20_000, currency: "RUB", refund_ref: "RF-1" })).toBe(202);
    expect(await pi3({ op_ref, msg_type: "REFUND", amount: 15_000, currency: "RUB", refund_ref: "RF-2" })).toBe(202);
    expect(await pi3({ op_ref, msg_type: "REFUND", amount: 15_000, currency: "RUB", refund_ref: null })).toBe(400);
    const feed = (await signedGet("/pao/v1/events")).json() as { type: string; data: Record<string, unknown> }[];
    expect(feed.filter((e) => e.type === "operation.refunded" && e.data.op_ref === op_ref)).toHaveLength(1);
    expect((await signedGet(`/pao/v1/operations/${op_ref}`)).json()).toMatchObject({ status: "REFUNDED", reason: null });
    expect(await left(), "restore_budget_on_refund = false (РП9, РП71 п. 6)").toBe(40_000);
  });
});
