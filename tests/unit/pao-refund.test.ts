// Возврат (PS-16 ч. 3, РП55 п. 3–5; ПС15): ПИ-3 REFUND после клиринга — запись и одно operation.refunded, GET — REFUNDED с
// прежним fulfilment; бюджет мандата не восстанавливается (restore_budget_on_refund = false, РП9), исчерпанный остаётся
// исчерпанным; отзыв мандата возврат не останавливает. До клиринга — 503 (перестановка); после реверсала и по отказу —
// 202 без записи; валюта — 400; больше суммы клиринга — запись и инцидент; второй с другой суммой — инцидент.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { fulfilmentRefFor, MemoryFulfilmentStore, type FulfilmentRecord } from "../../src/fulfilment/records.js";
import { acceptRefund, MemoryRefundStore } from "../../src/fulfilment/refunds.js";
import { operationEventIdFor } from "../../src/pao/events.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-fifteen:v1";
const T0 = new Date("2026-10-23T13:00:00Z");

type Feed = readonly { readonly event_id: string; readonly type: string; readonly data: Record<string, unknown> }[];
interface Mandates {
  readonly intent: string;
  readonly cart: string;
}

const opRef = (): string => `OPKC-REF-${letters(12)}`;

describe("возврат REFUND → operation.refunded без восстановления бюджета на стенде (РП55, ПС15)", () => {
  let stand: Stand;
  let side: AgentSide;
  const principal = opaquePrincipalRef("prn_ref_");
  beforeAll(() => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
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
  const present = (op_ref: string, amount: number) => pi3({ op_ref, msg_type: "PRESENTMENT", amount, currency: "RUB" });
  const refund = (op_ref: string, amount: number, currency: unknown = "RUB") => pi3({ op_ref, msg_type: "REFUND", amount, currency });
  const signedGet = (path: string) => signedInject(stand.app, side, CODE, { method: "GET", path, now: stand.now() });
  const left = async (mandate_id: string): Promise<number> => ((await signedGet(`/pao/v1/mandates/${mandate_id}/verify`)).json() as { amount_left: number }).amount_left;
  const op = async (op_ref: string) => (await signedGet(`/pao/v1/operations/${op_ref}`)).json() as Record<string, unknown>;
  const refunded = async (op_ref: string) =>
    ((await signedGet("/pao/v1/events")).json() as Feed).filter((e) => e.type === "operation.refunded" && e.data.op_ref === op_ref);
  const approved = async (m: Mandates, amount: number): Promise<string> => {
    const op_ref = opRef();
    expect(await decide(await pay().auth(m.cart, amount, op_ref))).toMatchObject({ decision: "APPROVE" });
    return op_ref;
  };
  const settled = async (m: Mandates, amount: number): Promise<string> => {
    const op_ref = await approved(m, amount);
    expect(await issuer(op_ref, true)).toBe(202);
    expect(await present(op_ref, amount)).toBe(202);
    return op_ref;
  };

  it("ПС15: возврат после клиринга — одно operation.refunded, GET — REFUNDED с прежним fulfilment; бюджет не восстановлен; повтор — без второго события", async () => {
    const m = await mandates(100_000);
    const o = await settled(m, 60_000);
    expect(await left(m.cart)).toBe(40_000);
    expect(await refund(o, 60_000)).toBe(202);
    const evs = await refunded(o);
    expect(evs.map((e) => [e.type, e.data])).toEqual([["operation.refunded", { op_ref: o }]]);
    expect(evs[0]!.event_id).toBe(operationEventIdFor(o, "operation.refunded"));
    expect(await op(o)).toMatchObject({
      op_ref: o,
      status: "REFUNDED",
      reason: null,
      fulfilment: { fulfilment_ref: fulfilmentRefFor(o), final_amount: 60_000, scope_check: "WITHIN_LIMITS" },
    });
    expect(await left(m.cart), "restore_budget_on_refund = false (РП9)").toBe(40_000);
    expect(await left(m.intent)).toBe(40_000);
    expect(await refund(o, 60_000)).toBe(202);
    expect(await refunded(o)).toHaveLength(1);
  });

  it("исчерпанный мандат остаётся исчерпанным после возврата; частичный возврат — REFUNDED", async () => {
    const m = await mandates(50_000);
    const o = await settled(m, 50_000);
    expect(await left(m.cart)).toBe(0);
    expect(await refund(o, 20_000)).toBe(202);
    expect(await left(m.cart)).toBe(0);
    expect(await op(o)).toMatchObject({ status: "REFUNDED", fulfilment: { final_amount: 50_000 } });
    expect(((await signedGet(`/pao/v1/mandates/${m.cart}`)).json() as { status: string }).status, "EXHAUSTED конечный (РП41)").toBe("EXHAUSTED");
  });

  it("до клиринга — 503 (перестановка), после — принято; до ответа эмитента — 503", async () => {
    const m = await mandates(100_000);
    const o = await approved(m, 30_000);
    expect(await refund(o, 30_000)).toBe(503);
    expect(await issuer(o, true)).toBe(202);
    expect(await refund(o, 30_000)).toBe(503);
    expect(await present(o, 30_000)).toBe(202);
    expect(await refund(o, 30_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "REFUNDED" });
  });

  it("после отзыва мандата клиентом — возврат записан, событие есть (A3 п. 6.3)", async () => {
    const m = await mandates(100_000);
    const o = await settled(m, 25_000);
    expect((await stand.issuer.revoke(m.cart)).statusCode).toBe(200);
    expect(await refund(o, 25_000)).toBe(202);
    expect(await refunded(o)).toHaveLength(1);
    expect(await op(o)).toMatchObject({ status: "REFUNDED" });
  });

  it("больше суммы клиринга — записан как пришёл (РП55 п. 3); второй с другой суммой — 202, запись прежняя, второго события нет", async () => {
    const m = await mandates(100_000);
    const o = await settled(m, 10_000);
    expect(await refund(o, 15_000)).toBe(202);
    expect(await op(o)).toMatchObject({ status: "REFUNDED" });
    expect(await refund(o, 5_000)).toBe(202);
    expect(await refunded(o)).toHaveLength(1);
  });

  it("клиринг после реверсала, затем возврат — записан, operation.refunded, GET — REFUNDED с NOT_RESERVED (клиринг старше, КТ1 п. 3)", async () => {
    const m = await mandates(100_000);
    const o = await approved(m, 20_000);
    expect(await issuer(o, true)).toBe(202);
    expect(await pi3({ op_ref: o, msg_type: "REVERSAL" })).toBe(202);
    expect(await present(o, 20_000)).toBe(202);
    expect(await refund(o, 20_000)).toBe(202);
    expect(await refunded(o)).toHaveLength(1);
    expect(await op(o)).toMatchObject({ status: "REFUNDED", fulfilment: { scope_check: "NOT_RESERVED" } });
  });

  it("форма — 400; валюта не операции — 400 без записи; реверсал без клиринга — 503 (ждёт клиринга); по отказу эмитента и BYPASS — 202 без записи и события", async () => {
    const m = await mandates(100_000);
    const o = await settled(m, 10_000);
    expect(await refund(o, 0)).toBe(400);
    expect(await refund(o, 10_000, "rub")).toBe(400);
    expect(await refund(o, 10_000, "USD")).toBe(400);
    expect(await op(o)).toMatchObject({ status: "SETTLED" });
    const r = await approved(m, 10_000);
    expect(await issuer(r, true)).toBe(202);
    expect(await pi3({ op_ref: r, msg_type: "REVERSAL" })).toBe(202);
    expect(await refund(r, 10_000)).toBe(503);
    expect(await op(r)).toMatchObject({ status: "REVERSED" });
    const no = await approved(m, 10_000);
    expect(await issuer(no, false)).toBe(202);
    expect(await refund(no, 10_000)).toBe(202);
    expect(await refunded(r)).toEqual([]);
    expect(await refunded(no)).toEqual([]);
    expect(await refund(`OPKC-BYPASS-${letters(12)}`, 1_000)).toBe(202);
  });
});

describe("acceptRefund без стенда: инциденты, агент не установлен, окно перестановки (РП55 п. 3, 5)", () => {
  const AT = "2026-10-23T13:00:00.000Z";
  const OP = "OPKC-REF-UNIT";
  const fulfilment = (agent_code: string | null): FulfilmentRecord => ({
    op_ref: OP,
    fulfilment_ref: fulfilmentRefFor(OP),
    agent_code,
    mandate_id: "mnd_u",
    order_ref: "ORD-u",
    merchant_id: "MER-1",
    authorized_amount: 10_000,
    final_amount: 10_000,
    currency: "RUB",
    scope_check: "WITHIN_LIMITS",
    spent_position: 10_000,
    at: AT,
  });
  const setup = async (opts: { settled?: boolean; agent?: string | null } = {}) => {
    const operations = new MemoryOperationStore();
    await operations.begin(OP, "d".repeat(64), AT);
    await operations.finish({
      op_ref: OP,
      msg_hash: "d".repeat(64),
      decision: { decision: "APPROVE", reason: null, reservation_id: "h1", decided_in_ms: 1 },
      mandate_id: "mnd_u",
      holds: ["h1"],
      at: AT,
    });
    const outcomes = new MemoryOutcomeStore(operations);
    await outcomes.record({ op_ref: OP, agent_code: opts.agent ?? CODE, status: "AUTHORIZED", reason: null, source: "ISSUER", at: AT }, undefined);
    const fulfilments = new MemoryFulfilmentStore();
    if (opts.settled !== false) await fulfilments.record(fulfilment(opts.agent === undefined ? CODE : opts.agent), undefined);
    const appended: unknown[] = [];
    const refunds = new MemoryRefundStore({ appendOperationEventNow: (e) => void appended.push(e) });
    const out: { level: string; fields: Record<string, unknown> }[] = [];
    const log = (level: "info" | "warn", fields: Record<string, unknown>) => void out.push({ level, fields });
    return { deps: { operations, outcomes, fulfilments, refunds, log, now: () => new Date(AT), reorder_window_ms: 5_000 }, appended, out };
  };
  const incidents = (out: readonly { fields: Record<string, unknown> }[]) => out.filter((x) => x.fields.incident === true);

  it("больше суммы клиринга — запись и инцидент; второй с другой суммой — инцидент, запись прежняя", async () => {
    const s = await setup();
    expect(await acceptRefund(s.deps, { op_ref: OP, msg_type: "REFUND", amount: 12_000, currency: "RUB" })).toBe(202);
    expect(await s.deps.refunds.get(OP)).toMatchObject({ amount: 12_000, currency: "RUB", agent_code: CODE, mandate_id: "mnd_u" });
    expect(incidents(s.out)).toHaveLength(1);
    expect(await acceptRefund(s.deps, { op_ref: OP, msg_type: "REFUND", amount: 3_000, currency: "RUB" })).toBe(202);
    expect(await s.deps.refunds.get(OP)).toMatchObject({ amount: 12_000 });
    expect(incidents(s.out)).toHaveLength(2);
    expect(s.appended).toHaveLength(1);
  });

  it("агент не установлен — запись без события", async () => {
    const s = await setup({ agent: null });
    expect(await acceptRefund(s.deps, { op_ref: OP, msg_type: "REFUND", amount: 10_000, currency: "RUB" })).toBe(202);
    expect(await s.deps.refunds.get(OP)).toMatchObject({ agent_code: null });
    expect(s.appended).toEqual([]);
  });

  it("без клиринга за окном — 503 и инцидент «предшественник не пришёл»", async () => {
    const s = await setup({ settled: false });
    const late = { ...s.deps, now: () => new Date(Date.parse(AT) + 5_001) };
    expect(await acceptRefund(late, { op_ref: OP, msg_type: "REFUND", amount: 10_000, currency: "RUB" })).toBe(503);
    expect(incidents(s.out)).toEqual([expect.objectContaining({ fields: expect.objectContaining({ missing: "PRESENTMENT" }) })]);
  });
});
