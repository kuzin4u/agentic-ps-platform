// GET /pao/v1/operations/{op_ref} на стенде (PS-16 ч. 2, РП52 п. 10, РП53 п. 10): итог — из записи итога, а без неё — из
// решения в записи операции ADP, независимо от сборщика и его горизонта (условие к д1, «Дополнения» РП52 п. 1); только
// своему агенту по домену токена; чужая, неизвестная, без установленного агента и без итога — 400 REQUEST_INVALID;
// SUSPENDED — 403; сбой чтения — 503. Записи до sql/114 и признак без обязательных полей — без догадки (view).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { MemoryOperationStore, type OperationRecord } from "../../src/adp/operations.js";
import { MemoryOutcomeStore } from "../../src/fulfilment/outcomes.js";
import { operationFor } from "../../src/fulfilment/view.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-sixteen-get:v1";
const OTHER = "nspk:agent:ps-sixteen-get-other:v1";
const PRINCIPAL = "prn_ps_sixteen_get";
const T0 = new Date("2026-10-23T09:00:00Z");

type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];

describe("GET /pao/v1/operations/{op_ref} на стенде (РП52 п. 10, РП53 п. 10)", () => {
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    other = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    expect((await stand.admit(buyerApplication(OTHER, other), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, PRINCIPAL);
  const cart = async (limit: number): Promise<string> => {
    const p = pay();
    return p.cart(await p.mandate({ amount_limit: limit }), limit);
  };
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const issuer = async (op_ref: string, issuer_approved: boolean) =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload: { op_ref, msg_type: "ISSUER_RESPONSE", issuer_approved } })).statusCode;
  const getAs = (s: AgentSide, code: string, op_ref: string) =>
    signedInject(stand.app, s, code, { method: "GET", path: `/pao/v1/operations/${op_ref}`, now: stand.now() });
  const get = (op_ref: string) => getAs(side, CODE, op_ref);
  const opEvents = async (op_ref: string) => {
    const r = await signedInject(stand.app, side, CODE, { method: "GET", path: "/pao/v1/events", now: stand.now() });
    return (r.json() as Feed).filter((e) => e.type.startsWith("operation.") && e.data.op_ref === op_ref);
  };
  /** LIMIT_EXCEEDED: CART 100 000, одобрено 60 000, вторая на 60 000 — остатка нет. */
  const limitDecline = async (op_ref: string): Promise<CanonicalMessage> => {
    const m = await cart(100_000);
    expect(await decide(await pay().auth(m, 60_000))).toMatchObject({ decision: "APPROVE" });
    const msg = await pay().auth(m, 60_000, op_ref);
    expect(await decide(msg)).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    return msg;
  };

  it("отказ ADP — итог из записи операции до прохода сборщика: DECLINED с кодом, факты из сообщения процессинга; token_ref нет", async () => {
    const op = `OPKC-GET-${randomUUID()}`;
    const msg = await limitDecline(op);
    const r = await get(op);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({
      op_ref: op,
      order_ref: msg.order_ref,
      channel: "CARD",
      amount: 60_000,
      merchant_id: msg.merchant.id,
      aoi: msg.aoi,
      status: "DECLINED",
      reason: "LIMIT_EXCEEDED",
      fulfilment: null,
      deal_ref: null,
    });
    expect(r.body).not.toContain(msg.instrument.token_ref);
    // После прохода — тот же ответ из записи итога.
    await stand.collectOperationOutcomes();
    expect((await get(op)).json()).toEqual(r.json());
  });

  it("условие к д1: старый отказ за горизонтом — события нет, GET отдаёт итог (РП52 «Дополнения» п. 1)", async () => {
    await stand.collectOperationOutcomes();
    const op = `OPKC-GET-${randomUUID()}`;
    await limitDecline(op);
    stand.setClock(new Date(stand.now().getTime() + 86_400_000 + 1_000));
    await stand.collectOperationOutcomes();
    expect(await opEvents(op), "горизонт: события нет").toEqual([]);
    const r = await get(op);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ op_ref: op, status: "DECLINED", reason: "LIMIT_EXCEEDED" });
  });

  it("APPROVE до ответа эмитента — 400 (итога нет); одобрение — AUTHORIZED без причины; отказ эмитента — DECLINED ISSUER_DECLINED", async () => {
    const m = await cart(200_000);
    const ok = `OPKC-GET-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 50_000, ok))).toMatchObject({ decision: "APPROVE" });
    const early = await get(ok);
    expect(early.statusCode).toBe(400);
    expect(early.json()).toMatchObject({ code: "REQUEST_INVALID" });
    expect(await issuer(ok, true)).toBe(202);
    expect((await get(ok)).json()).toMatchObject({ op_ref: ok, status: "AUTHORIZED", reason: null, fulfilment: null });
    const no = `OPKC-GET-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 50_000, no))).toMatchObject({ decision: "APPROVE" });
    expect(await issuer(no, false)).toBe(202);
    expect((await get(no)).json()).toMatchObject({ op_ref: no, status: "DECLINED", reason: "ISSUER_DECLINED" });
  });

  it("CONFIRMATION_REQUIRED — из записи операции, без причины", async () => {
    const m = await cart(400_000);
    const cr = `OPKC-GET-${randomUUID()}`;
    expect(await decide(await pay().auth(m, 350_000, cr))).toMatchObject({ decision: "CONFIRMATION_REQUIRED" });
    expect((await get(cr)).json()).toMatchObject({ op_ref: cr, status: "CONFIRMATION_REQUIRED", reason: null });
  });

  it("чужая, неизвестная, без установленного агента — один ответ 400 REQUEST_INVALID", async () => {
    const op = `OPKC-GET-${randomUUID()}`;
    await limitDecline(op);
    const theirs = await getAs(other, OTHER, op);
    expect(theirs.statusCode).toBe(400);
    const unknown = await get(`OPKC-GET-${randomUUID()}`);
    expect(unknown.statusCode).toBe(400);
    expect(unknown.json()).toEqual(theirs.json());
    // Токена нет в записях Платформы — агент не установлен: итог есть, но никому (РП52 п. 5).
    const m = await cart(50_000);
    const forgedOp = `OPKC-GET-${randomUUID()}`;
    const msg = await pay().auth(m, 10_000, forgedOp);
    const forged = { ...msg, instrument: { ...msg.instrument, token_ref: "tok_unknown_get" } } as CanonicalMessage;
    expect(await decide(forged)).toMatchObject({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    expect((await get(forgedOp)).statusCode).toBe(400);
  });

  it("AOI_MISMATCH — итог владельцу токена без aoi: чужой код агента и мандат не отдаются (решение владельца на КТ1 № 10)", async () => {
    const m = await cart(50_000);
    const op = `OPKC-GET-${randomUUID()}`;
    const msg = await pay().auth(m, 10_000, op);
    const lie = { ...msg, aoi: { ...msg.aoi, agent_code: OTHER, mandate_id: "mnd_someone_else" } } as CanonicalMessage;
    expect(await decide(lie)).toMatchObject({ decision: "DECLINE", reason: "AOI_MISMATCH" });
    const r = await get(op);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ op_ref: op, status: "DECLINED", reason: "AOI_MISMATCH" });
    expect(r.json()).not.toHaveProperty("aoi");
    expect(r.body).not.toContain(OTHER);
    expect(r.body).not.toContain("mnd_someone_else");
  });

  it("SUSPENDED — 403 AGENT_SUSPENDED; после снятия — итог", async () => {
    const op = `OPKC-GET-${randomUUID()}`;
    await limitDecline(op);
    await stand.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    try {
      const r = await get(op);
      expect(r.statusCode).toBe(403);
      expect(r.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
    } finally {
      await stand.registry.changeStatus(CODE, { to: "ACTIVE" });
      // Реквизит в ту же миллисекунду, что приостановление, — выдан «до» (Р-634): следующим тестам — часы на 1 мс вперёд.
      stand.setClock(new Date(stand.now().getTime() + 1));
    }
    expect((await get(op)).statusCode).toBe(200);
  });

  it("сбой чтения итога — 503 STATE_UNAVAILABLE с Retry-After (инвариант 3)", async () => {
    const op = `OPKC-GET-${randomUUID()}`;
    await limitDecline(op);
    const spy = vi.spyOn(MemoryOutcomeStore.prototype, "get").mockRejectedValueOnce(new Error("П8 недоступно"));
    try {
      const r = await get(op);
      expect(r.statusCode).toBe(503);
      expect(r.headers["retry-after"]).toBeDefined();
      expect(r.json()).toMatchObject({ code: "STATE_UNAVAILABLE" });
    } finally {
      spy.mockRestore();
    }
  });
});

describe("operationFor — без догадки (РП52 п. 10, «Нюансы реализации» п. 4)", () => {
  const AT = "2026-10-23T09:00:00.000Z";
  const reader = (rec: OperationRecord) => ({ get: (op_ref: string) => (op_ref === rec.op_ref ? rec : undefined) });
  const outcomes = new MemoryOutcomeStore(new MemoryOperationStore());
  const decline: Decision = { decision: "DECLINE", reason: "MANDATE_REVOKED", decided_in_ms: 1 };

  it("запись до sql/114: агент — из столбца уведомителя, фактов нет — поля опущены", async () => {
    const rec: OperationRecord = {
      op_ref: "OP-legacy",
      msg_hash: "a".repeat(64),
      decision: decline,
      mandate_id: "mnd_x",
      holds: [],
      at: AT,
      notify: { participant_code: "ISS-01", principal_ref: "prn_x", agent_code: CODE },
    };
    expect(await operationFor({ operations: reader(rec), outcomes }, CODE, "OP-legacy")).toEqual({
      op_ref: "OP-legacy",
      status: "DECLINED",
      reason: "MANDATE_REVOKED",
      fulfilment: null,
      deal_ref: null,
    });
    expect(await operationFor({ operations: reader(rec), outcomes }, OTHER, "OP-legacy")).toBeUndefined();
  });

  it("признак без обязательного поля Aoi ПАО — опускается, не дополняется", async () => {
    const rec: OperationRecord = {
      op_ref: "OP-aoi",
      msg_hash: "a".repeat(64),
      decision: decline,
      mandate_id: "mnd_x",
      holds: [],
      at: AT,
      facts: { agent_code: CODE, order_ref: "ORD-1", channel: null, merchant_id: null, amount: 100, currency: "RUB", aoi: { indicator: true, agent_code: CODE } },
    };
    const op = await operationFor({ operations: reader(rec), outcomes }, CODE, "OP-aoi");
    expect(op).toEqual({ op_ref: "OP-aoi", order_ref: "ORD-1", amount: 100, status: "DECLINED", reason: "MANDATE_REVOKED", fulfilment: null, deal_ref: null });
  });

  it("запись «в работе» (решения нет) — итога нет", async () => {
    const rec: OperationRecord = { op_ref: "OP-wip", msg_hash: "a".repeat(64), decision: null, mandate_id: null, holds: [], at: AT, facts: undefined };
    expect(await operationFor({ operations: reader(rec), outcomes }, CODE, "OP-wip")).toBeUndefined();
  });
});
