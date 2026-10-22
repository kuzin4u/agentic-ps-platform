// Запрос подтверждения агенту на стенде (PS-19 ч. 2, РП51 п. 1–11): событие confirmation.* в ленте агента с общим номером,
// GET /pao/v1/confirmations/{id} — только свой (чужой, неизвестный, не по форме — 400 REQUEST_INVALID), USED — как APPROVED
// с той же ссылкой, link — страница УПК без сумм и ссылки, истечение при чтении — событие; POST — 400 без записи;
// SUSPENDED — 403. Решение человека — приложением банка стенда (ПИ-8); страница УПК — К2.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { MemoryConfirmationStore } from "../../src/confirm/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:cnf-get:v1";
const OTHER = "nspk:agent:cnf-get-other:v1";
const AMOUNT = 340_000;

type Feed = readonly { readonly event_id: string; readonly type: string; readonly data: unknown }[];

describe("GET /pao/v1/confirmations/{id} и события confirmation.* на стенде (РП51)", () => {
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  let cartId: string;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-10-22T09:00:00Z"));
    side = newAgentSide();
    other = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    expect(stand.admit(buyerApplication(OTHER, other), "op").admitted).toBe(true);
    const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
    cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: 2_000_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: AMOUNT }], total: AMOUNT },
    });
  });
  afterAll(async () => stand.close());

  const call = (method: "GET" | "POST", path: string, body?: unknown, who: [AgentSide, string] = [side, CODE]) =>
    signedInject(stand.app, who[0], who[1], {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });

  async function mandate(over: Partial<MandateRequest>): Promise<string> {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: "prn_cnf_get",
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await call("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  }

  /** Реквизит на заказ и авторизация выше порога: CONFIRMATION_REQUIRED и запрос подтверждения. */
  async function order(order_ref: string) {
    const res = await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const auth = (op_ref: string, confirmation_ref?: string): CanonicalMessage => ({
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: AMOUNT,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
      order_ref,
      ...(confirmation_ref ? { confirmation_ref } : {}),
    });
    const decide = async (m: CanonicalMessage): Promise<Decision> =>
      (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
    expect((await decide(auth(`OPKC-${order_ref}-1`))).decision).toBe("CONFIRMATION_REQUIRED");
    const before = (await feed());
    const ev = before.at(-1)!;
    expect(ev.type).toBe("confirmation.required");
    const id = (ev.data as { confirmation_id: string }).confirmation_id;
    return { id, auth, decide };
  }

  const feed = async (who: [AgentSide, string] = [side, CODE]): Promise<Feed> => (await call("GET", "/pao/v1/events", undefined, who)).json() as Feed;
  const get = (id: string, who?: [AgentSide, string]) => call("GET", `/pao/v1/confirmations/${id}`, undefined, who);

  it("доказательный: confirmation.required в ленте после mandate.* → GET PENDING с link → банк подтвердил → approved → GET со ссылкой → повтор APPROVE → GET APPROVED с той же ссылкой", async () => {
    const { id, auth, decide } = await order("ORD-get-1");
    const evs = (await feed());
    expect(evs.map((e) => e.type)).toEqual(["mandate.signed", "mandate.signed", "confirmation.required"]);
    expect(evs.at(-1)!.data).toEqual({ confirmation_id: id });

    const p = await get(id);
    expect(p.statusCode).toBe(200);
    const view = p.json() as Record<string, unknown>;
    expect(Object.keys(view).sort()).toEqual(["confirmation_ref", "expires_at", "id", "link", "status"]);
    expect(view).toMatchObject({ id, status: "PENDING", confirmation_ref: null, link: `https://upk.stand/c/${id}`, expires_at: "2026-10-22T09:15:00.000Z" });

    expect((await stand.issuer.confirm(id)).statusCode).toBe(200);
    expect((await feed()).at(-1)).toMatchObject({ type: "confirmation.approved", data: { confirmation_id: id } });
    const a = (await get(id)).json() as { status: string; confirmation_ref: string };
    expect(a.status).toBe("APPROVED");
    expect(a.confirmation_ref).toMatch(/^cr_[a-z2-7]{26}$/);

    expect((await decide(auth("OPKC-ORD-get-1-2", a.confirmation_ref))).decision).toBe("APPROVE");
    expect((await stand.confirmations.get(id))?.status).toBe("USED");
    // USED — как APPROVED с той же ссылкой до ПАО 1.5.0 (РП51 п. 9); у погашения события нет (п. 2).
    expect((await get(id)).json()).toMatchObject({ status: "APPROVED", confirmation_ref: a.confirmation_ref });
    expect((await feed()).at(-1)!.type).toBe("confirmation.approved");
  });

  it("отказ человека — rejected, GET REJECTED без ссылки", async () => {
    const { id } = await order("ORD-get-rej");
    await stand.issuer.confirm(id, { decision: "REJECT" });
    expect((await feed()).at(-1)).toMatchObject({ type: "confirmation.rejected", data: { confirmation_id: id } });
    expect((await get(id)).json()).toMatchObject({ status: "REJECTED", confirmation_ref: null });
  });

  it("чужой, неизвестный и не по форме id — один ответ 400 REQUEST_INVALID; чужому агенту события не видно", async () => {
    const { id } = await order("ORD-get-foreign");
    const foreign = await get(id, [other, OTHER]);
    const unknown = await get("cnf_00000000-0000-4000-8000-000000000000");
    const malformed = await get("cnf_x");
    for (const r of [foreign, unknown, malformed]) {
      expect(r.statusCode).toBe(400);
      expect((r.json() as { code: string }).code).toBe("REQUEST_INVALID");
    }
    expect(foreign.json()).toEqual(unknown.json());
    expect((await feed([other, OTHER]))).toEqual([]);
  });

  it("PENDING после срока — EXPIRED этим чтением и одно событие confirmation.expired", async () => {
    const { id } = await order("ORD-get-exp");
    stand.setClock(new Date("2026-10-22T09:15:00Z"));
    try {
      expect((await get(id)).json()).toMatchObject({ status: "EXPIRED", confirmation_ref: null });
      expect((await get(id)).json()).toMatchObject({ status: "EXPIRED" });
      const exp = (await feed()).filter((e) => e.type === "confirmation.expired");
      expect(exp).toEqual([expect.objectContaining({ data: { confirmation_id: id } })]);
    } finally {
      stand.setClock(new Date("2026-10-22T09:00:00Z"));
    }
  });

  it("POST /pao/v1/confirmations в 1.4.x — 400 REQUEST_INVALID без записи; повтор тем же ключом — снова 400, ключ не занят (РП51 п. 11)", async () => {
    const before = (await feed()).length;
    const body = JSON.stringify({ mandate_id: cartId, merchant_id: "MER-1042", amount: AMOUNT, summary: "x" });
    const key = randomUUID();
    for (let i = 0; i < 2; i++) {
      const r = await signedInject(stand.app, side, CODE, { method: "POST", path: "/pao/v1/confirmations", body, headers: { "idempotency-key": key }, now: stand.now() });
      expect(r.statusCode).toBe(400);
      expect((r.json() as { code: string }).code).toBe("REQUEST_INVALID");
    }
    expect(await feed()).toHaveLength(before);
    expect(await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref: "x", amount: AMOUNT, currency: "RUB" })).toEqual([]);
  });

  it("чужой GET после срока — 400, запрос владельца не переводится в EXPIRED и события нет (агент сверяется до истечения)", async () => {
    const { id } = await order("ORD-get-foreign-exp");
    stand.setClock(new Date("2026-10-22T09:15:00Z"));
    try {
      expect((await get(id, [other, OTHER])).statusCode).toBe(400);
      expect((await stand.confirmations.get(id))?.status).toBe("PENDING");
      expect((await feed()).filter((e) => e.type === "confirmation.expired" && (e.data as { confirmation_id: string }).confirmation_id === id)).toEqual([]);
    } finally {
      stand.setClock(new Date("2026-10-22T09:00:00Z"));
    }
  });

  it("сбой П6 при чтении — 503 STATE_UNAVAILABLE с Retry-After, тело ПАО (инвариант 3)", async () => {
    const { id } = await order("ORD-get-fail");
    const spy = vi.spyOn(MemoryConfirmationStore.prototype, "get").mockRejectedValueOnce(new Error("П6 недоступно"));
    try {
      const r = await get(id);
      expect(r.statusCode).toBe(503);
      expect(r.headers["retry-after"]).toBe("1");
      expect(r.json()).toMatchObject({ code: "STATE_UNAVAILABLE", retry: "same_key" });
    } finally {
      spy.mockRestore();
    }
  });

  it("SUSPENDED — 403 AGENT_SUSPENDED у GET запроса подтверждения", async () => {
    const { id } = await order("ORD-get-susp");
    stand.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    const r = await get(id);
    expect(r.statusCode).toBe(403);
    expect((r.json() as { code: string }).code).toBe("AGENT_SUSPENDED");
  });
});
