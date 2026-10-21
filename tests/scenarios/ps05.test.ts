// ПС05 «Агентский токен и криптограмма на заказ» на стенде (A3 п. 2; РП2, РП47; ФП4): POST /pao/v1/credentials по CART
// ACTIVE — реквизит выдан, домен токена = agent_code + CART + merchant_scope, номера карты нет нигде, повтор на тот же
// order_ref — тот же реквизит и та же криптограмма. Коды отказов выдачи — РП47 п. 4.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:ps-five:v1";
const PRINCIPAL = "prn_ps_five";
const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8"), { maxAliasCount: -1 });

describe("ПС05 на стенде: агентский токен и криптограмма на заказ (РП47)", () => {
  let stand: Stand;
  let side: AgentSide;
  let intentId: string;
  let cartId: string;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-10-20T09:00:00Z"));
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    intentId = await mandate({ type: "INTENT", amount_limit: 300_000, subject: "продукты" });
    cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: 189_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 189_000 }], total: 189_000 },
    });
  });
  afterAll(async () => stand.close());

  const call = (method: "GET" | "POST", path: string, body?: unknown, key: string | null = randomUUID()) =>
    signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
      headers: key === null ? {} : { "idempotency-key": key },
      now: stand.now(),
    });

  async function mandate(over: Partial<MandateRequest>, token_consent = true): Promise<string> {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await call("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id, { token_consent })).statusCode).toBe(200);
    return id;
  }

  const credReq = (over: Record<string, unknown> = {}) => ({
    mandate_id: cartId,
    order_ref: "ORD-ps05",
    merchant_id: "MER-1042",
    amount_max: 189_000,
    currency: "RUB",
    kind: "CARD",
    ...over,
  });

  it("201: реквизит по схеме Credential, домен токена = agent_code + CART + merchant_scope, криптограмма верна", async () => {
    const res = await call("POST", "/pao/v1/credentials", credReq());
    expect(res.statusCode).toBe(201);
    const c = res.json() as Credential;
    const schema = pao.components.schemas.Credential;
    for (const f of schema.required as string[]) expect(c, f).toHaveProperty(f);
    expect(Object.keys(c).sort()).toEqual(Object.keys(schema.properties).sort());
    expect(c.status).toBe("ISSUED");
    expect(c.aoi).toEqual({ indicator: true, agent_code: CODE, mandate_id: cartId });
    expect(c.payload.valid_to).toBe(new Date(stand.now().getTime() + stand.params.cryptogram_ttl_sec * 1000).toISOString());
    const token_ref = c.payload.token_ref as string;
    expect(stand.tsp.issued.get(token_ref)?.domain).toEqual({
      agent_code: CODE,
      mandate_id: cartId,
      merchant_scope: ["MER-1042"],
      valid_to: "2026-10-26T00:00:00Z",
    });
    const input = { token_ref, order_ref: "ORD-ps05", merchant_id: "MER-1042", amount_max: 189_000, currency: "RUB", valid_to: c.payload.valid_to as string };
    expect(stand.tsp.verify(input, c.payload.cryptogram as string)).toBe(true);
  });

  it("повтор на тот же order_ref (новый Idempotency-Key, позже по часам) — тот же реквизит и та же криптограмма", async () => {
    const a = (await call("POST", "/pao/v1/credentials", credReq())).json();
    stand.setClock(new Date(stand.now().getTime() + 120_000));
    const b = await call("POST", "/pao/v1/credentials", credReq());
    expect(b.statusCode).toBe(201);
    expect(b.json()).toEqual(a);
  });

  it("повтор под тем же Idempotency-Key — тот же реквизит и та же криптограмма; после погашения — USED (РП48 (в))", async () => {
    const key = randomUUID();
    const order = credReq({ order_ref: "ORD-ps05-key", amount_max: 30_000 });
    const a = await call("POST", "/pao/v1/credentials", order, key);
    const b = await call("POST", "/pao/v1/credentials", order, key);
    expect([a.statusCode, b.statusCode]).toEqual([201, 201]);
    expect(b.json()).toEqual(a.json());
    const c = a.json() as Credential;
    const msg: CanonicalMessage = {
      op_ref: "OPKC-PS05-KEY",
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: 30_000,
      currency: "RUB",
      merchant: { id: "MER-1042" },
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      aoi: c.aoi,
    };
    expect(parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json(), "adp").decision).toBe("APPROVE");
    const after = await call("POST", "/pao/v1/credentials", order, key);
    expect([after.statusCode, after.json()]).toEqual([201, { ...c, status: "USED" }]);
  });

  it("тот же order_ref с другой суммой — 409 IDEMPOTENCY_CONFLICT", async () => {
    const res = await call("POST", "/pao/v1/credentials", credReq({ amount_max: 100_000 }));
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("номера карты нет: в ответе нет серий из 13–19 цифр, ссылки — без цифр (инвариант 1)", async () => {
    const res = await call("POST", "/pao/v1/credentials", credReq({ order_ref: "ORD-ps05-b" }));
    expect(res.body).not.toMatch(/\d{13,19}/);
    const c = res.json() as Credential;
    expect(c.credential_ref).toMatch(/^crd_[a-z]{24}$/);
    expect(c.payload.token_ref).toMatch(/^tok_ag_[a-z]{24}$/);
    expect(c.payload).not.toHaveProperty("pan");
  });

  it("INTENT — 409 MANDATE_SCOPE; SBP — 409 CREDENTIAL_INVALID; продавец вне области — 409 MANDATE_SCOPE", async () => {
    const intent = await call("POST", "/pao/v1/credentials", credReq({ mandate_id: intentId, order_ref: "ORD-i" }));
    expect([intent.statusCode, intent.json().code]).toEqual([409, "MANDATE_SCOPE"]);
    const sbp = await call("POST", "/pao/v1/credentials", credReq({ kind: "SBP", order_ref: "ORD-s" }));
    expect([sbp.statusCode, sbp.json().code, sbp.json().retry]).toEqual([409, "CREDENTIAL_INVALID", "after_fix"]);
    const scope = await call("POST", "/pao/v1/credentials", credReq({ merchant_id: "MER-9", order_ref: "ORD-m" }));
    expect([scope.statusCode, scope.json().code]).toEqual([409, "MANDATE_SCOPE"]);
  });

  it("корень подписан без согласия на токен — 409 MANDATE_SCOPE (after_human), токен не выпущен", async () => {
    const root = await mandate({ type: "INTENT", amount_limit: 50_000, principal_ref: "prn_no_token" }, false);
    const cart = await mandate({
      type: "CART",
      parent_id: root,
      amount_limit: 10_000,
      principal_ref: "prn_no_token",
      cart: { merchant_id: "MER-1042", items: [{ sku: "x", qty: 1, price: 10_000 }], total: 10_000 },
    });
    const before = stand.tsp.issued.size;
    const res = await call("POST", "/pao/v1/credentials", credReq({ mandate_id: cart, amount_max: 10_000 }));
    expect([res.statusCode, res.json().code, res.json().retry]).toEqual([409, "MANDATE_SCOPE", "after_human"]);
    expect(stand.tsp.issued.size).toBe(before);
  });

  it("реквизит в авторизации через ADP стенда: APPROVE и погашение; та же криптограмма ещё раз — CREDENTIAL_INVALID; повтор выдачи — USED", async () => {
    const res = await call("POST", "/pao/v1/credentials", credReq({ order_ref: "ORD-ps05-adp", amount_max: 50_000 }));
    const c = res.json() as Credential;
    const msg = (op_ref: string): CanonicalMessage => ({
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: 40_000,
      currency: "RUB",
      merchant: { id: "MER-1042" },
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      aoi: c.aoi,
    });
    const decide = async (op_ref: string) =>
      parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg(op_ref) })).json(), "adp");
    // Домен — из записи токена Платформы, которую читает ADP (а не копия эмулятора): чужой код агента в aoi — AOI_MISMATCH.
    const foreign = { ...msg("OPKC-PS05-0"), aoi: { ...c.aoi, agent_code: "nspk:agent:other:v1" } };
    expect(parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: foreign })).json(), "adp")).toMatchObject({
      decision: "DECLINE",
      reason: "AOI_MISMATCH",
    });
    expect((await decide("OPKC-PS05-1")).decision).toBe("APPROVE");
    expect(await decide("OPKC-PS05-2")).toMatchObject({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    const again = await call("POST", "/pao/v1/credentials", credReq({ order_ref: "ORD-ps05-adp", amount_max: 50_000 }));
    expect([again.statusCode, (again.json() as Credential).status, (again.json() as Credential).payload]).toEqual([201, "USED", c.payload]);
  });

  it("мандат не найден или не по форме — 404; тело не по схеме — 400 REQUEST_INVALID; без ключа — 400 IDEMPOTENCY_REQUIRED", async () => {
    const unknown = await call("POST", "/pao/v1/credentials", credReq({ mandate_id: "mnd_00000000-0000-8000-8000-000000000000" }));
    expect([unknown.statusCode, unknown.json().code]).toEqual([404, "MANDATE_NOT_FOUND"]);
    // Вид реквизита — после мандата (РП47 п. 4, ревью КТ1 З3): несуществующий мандат + SBP — 404, а не CREDENTIAL_INVALID.
    const sbp = await call("POST", "/pao/v1/credentials", credReq({ mandate_id: "mnd_00000000-0000-8000-8000-000000000000", kind: "SBP" }));
    expect([sbp.statusCode, sbp.json().code]).toEqual([404, "MANDATE_NOT_FOUND"]);
    const form = await call("POST", "/pao/v1/credentials", credReq({ mandate_id: "MND-1" }));
    expect([form.statusCode, form.json().code]).toEqual([404, "MANDATE_NOT_FOUND"]);
    for (const bad of [credReq({ amount_max: 0 }), credReq({ currency: "rub" }), credReq({ kind: "PAN" }), credReq({ order_ref: "" }), "[]"]) {
      const res = await call("POST", "/pao/v1/credentials", bad);
      expect([res.statusCode, res.json().code]).toEqual([400, "REQUEST_INVALID"]);
    }
    const nokey = await call("POST", "/pao/v1/credentials", credReq(), null);
    expect([nokey.statusCode, nokey.json().code]).toEqual([400, "IDEMPOTENCY_REQUIRED"]);
  });
});
