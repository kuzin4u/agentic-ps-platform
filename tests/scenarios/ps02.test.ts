// ПС02 · негатив · П1/П4/П9 · Отзыв ключа и распространение (A2 п. 5.4, ФП2, РП23 п. 5).
// Закрыто по ПАО: 401 AGENT_KEY_REVOKED и время до проверки подписи. Замер внутрипроцессный (одно хранилище в памяти);
// настоящая проверка ФП2 — после CO-1/CO-2 и PS-10 (распространение в ADP, хранилище PostgreSQL).
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const CODE = "nspk:agent:buyref-01:v3";

describe("ПС02: отзыв ключа и распространение", () => {
  let s: Stand;
  let side: AgentSide;

  beforeEach(() => {
    s = stand();
    side = newAgentSide();
    const d = s.registry.admit(buyerApplication(CODE, side), { contour: "sandbox", operator: "buyref-operator" });
    expect(d.admitted).toBe(true);
  });
  afterEach(async () => {
    await s.app.close();
  });

  it("оператор агента отзывает скомпрометированный ключ; обращение старым ключом — 401 AGENT_KEY_REVOKED, retry new_key", async () => {
    expect((await signedInject(s.app, side, CODE)).statusCode).toBe(200);
    // Оператор агента — вызывающий сервиса ключей; его аутентификация — SEC-1 (расхождение №9).
    s.keys.revoke(CODE, side.kid);
    const res = await signedInject(s.app, side, CODE);
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({
      code: "AGENT_KEY_REVOKED",
      message: expect.any(String),
      norm: "A2 п. 5.4",
      retry: "new_key",
    });
  });

  it("время распространения отзыва до проверки подписи ≤ revocation_propagation_max_ms — измерено (внутрипроцессно)", async () => {
    const t0 = performance.now();
    s.keys.revoke(CODE, side.kid);
    const res = await signedInject(s.app, side, CODE);
    const elapsed = performance.now() - t0;
    expect(res.json().code).toBe("AGENT_KEY_REVOKED");
    console.info(`ПС02: отзыв → отказ проверки подписи за ${elapsed.toFixed(2)} мс (порог ${s.params.revocation_propagation_max_ms} мс)`);
    expect(elapsed).toBeLessThanOrEqual(s.params.revocation_propagation_max_ms);
  });

  it("после отзыва и регистрации нового ключа оператором: новый ключ — 200, старый — 401; в GET /agent только новый", async () => {
    const before = await signedInject(s.app, side, CODE);
    s.keys.revoke(CODE, side.kid);
    expect(before.statusCode).toBe(200);
    const next = newAgentSide();
    s.keys.register(CODE, { alg: "ed25519", public_key: next.publicKey });
    expect((await signedInject(s.app, next, CODE)).statusCode).toBe(200);
    expect((await signedInject(s.app, side, CODE)).statusCode).toBe(401);
    expect((await signedInject(s.app, next, CODE)).json().keys.map((k: { kid: string }) => k.kid)).toEqual([next.kid]);
  });

  it.todo("авторизованное до отзыва исполняется (инвариант 8) — PS-10 (ADP), PS-14 (криптограмма)");
  it.todo("распространение отзыва в ADP ≤ revocation_propagation_max_ms — PS-10 (точка решения), PS-17");
  // Решение владельца 20.10 (РП47 доп. п. 8): отзыв ключа подписи не аннулирует выданный реквизит — он привязан к
  // мандату, CART, продавцу и сумме, агент ACTIVE; при компрометации агента приостанавливают (PS-17), а пакет оплаты с
  // отозванным ключом отклоняет продавец по каталогу ключей (РП22).
  it("продавец проводит авторизацию с ранее выданной криптограммой после отзыва ключа — APPROVE (ADP ключ ПАО не проверяет)", async () => {
    const call = (body: unknown) =>
      signedInject(s.app, side, CODE, { method: "POST", path: "/pao/v1/mandates", body: JSON.stringify(body), headers: { "idempotency-key": randomUUID() } });
    const base: MandateRequest = {
      type: "INTENT",
      subject: "продукты",
      amount_limit: 50_000,
      currency: "RUB",
      // Срок в пределах простой подписи (qualified_signature_above_days, РП36 п. 6).
      valid_to: new Date(s.now().getTime() + 3 * 86_400_000).toISOString(),
      merchant_scope: ["MER-1042"],
      principal_ref: "prn_ps_two",
      mode: "IMMEDIATE",
    };
    const intent = (await call(base)).json() as { id: string };
    expect((await s.issuer.sign(intent.id)).statusCode).toBe(200);
    const cart = (
      await call({
        ...base,
        type: "CART",
        parent_id: intent.id,
        amount_limit: 20_000,
        cart: { merchant_id: "MER-1042", items: [{ sku: "x", qty: 1, price: 20_000 }], total: 20_000 },
      })
    ).json() as { id: string };
    expect((await s.issuer.sign(cart.id)).statusCode).toBe(200);
    const res = await signedInject(s.app, side, CODE, {
      method: "POST",
      path: "/pao/v1/credentials",
      body: JSON.stringify({ mandate_id: cart.id, order_ref: "ORD-ps02", merchant_id: "MER-1042", amount_max: 20_000, currency: "RUB", kind: "CARD" }),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;

    s.keys.revoke(CODE, side.kid);
    expect((await signedInject(s.app, side, CODE)).json().code).toBe("AGENT_KEY_REVOKED");

    const msg: CanonicalMessage = {
      op_ref: `OPKC-PS02-${randomUUID()}`,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: 15_000,
      currency: "RUB",
      merchant: { id: "MER-1042" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
    };
    const d = parseDecision((await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json(), "adp");
    expect(d.decision).toBe("APPROVE");
  });
});
