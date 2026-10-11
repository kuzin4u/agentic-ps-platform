// ПС02 · негатив · П1/П4/П9 · Отзыв ключа и распространение (A2 п. 5.4, ФП2, РП23 п. 5).
// Закрыто по ПАО: 401 AGENT_KEY_REVOKED и время до проверки подписи. Замер внутрипроцессный (одно хранилище в памяти);
// настоящая проверка ФП2 — после CO-1/CO-2 и PS-10 (распространение в ADP, хранилище PostgreSQL).
import { performance } from "node:perf_hooks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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

  it("принятое до отзыва не отменяется; после отзыва новый ключ оператора работает, старый — нет", async () => {
    const before = await signedInject(s.app, side, CODE);
    s.keys.revoke(CODE, side.kid);
    expect(before.statusCode).toBe(200);
    const next = newAgentSide();
    s.keys.register(CODE, { alg: "ed25519", public_key: next.publicKey });
    expect((await signedInject(s.app, next, CODE)).statusCode).toBe(200);
    expect((await signedInject(s.app, side, CODE)).statusCode).toBe(401);
    expect((await signedInject(s.app, next, CODE)).json().keys.map((k: { kid: string }) => k.kid)).toEqual([next.kid]);
  });

  it.todo("распространение отзыва в ADP ≤ revocation_propagation_max_ms — PS-10 (точка решения), PS-17");
  it.todo("продавец проводит авторизацию с ранее выданной криптограммой — PS-14 (реквизиты), PS-10");
});
