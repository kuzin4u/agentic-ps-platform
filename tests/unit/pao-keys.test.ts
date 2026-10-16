// POST /pao/v1/agent/keys по HTTP (PS-05 К2.4): РП23 п. 2–4, РП30 п. 3 и дополнение (хэш ключа), РП31; Ш16.
// Хранилище идемпотентности — память ядра (стенд); тот же договор на PostgreSQL — pao-idempotency-pg.test.ts.
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  PaoRequestVerifier,
  idempotencyKeyHash,
  idempotencyScope,
  paoIdempotency,
  type PaoIdempotency,
} from "../../src/pao/index.js";
import {
  AgentExcludedError,
  AgentKeys,
  AgentRegistry,
  ConcurrentChangeError,
  InMemoryAgentRegistryStore,
  KeyInvalidError,
} from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const A = "nspk:agent:buyref-01:v3";
const B = "nspk:agent:other-01:v1";
const PATH = "/pao/v1/agent/keys";
const spkiOf = (hex: string): string =>
  Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]).toString("base64");
const IDENTITY = spkiOf("0100000000000000000000000000000000000000000000000000000000000000");

describe("POST /pao/v1/agent/keys", () => {
  let s: Stand;
  let a: AgentSide;
  let b: AgentSide;

  beforeEach(() => {
    s = stand();
    a = newAgentSide();
    b = newAgentSide();
    expect(s.admit(buyerApplication(A, a), "op").admitted).toBe(true);
    expect(s.admit(buyerApplication(B, b), "op").admitted).toBe(true);
  });
  afterEach(async () => {
    await s.app.close();
  });

  const post = (side: AgentSide, code: string, body: string, key: string | null = randomUUID(), query = "") =>
    signedInject(s.app, side, code, {
      method: "POST",
      path: PATH,
      query,
      body,
      headers: key === null ? {} : { "idempotency-key": key },
    });
  const keyBody = (pub: string, extra: Record<string, unknown> = {}) =>
    JSON.stringify({ alg: "ed25519", public_key: pub, ...extra });
  const keysOf = (code: string) => s.keys.list(code);

  it("новый ключ → 201 Key ACTIVE; у прежнего valid_to сокращается до перекрытия (A2 п. 5.3, РП23 п. 4)", async () => {
    const n = newAgentSide();
    const res = await post(a, A, keyBody(n.publicKey));
    expect(res.statusCode).toBe(201);
    const key = res.json();
    expect(key).toEqual({
      kid: n.kid,
      alg: "ed25519",
      public_key: n.publicKey,
      valid_from: expect.any(String),
      valid_to: expect.any(String),
      status: "ACTIVE",
    });
    const old = keysOf(A).find((k) => k.kid === a.kid)!;
    const overlapEnd = Date.parse(key.valid_from) + s.params.key_overlap_days * 86_400_000;
    expect(Date.parse(old.valid_to ?? "")).toBe(overlapEnd);
    // Новым ключом агент подписывает следующее обращение.
    expect((await signedInject(s.app, n, A)).statusCode).toBe(200);
  });

  it("без Idempotency-Key → 400 IDEMPOTENCY_REQUIRED, раньше проверки тела; ключ не добавлен", async () => {
    for (const body of [keyBody(newAgentSide().publicKey), "не json"]) {
      const res = await post(a, A, body, null);
      expect(res.statusCode).toBe(400);
      expect(res.json()).toMatchObject({ code: "IDEMPOTENCY_REQUIRED", retry: "same_key" });
    }
    expect(await post(a, A, keyBody(newAgentSide().publicKey), "")).toMatchObject({ statusCode: 400 });
    expect(keysOf(A)).toHaveLength(1);
  });

  it("тело не по схеме → 400 REQUEST_INVALID без фрагментов тела; ключ идемпотентности не занят (РП31 п. 1)", async () => {
    const key = randomUUID();
    const bad = [
      "не json",
      "",
      "[]",
      "null",
      JSON.stringify({ alg: "ed25519" }),
      JSON.stringify({ public_key: "секрет-фрагмент" }),
      JSON.stringify({ alg: 1, public_key: "секрет-фрагмент" }),
      JSON.stringify({ alg: "ed25519", public_key: ["секрет-фрагмент"] }),
    ];
    for (const body of bad) {
      const res = await post(a, A, body, key);
      expect(res.statusCode, body).toBe(400);
      expect(res.json()).toEqual({ code: "REQUEST_INVALID", message: expect.any(String), retry: "after_fix" });
      expect(res.body).not.toContain("секрет-фрагмент");
    }
    // Тот же ключ с верным телом — исполняется: неполный запрос ключ не занимал.
    expect((await post(a, A, keyBody(newAgentSide().publicKey), key)).statusCode).toBe(201);
  });

  it("тело с чужим типом содержимого или без типа → ответ ПАО §6, а не 415 Fastify", async () => {
    for (const type of ["application/x-www-form-urlencoded", "text/plain", null]) {
      const res = await signedInject(s.app, a, A, {
        method: "POST",
        path: PATH,
        body: "alg=ed25519",
        headers: { "idempotency-key": randomUUID(), "content-type": type },
      });
      expect(res.statusCode, String(type)).toBe(400);
      expect(res.json()).toMatchObject({ code: "REQUEST_INVALID" });
    }
  });

  it("недопустимый ключ → 422 KEY_INVALID, причина не раскрывается (РП31 п. 2)", async () => {
    const cases = [
      keyBody(IDENTITY), // слабый (РП23 доп. 1)
      keyBody(a.publicKey), // уже у себя
      keyBody(b.publicKey), // уже у другого агента
      JSON.stringify({ alg: "gost", public_key: newAgentSide().publicKey }), // alg не из контура
      keyBody("не-base64"),
    ];
    const bodies = [];
    for (const body of cases) {
      const res = await post(a, A, body);
      expect(res.statusCode, body).toBe(422);
      bodies.push(res.json());
    }
    for (const x of bodies) expect(x).toEqual({ code: "KEY_INVALID", message: bodies[0].message, norm: "A2 п. 5.1", retry: "after_fix" });
    expect(keysOf(A)).toHaveLength(1);
  });

  it("причина отказа — в журнале процесса, закрытым перечнем (РП31 п. 2)", () => {
    const reason = (input: unknown): string | undefined => {
      try {
        s.keys.register(A, input, { requireActive: true });
      } catch (e) {
        return e instanceof KeyInvalidError ? e.reason : "другое";
      }
      return undefined;
    };
    expect(reason({ alg: "gost", public_key: newAgentSide().publicKey })).toBe("ALG");
    expect(reason({ alg: "ed25519", public_key: IDENTITY })).toBe("KEY");
    expect(reason({ alg: "ed25519", public_key: "не-base64" })).toBe("KEY");
    expect(reason({ alg: "ed25519", public_key: b.publicKey })).toBe("TAKEN");
  });

  it("повтор с тем же ключом → прежний ответ, второго ключа нет (РП30 п. 3)", async () => {
    const key = randomUUID();
    const body = keyBody(newAgentSide().publicKey);
    const first = await post(a, A, body, key);
    const again = await post(a, A, body, key);
    expect(first.statusCode).toBe(201);
    expect(again.statusCode).toBe(201);
    expect(again.json()).toEqual(first.json());
    expect(keysOf(A)).toHaveLength(2);
  });

  it("повтор отказа 422 — тот же отказ из хранилища (4xx сохраняется)", async () => {
    const key = randomUUID();
    const first = await post(a, A, keyBody(IDENTITY), key);
    const spy = vi.spyOn(s.keys, "register");
    const again = await post(a, A, keyBody(IDENTITY), key);
    expect([first.statusCode, again.statusCode]).toEqual([422, 422]);
    expect(again.json()).toEqual(first.json());
    expect(spy).not.toHaveBeenCalled();
  });

  it("тот же ключ, другое тело или другой запрос → 409 IDEMPOTENCY_CONFLICT", async () => {
    const key = randomUUID();
    expect((await post(a, A, keyBody(newAgentSide().publicKey), key)).statusCode).toBe(201);
    const other = await post(a, A, keyBody(newAgentSide().publicKey), key);
    expect(other.statusCode).toBe(409);
    expect(other.json()).toMatchObject({ code: "IDEMPOTENCY_CONFLICT", retry: "after_fix" });
    const q = await post(a, A, keyBody(newAgentSide().publicKey), key, "x=1");
    expect(q.statusCode).toBe(409);
    expect(keysOf(A)).toHaveLength(2);
  });

  it("тот же Idempotency-Key у другого агента — не повтор: свой ответ, свой ключ (Ш16)", async () => {
    const key = randomUUID();
    const na = newAgentSide();
    const nb = newAgentSide();
    const ra = await post(a, A, keyBody(na.publicKey), key);
    const rb = await post(b, B, keyBody(nb.publicKey), key);
    expect([ra.statusCode, rb.statusCode]).toEqual([201, 201]);
    expect(rb.json().kid).toBe(nb.kid);
    expect(keysOf(B).map((k) => k.kid)).toContain(nb.kid);
    expect(keysOf(A).map((k) => k.kid)).not.toContain(nb.kid);
    expect(idempotencyScope(A)).not.toBe(idempotencyScope(B));
  });

  it("ключ идемпотентности длиннее порога индекса (16 КБ, без предела транспорта inject) → 201 и повтор, не 503 (РП30 п. 3, доп.)", async () => {
    const key = "k".repeat(16 * 1024);
    const body = keyBody(newAgentSide().publicKey);
    const first = await post(a, A, body, key);
    const again = await post(a, A, body, key);
    expect([first.statusCode, again.statusCode]).toEqual([201, 201]);
    expect(again.json()).toEqual(first.json());
    expect(idempotencyKeyHash(key)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("сбой обработчика → 503 с Retry-After, не сохраняется: повтор с тем же ключом исполняется заново", async () => {
    const key = randomUUID();
    const body = keyBody(newAgentSide().publicKey);
    vi.spyOn(s.keys, "register").mockImplementationOnce(() => {
      throw new Error("сбой реестра");
    });
    const failed = await post(a, A, body, key);
    expect(failed.statusCode).toBe(503);
    expect(failed.headers["retry-after"]).toBe(String(s.params.unavailable_retry_after_sec));
    expect(failed.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    expect(failed.body).not.toContain("сбой реестра");
    expect((await post(a, A, body, key)).statusCode).toBe(201);
  });

  it("приостановлен после проверки обращения, до вставки ключа → 403 AGENT_SUSPENDED, ключ не добавлен (гонка)", async () => {
    const register = s.keys.register.bind(s.keys);
    vi.spyOn(s.keys, "register").mockImplementationOnce((code, input, o) => {
      s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
      return register(code, input, o);
    });
    const res = await post(a, A, keyBody(newAgentSide().publicKey));
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
    expect(keysOf(A)).toHaveLength(1);
  });

  it("исключён до вставки → 403, ответ сохраняется; конкурентное изменение → 503, не сохраняется", async () => {
    const key = randomUUID();
    const body = keyBody(newAgentSide().publicKey);
    vi.spyOn(s.keys, "register").mockImplementationOnce(() => {
      throw new AgentExcludedError(A);
    });
    expect((await post(a, A, body, key)).statusCode).toBe(403);
    expect((await post(a, A, body, key)).statusCode).toBe(403);

    const key2 = randomUUID();
    vi.spyOn(s.keys, "register").mockImplementationOnce(() => {
      throw new ConcurrentChangeError(A);
    });
    expect((await post(a, A, body, key2)).statusCode).toBe(503);
    expect((await post(a, A, body, key2)).statusCode).toBe(201);
  });

  it("приостановленный агент → 403 AGENT_SUSPENDED: смена ключа — через оператора, не через ПАО (РП23 п. 6.3)", async () => {
    s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    const res = await post(a, A, keyBody(newAgentSide().publicKey));
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
    expect(keysOf(A)).toHaveLength(1);
  });

  it("без подписи → 401 до идемпотентности и тела", async () => {
    const res = await s.app.inject({
      method: "POST",
      url: PATH,
      headers: { "x-agent-code": A, "idempotency-key": randomUUID(), "content-type": "application/json" },
      payload: keyBody(newAgentSide().publicKey),
    });
    expect(res.statusCode).toBe(401);
    expect(keysOf(A)).toHaveLength(1);
  });
});

describe("POST /pao/v1/agent/keys: тот же ключ, пока первое обращение выполняется (РП30 п. 3)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  it("второе обращение → 503 UPSTREAM_UNAVAILABLE same_key с Retry-After; после завершения — повтор первого ответа", async () => {
    const params = loadParams();
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const a = newAgentSide();
    expect(registry.admit(buyerApplication(A, a), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    let entered: () => void = () => undefined;
    const inside = new Promise<void>((r) => (entered = r));
    const inner = paoIdempotency({ ttlSec: params.idempotency_ttl_sec });
    // Обработчик держится в хранилище до release(): захват ключа — у первого обращения.
    const held: PaoIdempotency = (code) => {
      const st = inner(code);
      return {
        run: (k, body, fn) =>
          st.run(k, body, async () => {
            entered();
            await gate;
            return fn();
          }),
      };
    };
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    app = buildServer({ env: "sandbox", pao: { verifier, keys, idempotency: held, params } });
    const key = randomUUID();
    const body = JSON.stringify({ alg: "ed25519", public_key: newAgentSide().publicKey });
    const call = () =>
      signedInject(app!, a, A, { method: "POST", path: PATH, body, headers: { "idempotency-key": key } });
    const first = call();
    await inside;
    const second = await call();
    expect(second.statusCode).toBe(503);
    expect(second.headers["retry-after"]).toBe(String(params.unavailable_retry_after_sec));
    expect(second.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    release();
    const done = await first;
    expect(done.statusCode).toBe(201);
    const again = await call();
    expect(again.json()).toEqual(done.json());
    expect(keys.list(A)).toHaveLength(2);
  });
});
