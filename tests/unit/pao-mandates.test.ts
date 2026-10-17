// POST /pao/v1/mandates по HTTP (PS-06 К1.3): РП33 (отказы журнала → коды ПАО), РП31 (REQUEST_INVALID до захвата
// ключа), РП30 п. 3 (повтор — тот же ответ); agent_code — из обращения (инвариант 5). Журнал — память ядра.
import { createHash, randomUUID } from "node:crypto";
import { AsyncHashChainJournal, type JournalEntry } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ConsentJournal, mandateIdFor, MemoryConsentStore, type ConsentStore } from "../../src/consent/index.js";
import {
  assertHandlerBudget,
  PAO_DB_TIMEOUT_MS,
  PAO_HANDLER_BUDGET_MS,
  PAO_IDEMPOTENCY_LEASE_MS,
  PaoRequestVerifier,
  paoIdempotency,
  type PaoIdempotency,
} from "../../src/pao/index.js";
import { PARENT_REJECTED_MESSAGE } from "../../src/pao/consent-errors.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const A = "nspk:agent:mand-a:v1";
const B = "nspk:agent:mand-b:v1";
const PATH = "/pao/v1/mandates";
/** Срок — один на файл: у CART не позже родителя (сужение, A7 п. 5). */
const VALID_TO = new Date(Date.now() + 7 * 86_400_000).toISOString();

const intent = (over: Record<string, unknown> = {}) => ({
  type: "INTENT",
  subject: "секрет-предмет молоко",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: VALID_TO,
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});
const cart = (parent_id: string, over: Record<string, unknown> = {}) =>
  intent({
    type: "CART",
    parent_id,
    amount_limit: 1_000,
    cart: { merchant_id: "MER-1042", items: [{ sku: "milk", qty: 1, price: 1_000 }], total: 1_000 },
    ...over,
  });

describe("POST /pao/v1/mandates", () => {
  let app: FastifyInstance;
  let store: ConsentStore;
  /** Сдвиг часов журнала: истечение родителя без ожидания (подпись обращений — по настоящим часам). */
  let shiftMs = 0;
  let a: AgentSide;
  let b: AgentSide;
  /** Хранилище идемпотентности; новое — как память ключей ядра, истёкшая за TTL. */
  let idem: PaoIdempotency;
  let failDone = false;
  /** Часы предела обработчика (РП33 доп.). */
  let clockMs = 0;

  beforeEach(() => {
    const params = loadParams();
    const reg = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(reg, { keys: params });
    const keys = new AgentKeys(reg, { keys: params });
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    store = new MemoryConsentStore();
    shiftMs = 0;
    clockMs = 0;
    failDone = false;
    const consent = new ConsentJournal(store, { now: () => new Date(Date.now() + shiftMs) });
    idem = paoIdempotency({ ttlSec: params.idempotency_ttl_sec });
    // Сбой отметки DONE: обработчик исполнен, результат не сохранён — ядро снова отдаст ключ (аренда истекла).
    const idempotency: PaoIdempotency = (code) => ({
      run: async (k, body, fn) => {
        if (!failDone) return idem(code).run(k, body, fn);
        failDone = false;
        await fn();
        throw new Error("отметка DONE не записана");
      },
    });
    app = buildServer({ env: "dev", pao: { verifier, keys, idempotency, params, consent, clock: () => clockMs } });
    a = newAgentSide();
    b = newAgentSide();
    expect(registry.admit(buyerApplication(A, a), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    expect(registry.admit(buyerApplication(B, b), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
  });
  afterEach(async () => {
    await app.close();
  });

  const post = (side: AgentSide, code: string, body: unknown, key: string | null = randomUUID()) =>
    signedInject(app, side, code, {
      method: "POST",
      path: PATH,
      body: typeof body === "string" ? body : JSON.stringify(body),
      headers: key === null ? {} : { "idempotency-key": key },
    });
  /** Подпись принципала — часть 2 PS-06; здесь — запись MANDATE_SIGNED напрямую. */
  const sign = async (id: string) => {
    const row = (await store.getMandate(id))!;
    await new AsyncHashChainJournal(store.journal(row.chain)).append("MANDATE_SIGNED", `${id}:signed`, {}, id);
  };
  const append = async (id: string, kind: string) => {
    const row = (await store.getMandate(id))!;
    await new AsyncHashChainJournal(store.journal(row.chain)).append(kind, `${id}:${kind}`, {}, id);
  };

  it("201 Mandate PENDING_SIGNATURE; agent_code — из обращения, не из тела (инвариант 5)", async () => {
    const res = await post(a, A, { ...intent(), agent_code: B, status: "ACTIVE", signature_type: "qualified" });
    expect(res.statusCode).toBe(201);
    const m = res.json();
    expect(m).toMatchObject({ type: "INTENT", status: "PENDING_SIGNATURE", agent_code: A, amount_limit: 50_000, currency: "RUB" });
    expect(m.id).toMatch(/^mnd_/);
    expect(m).not.toHaveProperty("signature_type");
  });

  it("повтор с тем же Idempotency-Key — тот же 201 и тот же мандат; тот же ключ, другое тело — IDEMPOTENCY_CONFLICT", async () => {
    const key = randomUUID();
    const r1 = await post(a, A, intent({ valid_to: "2030-01-01T00:00:00Z" }), key);
    const r2 = await post(a, A, intent({ valid_to: "2030-01-01T00:00:00Z" }), key);
    expect(r1.statusCode).toBe(201);
    expect(r2.statusCode).toBe(201);
    expect(r2.json()).toEqual(r1.json());
    const r3 = await post(a, A, intent({ valid_to: "2030-01-01T00:00:00Z", amount_limit: 1 }), key);
    expect(r3.statusCode).toBe(409);
    expect(r3.json()).toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("без Idempotency-Key — 400 IDEMPOTENCY_REQUIRED", async () => {
    const res = await post(a, A, intent(), null);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ code: "IDEMPOTENCY_REQUIRED" });
  });

  it("тело не по схеме — 400 REQUEST_INVALID без фрагментов тела; ключ не занят (РП31 п. 1)", async () => {
    const key = randomUUID();
    const bad: unknown[] = [
      "не json",
      "[]",
      { ...intent(), type: "PAYMENT" },
      { ...intent(), amount_limit: 0 },
      { ...intent(), amount_limit: "1000" },
      { ...intent(), merchant_scope: "MER-1042" },
      { ...intent(), subject: undefined },
      { ...intent(), cart: { items: "секрет-предмет" } },
      { ...intent(), conditional: { provider: 1 } },
    ];
    for (const body of bad) {
      const res = await post(a, A, body, key);
      expect(res.statusCode, JSON.stringify(body)).toBe(400);
      expect(res.json()).toMatchObject({ code: "REQUEST_INVALID", retry: "after_fix" });
      expect(res.body).not.toContain("секрет-предмет");
    }
    expect((await post(a, A, intent(), key)).statusCode).toBe(201);
  });

  it("реквизит недопустим (FIELD_INVALID) — 400 REQUEST_INVALID, причина не раскрывается, тело не отражается", async () => {
    for (const over of [{ principal_ref: "79990000000" }, { valid_to: "2020-01-01T00:00:00Z" }, { currency: "rub" }]) {
      const res = await post(a, A, intent(over));
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ code: "REQUEST_INVALID", message: expect.any(String), norm: "A7 п. 2", retry: "after_fix" });
      expect(res.body).not.toContain("principal_ref");
      expect(res.body).not.toContain("79990000000");
    }
  });

  it("CART: родитель неизвестный или чужой — 404 MANDATE_NOT_FOUND", async () => {
    const p = (await post(a, A, intent())).json();
    await sign(p.id);
    for (const [side, code, parent] of [
      [a, A, "mnd_00000000-0000-4000-8000-000000000000"],
      [b, B, p.id],
    ] as const) {
      const res = await post(side, code, cart(parent));
      expect(res.statusCode).toBe(404);
      expect(res.json()).toMatchObject({ code: "MANDATE_NOT_FOUND", retry: "after_human" });
    }
  });

  it("CART: родитель не подписан, отклонён, отозван — 409 с кодом по статусу (РП33 п. 1–2)", async () => {
    const pending = (await post(a, A, intent())).json();
    let res = await post(a, A, cart(pending.id));
    expect([res.statusCode, res.json().code]).toEqual([409, "PRINCIPAL_SIGNATURE_PENDING"]);

    const rejectedP = (await post(a, A, intent())).json();
    await append(rejectedP.id, "MANDATE_REJECTED");
    res = await post(a, A, cart(rejectedP.id));
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: "MANDATE_REVOKED", message: PARENT_REJECTED_MESSAGE, retry: "never" });

    const revoked = (await post(a, A, intent())).json();
    await sign(revoked.id);
    await append(revoked.id, "MANDATE_REVOKED");
    res = await post(a, A, cart(revoked.id));
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe("MANDATE_REVOKED");
    expect(res.json().message).not.toBe(PARENT_REJECTED_MESSAGE);
  });

  it("CART шире родителя — 409 MANDATE_SCOPE; CART под CART — 400 REQUEST_INVALID; сужение — 201", async () => {
    const p = (await post(a, A, intent())).json();
    await sign(p.id);
    const wide = await post(a, A, cart(p.id, { amount_limit: 60_000 }));
    expect([wide.statusCode, wide.json().code]).toEqual([409, "MANDATE_SCOPE"]);
    const other = await post(a, A, cart(p.id, { principal_ref: "prn_other" }));
    expect([other.statusCode, other.json().code]).toEqual([409, "MANDATE_SCOPE"]);
    const ok = await post(a, A, cart(p.id));
    expect(ok.statusCode).toBe(201);
    await sign(ok.json().id);
    const nested = await post(a, A, cart(ok.json().id));
    expect([nested.statusCode, nested.json().code]).toEqual([400, "REQUEST_INVALID"]);
  });

  it("нарушенная цепочка родителя — 503 STATE_UNAVAILABLE с Retry-After; не сохранён: после восстановления тот же ключ — 201", async () => {
    const p = (await post(a, A, intent())).json();
    await sign(p.id);
    const rows = (await store.journal((await store.getMandate(p.id))!.chain).all()) as JournalEntry[];
    const original = rows[0]!;
    rows[0] = { ...original, payload: { ...(original.payload as object), amount_limit: 99_999_999 } };
    const key = randomUUID();
    const res = await post(a, A, cart(p.id), key);
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ code: "STATE_UNAVAILABLE", retry: "same_key" });
    expect(res.headers["retry-after"]).toBeDefined();
    // 5xx не сохранён (РП30 п. 3): сохранённый 503 вернулся бы и после восстановления цепочки.
    rows[0] = original;
    const again = await post(a, A, cart(p.id), key);
    expect(again.statusCode).toBe(201);
  });

  it("сбой хранилища — 503 UPSTREAM_UNAVAILABLE, не сохранён: повтор с тем же ключом — 201", async () => {
    const insert = store.insertMandate.bind(store);
    let fail = true;
    store.insertMandate = async (row) => {
      if (fail) throw new Error("db down: secret-host:5432");
      return insert(row);
    };
    const key = randomUUID();
    const res = await post(a, A, intent(), key);
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    expect(res.body).not.toContain("secret-host");
    fail = false;
    expect((await post(a, A, intent(), key)).statusCode).toBe(201);
  });

  it("родитель истёк — 409 MANDATE_EXPIRED; другая валюта CART — 409 MANDATE_SCOPE", async () => {
    const p = (await post(a, A, intent())).json();
    await sign(p.id);
    const usd = await post(a, A, cart(p.id, { currency: "USD" }));
    expect([usd.statusCode, usd.json().code]).toEqual([409, "MANDATE_SCOPE"]);
    shiftMs = 8 * 86_400_000;
    const res = await post(a, A, cart(p.id, { valid_to: new Date(Date.now() + 9 * 86_400_000).toISOString() }));
    expect([res.statusCode, res.json().code]).toEqual([409, "MANDATE_EXPIRED"]);
  });

  // РП33 доп. (`/audit` К1.3 № 2): id мандата от (агент, ключ) — повтор после сбоя находит записанный мандат.
  const heads = async (id: string) => {
    const row = (await store.getMandate(id))!;
    return (await store.journal(row.chain).all()).filter((e) => e.ref === id && e.kind === "MANDATE_REQUESTED");
  };
  const keyHash = (k: string) => createHash("sha256").update(k, "utf8").digest("hex");

  it("сбой отметки DONE: повтор тем же ключом — 201, тот же мандат, в журнале одна запись", async () => {
    const key = randomUUID();
    failDone = true;
    const r1 = await post(a, A, intent(), key);
    expect([r1.statusCode, r1.json().code]).toEqual([503, "UPSTREAM_UNAVAILABLE"]);
    const id = mandateIdFor(A, keyHash(key));
    expect(await heads(id)).toHaveLength(1);
    const r2 = await post(a, A, intent(), key);
    expect(r2.statusCode).toBe(201);
    expect(r2.json().id).toBe(id);
    expect(await heads(id)).toHaveLength(1);
  });

  it("ключ после срока памяти ядра: тот же запрос — тот же мандат (201), другой — 409 IDEMPOTENCY_CONFLICT", async () => {
    const key = randomUUID();
    const m = (await post(a, A, intent(), key)).json();
    idem = paoIdempotency({ ttlSec: 86_400 });
    const same = await post(a, A, intent(), key);
    expect([same.statusCode, same.json().id]).toEqual([201, m.id]);
    idem = paoIdempotency({ ttlSec: 86_400 });
    const other = await post(a, A, intent({ amount_limit: 1 }), key);
    expect([other.statusCode, other.json().code]).toEqual([409, "IDEMPOTENCY_CONFLICT"]);
    expect(other.body).not.toContain(m.id);
    expect(await heads(m.id)).toHaveLength(1);
  });

  it("предел обработчика исчерпан до записи — 503, после предела не пишется; повтор — 201, одна запись", async () => {
    // Последняя запись — не позже предела + худшей команды базы, раньше конца аренды; иначе шлюз не запускается.
    expect(() => assertHandlerBudget(PAO_HANDLER_BUDGET_MS, PAO_DB_TIMEOUT_MS, PAO_IDEMPOTENCY_LEASE_MS)).not.toThrow();
    expect(() => assertHandlerBudget(56_000, PAO_DB_TIMEOUT_MS, PAO_IDEMPOTENCY_LEASE_MS)).toThrow(/аренды/);
    const insert = store.insertMandate.bind(store);
    let slow = true;
    store.insertMandate = async (row) => {
      await insert(row);
      if (slow) clockMs += PAO_HANDLER_BUDGET_MS + 1;
    };
    const key = randomUUID();
    const r1 = await post(a, A, intent(), key);
    expect([r1.statusCode, r1.json().code]).toEqual([503, "UPSTREAM_UNAVAILABLE"]);
    const id = mandateIdFor(A, keyHash(key));
    expect(await store.getMandate(id)).toBeDefined();
    expect(await store.getSubject(id)).toBeUndefined();
    slow = false;
    const r2 = await post(a, A, intent(), key);
    expect([r2.statusCode, r2.json().id]).toEqual([201, id]);
    expect(await heads(id)).toHaveLength(1);
  });

  it("FIELD_INVALID сохраняется под ключом: повтор — тот же 400, другое тело — IDEMPOTENCY_CONFLICT (РП33 п. 1)", async () => {
    const key = randomUUID();
    const bad = intent({ principal_ref: "79990000000" });
    const r1 = await post(a, A, bad, key);
    expect([r1.statusCode, r1.json().code]).toEqual([400, "REQUEST_INVALID"]);
    expect((await post(a, A, bad, key)).json()).toEqual(r1.json());
    expect((await post(a, A, intent(), key)).json().code).toBe("IDEMPOTENCY_CONFLICT");
  });
});
