// Идемпотентность POST /pao/v1/agent/keys на PostgreSQL (РП30 п. 3, 7 и дополнение — хэш ключа; Ш16). PG-тесты — только
// при DATABASE_URL: локально пропуск, в CI их выполнение сторожит tests/unit/pg.test.ts.
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  PaoRequestVerifier,
  idempotencyKeyHash,
  idempotencyScope,
  paoIdempotency,
  paoNonceStore,
} from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { signedInject } from "../support/signed-inject.js";
import { memoryConsent } from "../support/consent.js";

const params = loadParams();
const SKEW = params.signature_skew_sec;
const A = "nspk:agent:buyref-01:v3";
const B = "nspk:agent:other-01:v1";
const PATH = "/pao/v1/agent/keys";

type Client = pg.Pool | { query: () => Promise<never> };

/** Реестр в памяти с A и B; «экземпляр шлюза» — сервер на своём пуле той же базы (nonce и идемпотентность — PG). */
function platform() {
  const store = new InMemoryAgentRegistryStore();
  const reg = new AgentRegistry(store, { keys: params });
  const keys = new AgentKeys(store, { keys: params });
  const sides = new Map<string, AgentSide>();
  for (const code of [A, B]) {
    const side = newAgentSide();
    expect(reg.admit(buyerApplication(code, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    sides.set(code, side);
  }
  const apps: FastifyInstance[] = [];
  const instance = (idem: Client, nonces: Client = idem): FastifyInstance => {
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => reg.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: SKEW, nonces: paoNonceStore({ client: nonces, skewSec: SKEW }) },
    );
    const app = buildServer({
      env: "sandbox",
      pao: { verifier, keys, idempotency: paoIdempotency({ client: idem, ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    });
    apps.push(app);
    return app;
  };
  return { keys, sides, instance, close: () => Promise.all(apps.map((a) => a.close())) };
}

const keyBody = (pub: string) => JSON.stringify({ alg: "ed25519", public_key: pub });

describe.skipIf(!DATABASE_URL)("идемпотентность ПАО на PostgreSQL (РП30 п. 3, Ш16)", () => {
  let db: TestDb;
  let p: ReturnType<typeof platform> | undefined;
  beforeAll(async () => {
    db = await openTestDb("idem");
  });
  afterEach(async () => {
    await p?.close();
    p = undefined;
  });
  afterAll(async () => {
    await db?.close();
  });

  const post = (app: FastifyInstance, side: AgentSide, code: string, body: string, key: string) =>
    signedInject(app, side, code, { method: "POST", path: PATH, body, headers: { "idempotency-key": key } });
  const stored = async (code: string) =>
    (await db.pool.query<{ key: string; state: string }>("SELECT key, state FROM core_idempotency WHERE scope = $1", [
      idempotencyScope(code),
    ])).rows;

  it("повтор после «перезапуска» (новый экземпляр на той же базе) — прежний ответ, второго ключа нет", async () => {
    p = platform();
    const a = p.sides.get(A)!;
    const key = randomUUID();
    const body = keyBody(newAgentSide().publicKey);
    const first = await post(p.instance(db.pool), a, A, body, key);
    const again = await post(p.instance(db.reopen()), a, A, body, key);
    expect([first.statusCode, again.statusCode]).toEqual([201, 201]);
    expect(again.json()).toEqual(first.json());
    expect(p.keys.list(A)).toHaveLength(2);
  });

  it("в хранилище — SHA-256 от Idempotency-Key, область pao:<agent_code>; ключ 16 КБ → 201 и повтор, не 503", async () => {
    p = platform();
    const a = p.sides.get(A)!;
    const key = "k".repeat(16 * 1024);
    const body = keyBody(newAgentSide().publicKey);
    const app = p.instance(db.pool);
    const first = await post(app, a, A, body, key);
    const again = await post(app, a, A, body, key);
    expect([first.statusCode, again.statusCode]).toEqual([201, 201]);
    expect(again.json()).toEqual(first.json());
    expect(await stored(A)).toContainEqual({ key: idempotencyKeyHash(key), state: "DONE" });
    expect((await stored(A)).every((r) => /^[0-9a-f]{64}$/.test(r.key))).toBe(true);
  });

  it("из 20 одновременных одинаковых обращений на двух экземплярах — один ключ; остальные — повтор или 503 same_key", async () => {
    p = platform();
    const a = p.sides.get(A)!;
    const key = randomUUID();
    const body = keyBody(newAgentSide().publicKey);
    const g1 = p.instance(db.pool);
    const g2 = p.instance(db.reopen());
    const res = await Promise.all(Array.from({ length: 20 }, (_, i) => post(i % 2 ? g1 : g2, a, A, body, key)));
    const codes = res.map((r) => r.statusCode);
    expect(codes.every((c) => c === 201 || c === 503)).toBe(true);
    expect(codes.filter((c) => c === 201).length).toBeGreaterThanOrEqual(1);
    for (const r of res.filter((x) => x.statusCode === 503)) expect(r.json()).toMatchObject({ retry: "same_key" });
    const ok = res.filter((r) => r.statusCode === 201).map((r) => r.json());
    for (const x of ok) expect(x).toEqual(ok[0]);
    expect(p.keys.list(A)).toHaveLength(2);
  });

  it("тот же Idempotency-Key у другого агента — не повтор (Ш16)", async () => {
    p = platform();
    const key = randomUUID();
    const app = p.instance(db.pool);
    const nb = newAgentSide();
    expect((await post(app, p.sides.get(A)!, A, keyBody(newAgentSide().publicKey), key)).statusCode).toBe(201);
    const rb = await post(app, p.sides.get(B)!, B, keyBody(nb.publicKey), key);
    expect(rb.statusCode).toBe(201);
    expect(rb.json().kid).toBe(nb.kid);
  });

  it("другое тело с тем же ключом — 409 IDEMPOTENCY_CONFLICT", async () => {
    p = platform();
    const a = p.sides.get(A)!;
    const key = randomUUID();
    const app = p.instance(db.pool);
    expect((await post(app, a, A, keyBody(newAgentSide().publicKey), key)).statusCode).toBe(201);
    const other = await post(app, a, A, keyBody(newAgentSide().publicKey), key);
    expect(other.statusCode).toBe(409);
    expect(other.json()).toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    expect(p.keys.list(A)).toHaveLength(2);
  });

  it("сбой хранилища идемпотентности — 503 до обработчика, ключ не добавлен, тело без текста исключения", async () => {
    p = platform();
    const failing = {
      query: async (): Promise<never> => {
        throw new Error("connect ECONNREFUSED secret-db:5432");
      },
    };
    const res = await post(p.instance(failing, db.pool), p.sides.get(A)!, A, keyBody(newAgentSide().publicKey), randomUUID());
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe(String(params.unavailable_retry_after_sec));
    expect(res.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    expect(res.body).not.toContain("secret-db");
    expect(p.keys.list(A)).toHaveLength(1);
  });
});
