// POST /pao/v1/credentials под одним Idempotency-Key на двух экземплярах шлюза над одной PostgreSQL (РП48 (в), РП47 п. 3,
// 10; РП30 п. 3): одна запись реквизита, одна криптограмма у всех ответов, значения криптограммы нет ни в core_idempotency,
// ни в agent_credentials. Токен-сервис — один внешний компонент для обоих экземпляров. PG-тесты — только при DATABASE_URL.
import { randomUUID } from "node:crypto";
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Credentials, PgCredentialStore } from "../../src/credentials/index.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { createTokenServiceEmulator } from "../../src/env/tsp/index.js";
import { PaoRequestVerifier, idempotencyScope, paoIdempotency, paoNonceStore } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import type { Credential, Mandate } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { memoryConsent } from "../support/consent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { signedInject } from "../support/signed-inject.js";

const params = loadParams();
const SKEW = params.signature_skew_sec;
const A = "nspk:agent:cred-pg:v1";
let cseq = 0;

const cartOf = (id: string): Mandate =>
  ({
    id,
    type: "CART",
    parent_id: "mnd_00000000-0000-8000-8000-00000000a001",
    subject: "s",
    amount_limit: 189_000,
    currency: "RUB",
    valid_to: "2099-01-01T00:00:00Z",
    merchant_scope: ["MER-1042"],
    principal_ref: "pr_alpha",
    mode: "IMMEDIATE",
    agent_code: A,
    status: "ACTIVE",
  }) as Mandate;

/** Реестр в памяти с A; «экземпляр шлюза» — сервер на своём пуле той же базы; токен-сервис и банк — общие. */
function platform() {
  const store = new InMemoryAgentRegistryStore();
  const reg = new AgentRegistry(store, { keys: params });
  const keys = new AgentKeys(store, { keys: params });
  const side = newAgentSide();
  expect(reg.admit(buyerApplication(A, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
  const tsp = createTokenServiceEmulator();
  const issuer = createIssuerEmulator();
  const apps: FastifyInstance[] = [];
  const instance = (pool: SqlClient): FastifyInstance => {
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => reg.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: SKEW, nonces: paoNonceStore({ client: pool, skewSec: SKEW }) },
    );
    const credentials = new Credentials({
      mandates: {
        get: async (id, code) =>
          code === A && id.startsWith("mnd_")
            ? { mandate: cartOf(id), client: { participant_code: issuer.participant_code, principal_ref: "pr_alpha" }, token_consent: true }
            : undefined,
      },
      store: new PgCredentialStore(pool),
      tsp,
      funding: issuer,
      params: { cryptogram_ttl_sec: params.cryptogram_ttl_sec },
    });
    const app = buildServer({
      env: "sandbox",
      pao: {
        verifier,
        keys,
        idempotency: paoIdempotency({ client: pool, ttlSec: params.idempotency_ttl_sec }),
        params,
        consent: memoryConsent(),
        credentials,
      },
    });
    apps.push(app);
    return app;
  };
  const post = (app: FastifyInstance, body: string, key: string) =>
    signedInject(app, side, A, { method: "POST", path: "/pao/v1/credentials", body, headers: { "idempotency-key": key } });
  return { instance, post, close: () => Promise.all(apps.map((a) => a.close())) };
}

/** Свой CART на тест: записи реквизитов и токенов разных тестов одной схемы не пересекаются. */
const order = () => {
  const cart = `mnd_00000000-0000-8000-8000-${String(++cseq).padStart(12, "0")}`;
  return {
    cart,
    body: JSON.stringify({ mandate_id: cart, order_ref: `ORD-${cseq}`, merchant_id: "MER-1042", amount_max: 100_000, currency: "RUB", kind: "CARD" }),
  };
};

describe.skipIf(!DATABASE_URL)("реквизит под одним Idempotency-Key на двух экземплярах PostgreSQL (РП48 (в))", () => {
  let db: TestDb;
  let p: ReturnType<typeof platform> | undefined;
  beforeAll(async () => {
    db = await openTestDb("credidem");
  });
  afterEach(async () => {
    await p?.close();
    p = undefined;
  });
  afterAll(async () => {
    await db?.close();
  });

  const results = async () =>
    (await db.pool.query<{ result: string | null }>("SELECT result FROM core_idempotency WHERE scope = $1", [idempotencyScope(A)])).rows;
  const credentialRows = async (cart: string) =>
    (await db.pool.query<Record<string, unknown>>("SELECT * FROM agent_credentials WHERE mandate_id = $1", [cart])).rows;

  it("выдача на одном экземпляре, повтор под ключом на другом — та же криптограмма; в core_idempotency.result её нет", async () => {
    p = platform();
    const one = p.instance(db.pool);
    const two = p.instance(db.reopen());
    const { cart, body } = order();
    const key = randomUUID();
    const a = await p.post(one, body, key);
    expect(a.statusCode).toBe(201);
    const c = a.json() as Credential;
    const cryptogram = c.payload.cryptogram as string;
    expect(typeof cryptogram).toBe("string");
    const b = await p.post(two, body, key);
    expect(b.statusCode).toBe(201);
    expect(b.body).toBe(a.body);
    // Главный инвариант сессии: значения криптограммы нет в базе Платформы — ни под ключом, ни в записи реквизита.
    const stored = (await results()).map((r) => r.result ?? "");
    expect(stored.some((r) => r.includes(c.credential_ref))).toBe(true);
    for (const r of stored) {
      expect(r).not.toContain(cryptogram);
      expect(r).not.toContain("cryptogram");
    }
    const rows = await credentialRows(cart);
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(cryptogram);
  });

  it("одновременно 10 одинаковых обращений под одним ключом на двух экземплярах — одна запись; все 201 — одна криптограмма, остальные 503 same_key", async () => {
    p = platform();
    const apps = [p.instance(db.pool), p.instance(db.reopen())];
    const { cart, body } = order();
    const key = randomUUID();
    const res = await Promise.all(Array.from({ length: 10 }, (_, i) => p!.post(apps[i % 2] as FastifyInstance, body, key)));
    const ok = res.filter((r) => r.statusCode === 201);
    const busy = res.filter((r) => r.statusCode === 503);
    expect(ok.length + busy.length).toBe(10);
    expect(ok.length).toBeGreaterThanOrEqual(1);
    for (const r of busy) expect(r.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    const values = new Set(ok.map((r) => (r.json() as Credential).payload.cryptogram));
    expect(values.size).toBe(1);
    // После завершения первого — повтор на любом экземпляре даёт тот же реквизит.
    const after = await p.post(apps[1] as FastifyInstance, body, key);
    expect(after.statusCode).toBe(201);
    expect((after.json() as Credential).payload.cryptogram).toBe([...values][0]);
    expect(await credentialRows(cart)).toHaveLength(1);
    for (const r of await results()) expect(r.result ?? "").not.toContain([...values][0] as string);
  });
});
