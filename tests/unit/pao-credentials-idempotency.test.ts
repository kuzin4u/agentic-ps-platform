// Повтор POST /pao/v1/credentials под тем же Idempotency-Key (РП48 (в)): под ключом хранится ответ без криптограммы;
// повтор пересчитывает её по записи реквизита (та же криптограмма, текущий status). Сбой пересчёта — 5xx без записи.
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { AsyncIdempotencyStore } from "@kuzin4u/agentic-core";
import { ConsentJournal, MemoryConsentStore } from "../../src/consent/index.js";
import { Credentials, MemoryCredentialStore } from "../../src/credentials/index.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { createTokenServiceEmulator } from "../../src/env/tsp/index.js";
import { paoIdempotency, type PaoReply } from "../../src/pao/idempotency.js";
import { paoRoutes } from "../../src/pao/routes.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import type { Credential, Mandate } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:idem-cred:v1";
const CART = "mnd_00000000-0000-8000-8000-00000000c001";

const cart = {
  id: CART,
  type: "CART",
  parent_id: "mnd_00000000-0000-8000-8000-00000000a001",
  subject: "s",
  amount_limit: 189_000,
  currency: "RUB",
  valid_to: "2099-01-01T00:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "pr_alpha",
  mode: "IMMEDIATE",
  agent_code: CODE,
  status: "ACTIVE",
} as Mandate;

const body = (over: Record<string, unknown> = {}) =>
  JSON.stringify({ mandate_id: CART, order_ref: "ORD-k", merchant_id: "MER-1042", amount_max: 100_000, currency: "RUB", kind: "CARD", ...over });

async function gateway() {
  const params = loadParams();
  const regStore = new InMemoryAgentRegistryStore();
  const registry = new AgentRegistry(regStore, { keys: params });
  const keys = new AgentKeys(regStore, { keys: params });
  const side = newAgentSide();
  expect(registry.admit(buyerApplication(CODE, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
  const issuer = createIssuerEmulator();
  const tsp = createTokenServiceEmulator();
  const store = new MemoryCredentialStore();
  const sw = { tspDown: false };
  const lines: string[] = [];
  const credentials = new Credentials({
    mandates: {
      get: async (id, code) =>
        id === CART && code === CODE
          ? { mandate: cart, client: { participant_code: issuer.participant_code, principal_ref: "pr_alpha" }, token_consent: true }
          : undefined,
    },
    store,
    tsp: {
      issueToken: (i) => tsp.issueToken(i),
      cryptogram: (i) => (sw.tspDown ? Promise.reject(new Error("down")) : tsp.cryptogram(i)),
    },
    funding: issuer,
    params: { cryptogram_ttl_sec: params.cryptogram_ttl_sec },
    log: (f, m) => lines.push(`${m} ${JSON.stringify(f)}`),
  });
  // Хранилище ядра в памяти с записью того, что под ключом сохранено: тело, которое уходит в core_idempotency.result.
  const saved: string[] = [];
  const inner = paoIdempotency({ ttlSec: params.idempotency_ttl_sec });
  const idempotency = (agent_code: string): AsyncIdempotencyStore<PaoReply> => ({
    run: (key, b, fn) =>
      inner(agent_code).run(key, b, async () => {
        const r = await fn();
        saved.push(JSON.stringify(r));
        return r;
      }),
  });
  const app = Fastify({ logger: { level: "info", stream: { write: (l: string) => void lines.push(l) } } });
  await app.register(async (scope) =>
    paoRoutes(scope, {
      verifier: new PaoRequestVerifier(
        { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
        { skewSec: params.signature_skew_sec },
      ),
      keys,
      idempotency,
      params,
      consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
      credentials,
    }),
  );
  await app.ready();
  const post = (raw: string, key: string) =>
    signedInject(app, side, CODE, { method: "POST", path: "/pao/v1/credentials", body: raw, headers: { "idempotency-key": key } });
  return { app, post, saved, store, tsp, sw, lines };
}

describe("POST /pao/v1/credentials под тем же Idempotency-Key (РП48 (в))", () => {
  it("повтор — 201, тот же реквизит и та же криптограмма; под ключом сохранён ответ без криптограммы", async () => {
    const g = await gateway();
    const key = randomUUID();
    const a = await g.post(body(), key);
    const b = await g.post(body(), key);
    expect([a.statusCode, b.statusCode]).toEqual([201, 201]);
    const c = a.json() as Credential;
    expect(typeof c.payload.cryptogram).toBe("string");
    expect(b.json()).toEqual(c);
    // Обработчик исполнен один раз; в сохранённом ответе нет ни поля, ни значения криптограммы (РП47 п. 3, 10).
    expect(g.saved).toHaveLength(1);
    expect(g.saved[0]).not.toContain("cryptogram");
    expect(g.saved[0]).not.toContain(c.payload.cryptogram as string);
    expect(JSON.parse(g.saved[0] as string)).toMatchObject({ status: 201, body: { credential_ref: c.credential_ref } });
    await g.app.close();
  });

  it("повтор после погашения — та же криптограмма, status USED (текущий, как у повтора по заказу)", async () => {
    const g = await gateway();
    const key = randomUUID();
    const c = (await g.post(body(), key)).json() as Credential;
    expect(await g.store.consume(c.credential_ref, "OPKC-1")).toBe(true);
    const b = await g.post(body(), key);
    expect(b.statusCode).toBe(201);
    expect(b.json()).toEqual({ ...c, status: "USED" });
    await g.app.close();
  });

  it("токен-сервис недоступен при повторе — 503 UPSTREAM_UNAVAILABLE с Retry-After; после восстановления — тот же ответ", async () => {
    const g = await gateway();
    const key = randomUUID();
    const c = (await g.post(body(), key)).json() as Credential;
    g.sw.tspDown = true;
    const down = await g.post(body(), key);
    expect(down.statusCode).toBe(503);
    expect(down.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
    expect(down.headers["retry-after"]).toBeDefined();
    expect(down.body).not.toContain(c.payload.cryptogram as string);
    g.sw.tspDown = false;
    expect((await g.post(body(), key)).json()).toEqual(c);
    expect(g.saved).toHaveLength(1);
    await g.app.close();
  });

  it("записи реквизита нет при повторе — 503 STATE_UNAVAILABLE и инцидент, значение не выдаётся", async () => {
    const g = await gateway();
    const key = randomUUID();
    await g.post(body(), key);
    g.store.credentialByOrder = async () => undefined;
    const r = await g.post(body(), key);
    expect(r.statusCode).toBe(503);
    expect(r.json()).toMatchObject({ code: "STATE_UNAVAILABLE" });
    expect(g.lines.some((l) => l.includes("повтор под ключом — запись реквизита не найдена") && l.includes('"incident":true'))).toBe(true);
    await g.app.close();
  });

  it("тот же ключ с другим телом — 409 IDEMPOTENCY_CONFLICT, как прежде (РП30 п. 3)", async () => {
    const g = await gateway();
    const key = randomUUID();
    expect((await g.post(body(), key)).statusCode).toBe(201);
    const r = await g.post(body({ amount_max: 99_000 }), key);
    expect(r.statusCode).toBe(409);
    expect(r.json()).toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await g.app.close();
  });

  it("отказ 4xx под ключом — сохранённый ответ как есть, без пересборки", async () => {
    const g = await gateway();
    const key = randomUUID();
    const a = await g.post(body({ merchant_id: "MER-OTHER" }), key);
    expect(a.statusCode).toBe(409);
    expect(a.json()).toMatchObject({ code: "MANDATE_SCOPE" });
    const b = await g.post(body({ merchant_id: "MER-OTHER" }), key);
    expect([b.statusCode, b.body]).toEqual([409, a.body]);
    expect(g.saved).toHaveLength(1);
    await g.app.close();
  });
});
