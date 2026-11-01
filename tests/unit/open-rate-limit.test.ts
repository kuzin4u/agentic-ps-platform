// Лимит частоты у открытых адресов (РП73; SECURITY С3б; SEC-2 ч. 1 К2.3): API для продавцов и шлюз участников ПИ-8 —
// свои счётчики по адресу, 429 {code: RATE_LIMITED} с Retry-After ≤ 30 и Cache-Control: no-store; ADP и /health — без лимита.
import { generateKeyPairSync } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { AGENT_KEYS_PATH } from "../../src/participants/merchant-api.js";
import { MemoryReadinessStore } from "../../src/participants/readiness.js";
import { loadTrustedParticipants } from "../../src/participants/trusted.js";
import { PaoRequestVerifier, paoIdempotency } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { memoryConsent } from "../support/consent.js";
import { coarseLimit } from "../support/rate-limit.js";

const A = "nspk:agent:openrl-01:v1";
const MANDATE = "mnd_00000000-0000-8000-8000-000000000000";
const SIGN = `/participants/v1/mandates/${MANDATE}/sign`;
const MERCHANT_PATHS = [AGENT_KEYS_PATH, `/merchants/v1/agents/${A}`, "/merchants/v1/merchants/MER-1/readiness"] as const;

type Res = { statusCode: number; headers: Record<string, unknown>; json: () => unknown };

/** Все контексты одного сервера: API продавцов, ПИ-8, ПАО (свой предел — большой), ADP без процессора (503). */
async function platform(merchantLimit: number, participantLimit: number): Promise<FastifyInstance> {
  const params = { ...coarseLimit(100), merchant_api_rate_limit_per_30s: merchantLimit, participant_rate_limit_per_30s: participantLimit };
  const store = new InMemoryAgentRegistryStore();
  const registry = new AgentRegistry(store, { keys: params });
  const keys = new AgentKeys(store, { keys: params });
  const public_key = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const application = { agent_code: A, class: "BUYER", model: "buyer-agent-ref", runtime: "python-3.12", alg: "ed25519", public_key };
  expect((await registry.admit(application, { contour: "sandbox", operator: "op" })).admitted).toBe(true);
  const verifier = new PaoRequestVerifier(
    { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
    { skewSec: params.signature_skew_sec },
  );
  return buildServer({
    env: "dev",
    merchants: { registry, keys, contour: "sandbox", params, readiness: new MemoryReadinessStore() },
    participants: {
      trusted: loadTrustedParticipants(undefined, { stand: false }),
      consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
      params,
    },
    pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    adp: {},
  });
}

const get = (app: FastifyInstance, url: string, remoteAddress?: string) =>
  app.inject({ method: "GET", url, ...(remoteAddress ? { remoteAddress } : {}) });
/** Запись ПИ-8 с неразборным телом: без лимита — 400 REQUEST_INVALID. */
const badSign = (app: FastifyInstance) =>
  app.inject({ method: "POST", url: SIGN, headers: { "content-type": "application/json" }, payload: "{не json" });

function expect429(res: Res): void {
  expect(res.statusCode).toBe(429);
  expect(res.json()).toStrictEqual({ code: "RATE_LIMITED" });
  const ra = Number(res.headers["retry-after"]);
  expect(Number.isInteger(ra)).toBe(true);
  expect(ra).toBeGreaterThanOrEqual(0);
  // РП24: не больше maxRetryAfterSec клиента ядра.
  expect(ra).toBeLessThanOrEqual(30);
  // РП73 п. 3: продавец не кеширует 429 вместо каталога или статуса.
  expect(res.headers["cache-control"]).toBe("no-store");
}

describe("лимит частоты у открытых адресов (РП73)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it.each(MERCHANT_PATHS)("API для продавцов %s: до предела — свой ответ, сверх — 429 RATE_LIMITED, Retry-After ≤ 30, no-store", async (path) => {
    app = await platform(2, 100);
    for (let i = 0; i < 2; i++) expect((await get(app, path)).statusCode).toBe(200);
    expect429(await get(app, path));
  });

  it("API для продавцов — один счётчик на контекст: три адреса вместе, а не по отдельности", async () => {
    app = await platform(3, 100);
    for (const path of MERCHANT_PATHS) expect((await get(app, path)).statusCode).toBe(200);
    expect429(await get(app, AGENT_KEYS_PATH));
  });

  it("перебор кодов агентов по статусу (С3б): неизвестные коды тоже считаются, сверх предела — 429, а не 404", async () => {
    app = await platform(3, 100);
    for (let i = 0; i < 3; i++) expect((await get(app, `/merchants/v1/agents/nspk:agent:guess-${i}:v1`)).statusCode).toBe(404);
    expect429(await get(app, "/merchants/v1/agents/nspk:agent:guess-x:v1"));
  });

  it("ПИ-8: неподписанный поток ограничен до проверки подписи — сверх предела 429 RATE_LIMITED", async () => {
    app = await platform(100, 2);
    for (let i = 0; i < 2; i++) expect((await badSign(app)).statusCode).toBe(400);
    expect429(await badSign(app));
  });

  it("ПИ-8: тело неверное и предел превышен — 429, а не 400 (метка лимита — до разбора 4xx; тело не читается)", async () => {
    app = await platform(100, 1);
    const first = await badSign(app);
    expect([first.statusCode, first.json()]).toEqual([400, { code: "REQUEST_INVALID" }]);
    expect429(await badSign(app));
  });

  it("счётчики раздельные: исчерпан API продавцов — ПИ-8 и /pao отвечают своим; исчерпан ПИ-8 — API продавцов отвечает", async () => {
    app = await platform(1, 1);
    expect((await get(app, AGENT_KEYS_PATH)).statusCode).toBe(200);
    expect429(await get(app, AGENT_KEYS_PATH));
    expect((await badSign(app)).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": A } })).statusCode).toBe(401);
    expect429(await badSign(app));
    expect429(await get(app, AGENT_KEYS_PATH));
    const other = await platform(1, 1);
    try {
      expect((await badSign(other)).statusCode).toBe(400);
      expect429(await badSign(other));
      expect((await get(other, AGENT_KEYS_PATH)).statusCode).toBe(200);
    } finally {
      await other.close();
    }
  });

  it("ADP и /health без лимита (инвариант 2): при исчерпанных счётчиках отвечают как прежде, 429 нет", async () => {
    app = await platform(1, 1);
    await get(app, AGENT_KEYS_PATH);
    await badSign(app);
    expect429(await get(app, AGENT_KEYS_PATH));
    expect429(await badSign(app));
    // Неагентская операция (без aoi) — 200 BYPASS без точки решения (РП4): лимит открытых адресов её не задевает.
    const plain = {
      op_ref: "OPKC-OPENRL-1",
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: 10_000,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
    };
    for (let i = 0; i < 5; i++) {
      expect((await get(app, "/health")).statusCode).toBe(200);
      const decide = await app.inject({ method: "POST", url: "/adp/v1/decide", payload: { ...plain, op_ref: `OPKC-OPENRL-${i}` } });
      expect([decide.statusCode, decide.json()], "ADP получил лимит").toEqual([200, { decision: "BYPASS", reason: null, decided_in_ms: 0 }]);
    }
  });

  it("IPv6 — по подсети /64 (как РП32 доп. п. 1): одна /64 — один счётчик, другая /64 — свой", async () => {
    app = await platform(2, 100);
    for (let i = 1; i <= 2; i++) expect((await get(app, AGENT_KEYS_PATH, `2001:db8:5:6::${i}`)).statusCode).toBe(200);
    expect429(await get(app, AGENT_KEYS_PATH, "2001:db8:5:6:ffff:ffff:ffff:ffff"));
    expect((await get(app, AGENT_KEYS_PATH, "2001:db8:5:7::1")).statusCode).toBe(200);
  });

  it.each([
    ["merchant_api_rate_limit_per_30s", 0],
    ["participant_rate_limit_per_30s", 0],
    ["merchant_api_rate_limit_per_30s", 1.5],
  ] as const)("%s = %s — отказ сборки контекста (целое ≥ 1; граница загрузчика — shared-config, PARAMS.md)", async (name, v) => {
    const params = { ...loadParams(), [name]: v };
    const bad = buildServer({
      env: "dev",
      merchants: { registry: { get: async () => undefined }, keys: { jwks: async () => ({ keys: [] }) }, contour: "sandbox", params },
      participants: {
        trusted: loadTrustedParticipants(undefined, { stand: false }),
        consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
        params,
      },
    });
    await expect(bad.ready()).rejects.toThrow(`${name} — целое ≥ 1`);
    await bad.close().catch(() => undefined);
  });
});
