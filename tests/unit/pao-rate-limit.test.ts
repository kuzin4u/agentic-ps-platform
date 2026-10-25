// Грубый лимит частоты шлюза ПАО по адресу (РП32; CodeQL № 81, Ш12): до проверки подписи, 429 по ПАО §6, Retry-After ≤ 30.
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PAO_RATE_WINDOW_MS, PaoRequestVerifier, paoIdempotency } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer, parseTrustedProxies } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { stand } from "../support/stand.js";
import { memoryConsent } from "../support/consent.js";
import { coarseLimit } from "../support/rate-limit.js";

const A = "nspk:agent:buyref-01:v3";
const LIMIT = 3;

describe("лимит частоты ПАО по адресу (РП32)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  const platform = (limit = LIMIT, trustedProxies?: string[]) => {
    const params = coarseLimit(limit);
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const side = newAgentSide();
    expect(registry.admit(buyerApplication(A, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    app = buildServer({
      env: "sandbox",
      ...(trustedProxies ? { trustedProxies } : {}),
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    });
    return { app, side, keys };
  };

  const unsigned = (a: FastifyInstance, headers: Record<string, string> = {}) =>
    a.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": A, ...headers } });

  const expect429 = (res: { statusCode: number; headers: Record<string, unknown>; json: () => unknown }) => {
    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({ code: "RATE_LIMITED", message: expect.any(String), retry: "same_key" });
    const ra = Number(res.headers["retry-after"]);
    expect(Number.isInteger(ra)).toBe(true);
    expect(ra).toBeGreaterThanOrEqual(0);
    // РП24: не больше maxRetryAfterSec клиента ядра.
    expect(ra).toBeLessThanOrEqual(30);
  };

  it("неподписанный поток ограничен до проверки подписи: сверх лимита — 429 RATE_LIMITED по ПАО §6, Retry-After ≤ 30", async () => {
    const { app } = platform();
    for (let i = 0; i < LIMIT; i++) expect((await unsigned(app)).statusCode).toBe(401);
    expect429(await unsigned(app));
  });

  it("подписанные GET /pao/v1/agent и POST /pao/v1/agent/keys — тот же счётчик; 429 до идемпотентности, ключ не добавлен", async () => {
    const { app, side, keys } = platform();
    for (let i = 0; i < LIMIT; i++) expect((await signedInject(app, side, A)).statusCode).toBe(200);
    const body = JSON.stringify({ alg: "ed25519", public_key: newAgentSide().publicKey });
    const res = await signedInject(app, side, A, {
      method: "POST",
      path: "/pao/v1/agent/keys",
      body,
      headers: { "idempotency-key": randomUUID() },
    });
    expect429(res);
    expect(keys.list(A)).toHaveLength(1);
  });

  it("окно — 30 с: Retry-After по стендовому лимиту тоже ≤ 30 (РП32 п. 2, РП24)", async () => {
    expect(PAO_RATE_WINDOW_MS).toBe(30_000);
    const { app } = platform(1);
    await unsigned(app);
    expect429(await unsigned(app));
  });

  it("обработчик ошибок области отвечает на 404 и 413 по ПАО §6 (РП62 п. 1–2); тело 1,1 МБ — больше любого предела, сам предел 64 КиБ — в pao-transport-errors", async () => {
    const { app } = platform(100);
    const nope = await app.inject({ method: "GET", url: "/pao/v1/nope" });
    expect([nope.statusCode, nope.json().code]).toEqual([404, "REQUEST_INVALID"]);
    const big = await app.inject({
      method: "POST",
      url: "/pao/v1/agent/keys",
      headers: { "content-type": "application/json", "x-agent-code": A },
      payload: "x".repeat(1_100_000),
    });
    expect([big.statusCode, big.json().code]).toEqual([413, "REQUEST_INVALID"]);
  });

  it("стенд для агента — тот же лимит из параметров стенда (РП32 п. 7)", async () => {
    const s = stand();
    try {
      expect(s.params.pao_rate_limit_per_30s).toBe(3000);
      let last = 0;
      for (let i = 0; i <= s.params.pao_rate_limit_per_30s; i++) last = (await unsigned(s.app)).statusCode;
      expect(last).toBe(429);
    } finally {
      await s.app.close();
    }
  });

  const from = (a: FastifyInstance, remoteAddress: string) =>
    a.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": A }, remoteAddress });

  it("IPv6 — по подсети /64: адреса одной /64 — один счётчик, другой /64 — свой (РП32, дополнение п. 1)", async () => {
    const { app } = platform();
    for (let i = 1; i <= LIMIT; i++) expect((await from(app, `2001:db8:1:2::${i}`)).statusCode).toBe(401);
    expect429(await from(app, "2001:db8:1:2:ffff:ffff:ffff:ffff"));
    expect((await from(app, "2001:db8:1:3::1")).statusCode).toBe(401);
    // IPv4 и IPv4 в IPv6 — один адрес, один счётчик.
    const { app: b } = platform(1);
    expect((await from(b, "192.0.2.7")).statusCode).toBe(401);
    expect429(await from(b, "::ffff:192.0.2.7"));
    expect((await from(b, "192.0.2.8")).statusCode).toBe(401);
  });

  it("часы переведены назад внутри окна — Retry-After всё равно ≤ 30 (РП32, дополнение п. 3; РП24)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const t = new Date("2026-10-16T12:00:00Z");
      vi.setSystemTime(t);
      const { app } = platform(1);
      expect((await unsigned(app)).statusCode).toBe(401);
      vi.setSystemTime(new Date(t.getTime() - 60_000));
      const res = await unsigned(app);
      expect429(res);
      expect(res.headers["retry-after"]).toBe("30");
    } finally {
      vi.useRealTimers();
    }
  });

  it("/health вне лимита", async () => {
    const { app } = platform(1);
    for (let i = 0; i < 5; i++) expect((await app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
  });

  it("без доверенного прокси X-Forwarded-For ключ не меняет: подстановка заголовка лимит не обходит", async () => {
    const { app } = platform();
    for (let i = 0; i < LIMIT; i++) await unsigned(app, { "x-forwarded-for": `10.0.0.${i + 1}` });
    expect429(await unsigned(app, { "x-forwarded-for": "10.0.0.99" }));
  });

  it("с доверенным прокси — адрес клиента из X-Forwarded-For: у разных клиентов свои счётчики", async () => {
    const { app } = platform(LIMIT, ["127.0.0.1"]);
    for (let i = 0; i < LIMIT; i++) await unsigned(app, { "x-forwarded-for": "10.0.0.1" });
    expect429(await unsigned(app, { "x-forwarded-for": "10.0.0.1" }));
    expect((await unsigned(app, { "x-forwarded-for": "10.0.0.2" })).statusCode).toBe(401);
  });

  it("лимит < 1 — отказ сборки шлюза", async () => {
    const params = { ...loadParams(), pao_rate_limit_per_30s: 0 };
    const keys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const verifier = new PaoRequestVerifier({ getAgent: () => undefined, lookupKey: () => undefined }, { skewSec: 1 });
    app = buildServer({ env: "sandbox", pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: 60 }), params, consent: memoryConsent() } });
    await expect(app.ready()).rejects.toThrow(/pao_rate_limit_per_30s/);
  });
});

describe("второй слой лимита — по агенту и уровню после подписи (РП63 п. 1–8)", () => {
  const B = "nspk:agent:buyref-02:v1";
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  // Малые значения (решение владельца 25.10): L1 = 4 в минуту — 2 за окно 30 с; первый слой щедрый.
  const SMALL = { pao_agent_rate_limit_per_min_l1: 4, pao_agent_rate_limit_per_min_l2: 6, pao_agent_rate_limit_per_min_l3: 8 };

  const platform = (opts: { level?: number; log?: (line: string) => void } = {}) => {
    const params = { ...loadParams(), pao_rate_limit_per_30s: 1000, ...SMALL };
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const a = newAgentSide();
    const b = newAgentSide();
    expect(registry.admit(buyerApplication(A, a), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    expect(registry.admit(buyerApplication(B, b), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    // Уровень меняет П8 (РП21 п. 3) — в тесте подставляется в запись реестра, как её отдал бы реестр.
    const getAgent = (c: string) => {
      const r = registry.get(c);
      return r && opts.level !== undefined ? { ...r, level: opts.level } : r;
    };
    const verifier = new PaoRequestVerifier(
      { getAgent, lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    app = buildServer({
      env: "sandbox",
      ...(opts.log ? { logger: { level: "info", stream: { write: opts.log } } } : {}),
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    });
    return { app, a, b, keys };
  };

  /** sent — сколько обращений с адреса уже учёл первый слой, включая это: его заголовки остаются, своих второй не ставит. */
  const expect429 = (res: { statusCode: number; headers: Record<string, unknown>; json: () => unknown }, sent?: number) => {
    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({ code: "RATE_LIMITED", message: expect.any(String), retry: "same_key" });
    const ra = Number(res.headers["retry-after"]);
    // ≥ 1: при живом окне повтор без паузы снова получил бы 429; ≤ 30 — РП24.
    expect(Number.isInteger(ra) && ra >= 1 && ra <= 30, String(ra)).toBe(true);
    expect(res.headers["x-ratelimit-limit"]).toBe("1000");
    if (sent !== undefined) expect(res.headers["x-ratelimit-remaining"]).toBe(String(1000 - sent));
  };

  it("предел в окне 30 с — половина минутного: третье подписанное обращение — 429 RATE_LIMITED, Retry-After ≤ 30", async () => {
    const { app, a } = platform();
    for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
    expect429(await signedInject(app, a, A), 3);
  });

  it("окно — 30 с: на 29-й секунде — 429 с Retry-After = 1, с 30-й — снова 200 (РП63 п. 3)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const t = Date.now();
      const { app, a } = platform();
      for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
      vi.setSystemTime(t + 29_000);
      const res = await signedInject(app, a, A);
      expect429(res);
      expect(res.headers["retry-after"]).toBe("1");
      vi.setSystemTime(t + 30_000);
      expect((await signedInject(app, a, A)).statusCode).toBe(200);
    } finally {
      vi.useRealTimers();
    }
  });

  it("часы переведены назад внутри окна — Retry-After второго слоя всё равно 30 (РП24; РП32, дополнение п. 3)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const t = Date.now();
      const { app, a } = platform();
      for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
      vi.setSystemTime(t - 60_000);
      const res = await signedInject(app, a, A);
      expect429(res);
      expect(res.headers["retry-after"]).toBe("30");
    } finally {
      vi.useRealTimers();
    }
  });

  it("счётчик — по agent_code: два агента с одного адреса — раздельно", async () => {
    const { app, a, b } = platform();
    for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
    expect429(await signedInject(app, a, A));
    for (let i = 0; i < 2; i++) expect((await signedInject(app, b, B)).statusCode).toBe(200);
    expect429(await signedInject(app, b, B));
  });

  it("до проверки подписи слой не считает: чужой x-agent-code без верной подписи квоту агента не тратит", async () => {
    const { app, a, b } = platform();
    // Без подписи и с подписью ключом другого агента под кодом A — 401, счётчик A не растёт.
    for (let i = 0; i < 5; i++) {
      expect((await app.inject({ method: "GET", url: "/pao/v1/agent", headers: { "x-agent-code": A } })).statusCode).toBe(401);
      expect((await signedInject(app, b, A)).statusCode).toBe(401);
    }
    for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
    expect429(await signedInject(app, a, A));
  });

  it("429 второго слоя — до обработчика: POST /pao/v1/agent/keys ключ не добавляет", async () => {
    const { app, a, keys } = platform();
    for (let i = 0; i < 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
    const res = await signedInject(app, a, A, {
      method: "POST",
      path: "/pao/v1/agent/keys",
      body: JSON.stringify({ alg: "ed25519", public_key: newAgentSide().publicKey }),
      headers: { "idempotency-key": randomUUID() },
    });
    expect429(res);
    expect(keys.list(A)).toHaveLength(1);
  });

  it.each([
    [1, 4],
    [2, 6],
    [3, 8],
  ])("GET /pao/v1/agent: уровень %i — rate_limit_per_min = %i, и он же применяется", async (level, perMin) => {
    const { app, a } = platform({ level });
    const self = await signedInject(app, a, A);
    expect(self.statusCode).toBe(200);
    expect(self.json().rate_limit_per_min).toBe(perMin);
    for (let i = 1; i < perMin / 2; i++) expect((await signedInject(app, a, A)).statusCode).toBe(200);
    expect429(await signedInject(app, a, A));
  });

  it.each([4, 0, 1.5, Number.NaN])("уровень вне таблицы (%s) — L1 (строжайший) с записью warn (п. 5, инвариант 3)", async (level) => {
    const lines: string[] = [];
    const { app, a } = platform({ level, log: (l) => lines.push(l) });
    const self = await signedInject(app, a, A);
    expect(self.json().rate_limit_per_min).toBe(SMALL.pao_agent_rate_limit_per_min_l1);
    expect((await signedInject(app, a, A)).statusCode).toBe(200);
    expect429(await signedInject(app, a, A));
    const warn = lines.map((l) => JSON.parse(l)).find((r) => r.msg === "ПАО: уровень агента вне таблицы лимита — предел L1");
    // NaN в JSON — null.
    expect(warn).toMatchObject({ level: 40, agent_code: A, agent_level: Number.isFinite(level) ? level : null });
  });

  it("стенд: 3 000 / 4 500 / 6 000 в минуту (РП63 п. 4) — те же параметры у стенда для агента", () => {
    const p = loadParams();
    expect([p.pao_agent_rate_limit_per_min_l1, p.pao_agent_rate_limit_per_min_l2, p.pao_agent_rate_limit_per_min_l3]).toEqual([3000, 4500, 6000]);
  });

  it.each([0, 1, 3, 2.5, -2])("значение %s — отказ сборки шлюза (чётное целое ≥ 2)", async (v) => {
    const params = { ...loadParams(), pao_agent_rate_limit_per_min_l2: v };
    const keys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const verifier = new PaoRequestVerifier({ getAgent: () => undefined, lookupKey: () => undefined }, { skewSec: 1 });
    app = buildServer({ env: "sandbox", pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: 60 }), params, consent: memoryConsent() } });
    await expect(app.ready()).rejects.toThrow(/pao_agent_rate_limit_per_min_l2/);
  });

  it.each([
    [{ pao_agent_rate_limit_per_min_l1: 8, pao_agent_rate_limit_per_min_l2: 6, pao_agent_rate_limit_per_min_l3: 8 }, /l1 больше pao_agent_rate_limit_per_min_l2/],
    [{ pao_agent_rate_limit_per_min_l1: 4, pao_agent_rate_limit_per_min_l2: 10, pao_agent_rate_limit_per_min_l3: 8 }, /l2 больше pao_agent_rate_limit_per_min_l3/],
    [{ ...SMALL, pao_rate_limit_per_30s: 3 }, /l3 \/ 2 больше pao_rate_limit_per_30s/],
  ])("параметры в обход загрузчика: %o — отказ сборки шлюза (РП63 доп. 1)", async (patch, msg) => {
    const params = { ...loadParams(), pao_rate_limit_per_30s: 1000, ...patch };
    const keys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const verifier = new PaoRequestVerifier({ getAgent: () => undefined, lookupKey: () => undefined }, { skewSec: 1 });
    app = buildServer({ env: "sandbox", pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: 60 }), params, consent: memoryConsent() } });
    await expect(app.ready()).rejects.toThrow(msg);
  });
});

describe("PAO_TRUSTED_PROXIES (РП32 п. 5)", () => {
  it("пусто или нет — прокси не доверяем; адреса и CIDR — список", () => {
    expect(parseTrustedProxies(undefined)).toEqual([]);
    expect(parseTrustedProxies(" ")).toEqual([]);
    expect(parseTrustedProxies("10.0.0.0/16, 192.168.1.10,::1,fd00::/32,10.1.2.0/24")).toEqual([
      "10.0.0.0/16",
      "192.168.1.10",
      "::1",
      "fd00::/32",
      "10.1.2.0/24",
    ]);
  });

  it.each([
    "true",
    "TRUE",
    "*",
    "0.0.0.0/0",
    "::/0",
    "0.0.0.0/1,128.0.0.0/1",
    "10.0.0.0/15",
    "10.0.0.0/8",
    "fd00::/31",
    "10.0.0.0/08",
    "fe80::1%eth0",
    "0.0.0.0/33",
    "::/129",
    "proxy.local",
    "10.0.0.1/8/1",
    "10.0.0.1/x",
  ])(
    "«%s» — отказ запуска: доверять всем или не адрес",
    (v) => {
      expect(() => parseTrustedProxies(v)).toThrow(/PAO_TRUSTED_PROXIES/);
    },
  );
});
