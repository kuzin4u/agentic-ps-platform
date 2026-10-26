// П9 Подписка на события (PS-08 К1.3б; РП40 п. 1–3, 6–8): форма адреса, адреса имени от SSRF (подмена DNS — через
// разрешение имени стенда), подписка в записи агента, отказ — 400 REQUEST_INVALID без причины в ответе.
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal, MemoryConsentStore } from "../../src/consent/index.js";
import { paoIdempotency } from "../../src/pao/idempotency.js";
import { paoRoutes } from "../../src/pao/routes.js";
import { PAO_DB_TIMEOUT_MS } from "../../src/pao/stores.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import {
  checkSubscriptionUrl,
  isGlobalAddress,
  resolveGlobal,
  type HostResolver,
} from "../../src/pao/subscription.js";
import { subscriptionBody } from "../../src/pao/body.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { createStandDns, STAND_AGENT_EMULATOR_ADDRESS, STAND_AGENT_EMULATOR_HOST } from "../../src/stand/dns.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const HOST = "agent.example";
const ALLOW = [HOST];

describe("форма адреса подписки (РП40 п. 2)", () => {
  it("https, имя из списка, без порта или с 443 — принимается; путь и запрос сохраняются", () => {
    expect(checkSubscriptionUrl(`https://${HOST}/hooks/pao?x=1`, ALLOW)).toEqual({
      ok: true,
      url: `https://${HOST}/hooks/pao?x=1`,
      host: HOST,
    });
    expect(checkSubscriptionUrl(`https://${HOST}:443/e`, ALLOW)).toMatchObject({ ok: true, url: `https://${HOST}/e` });
  });

  it.each([
    ["", "url_invalid"],
    ["не адрес", "url_invalid"],
    [`https://${HOST}/${"a".repeat(2048)}`, "url_invalid"],
    [`http://${HOST}/e`, "scheme"],
    [`ftp://${HOST}/e`, "scheme"],
    [`https://${HOST}:8443/e`, "port"],
    [`https://${HOST}:80/e`, "port"],
    [`https://u:p@${HOST}/e`, "userinfo"],
    [`https://u@${HOST}/e`, "userinfo"],
    [`https://@${HOST}/e`, "userinfo"],
    [`https://${HOST}/e#frag`, "fragment"],
    [`https://${HOST}/e#`, "fragment"],
    ["https://10.0.0.1/e", "ip_literal"],
    ["https://8.8.8.8/e", "ip_literal"],
    ["https://[::1]/e", "ip_literal"],
    ["https://0x7f000001/e", "ip_literal"],
    ["https://2130706433/e", "ip_literal"],
    ["https://127.1/e", "ip_literal"],
    ["https://other.example/e", "host_not_allowed"],
    [`https://sub.${HOST}/e`, "host_not_allowed"],
    [`https://${HOST}./e`, "host_not_allowed"],
    [` https://${HOST}/e`, "url_invalid"],
    [`https://${HOST}/e `, "url_invalid"],
    [`https://agent\t.example/e`, "url_invalid"],
    [`https://agent\n.example/e`, "url_invalid"],
    [`https://${HOST}\\@evil.example/e`, "url_invalid"],
    [`https:${HOST}/e`, "scheme"],
    [`https:\\\\${HOST}/e`, "url_invalid"],
    [`https:@${HOST}/e`, "scheme"],
    [`HTTP://${HOST}/e`, "scheme"],
  ])("%s — отказ %s", (url, reason) => {
    expect(checkSubscriptionUrl(url, ALLOW)).toMatchObject({ ok: false, reason });
  });

  it("при отказе после разбора — хост для журнала процесса, без пути", () => {
    expect(checkSubscriptionUrl(`https://other.example/secret-path?t=1`, ALLOW)).toEqual({
      ok: false,
      reason: "host_not_allowed",
      host: "other.example",
    });
  });

  // Нормализация WHATWG сводит эти записи к точному имени из списка; сохраняется нормализованный href (РП40 п. 2).
  it.each([
    [`https://agent%2Eexample/e`, `https://${HOST}/e`],
    [`https://agent\u3002example/e`, `https://${HOST}/e`],
    [`https://${HOST}:0443/e`, `https://${HOST}/e`],
    [`HTTPS://${HOST}/e`, `https://${HOST}/e`],
  ])("%s — нормализуется в %s", (raw, href) => {
    expect(checkSubscriptionUrl(raw, ALLOW)).toEqual({ ok: true, url: href, host: HOST });
  });

  it("регистр имени не важен: URL приводит хост к нижнему регистру", () => {
    expect(checkSubscriptionUrl(`https://AGENT.Example/e`, ALLOW)).toMatchObject({ ok: true, host: HOST });
  });

  it("пустой список разрешённых — отказ всем (fail-closed)", () => {
    expect(checkSubscriptionUrl(`https://${HOST}/e`, [])).toEqual({ ok: false, reason: "host_not_allowed", host: HOST });
  });
});

describe("глобальный адрес (РП40 п. 3)", () => {
  it.each([
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.8",
    "192.0.2.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fc00::1",
    "fd12:3456::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::FFFF:169.254.169.254",
    "64:ff9b::10.0.0.1",
    "64:ff9b::a00:1",
    "64:ff9b:0:0:0:0:7f00:1",
    "0064:ff9b::7f00:1",
    "64:ff9b:1::8.8.8.8",
    "0:0:0:0:0:ffff:7f00:1",
    "::ffff:0:7f00:1",
    "::127.0.0.1",
    "::7f00:1",
    "::8.8.8.8",
    "2002:7f00:1::",
    "2002:a9fe:a9fe::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "2001:1::1",
    "fec0::1",
    "100::1",
    "3fff::1",
    "5f00::1",
    "fe80::1%eth0",
    "192.88.99.1",
    "192.31.196.1",
    "192.52.193.1",
    "192.175.48.1",
    "2620:4f:8000::1",
    "2620:004f:8000:ffff::1",
    "не адрес",
    "",
  ])("%s — не глобальный", (ip) => {
    expect(isGlobalAddress(ip)).toBe(false);
  });

  it.each(["8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1", STAND_AGENT_EMULATOR_ADDRESS, "2a00:1450::1", "2001:4860:4860::8888", "192.31.197.1", "192.52.192.1", "192.175.49.1", "2620:4f:8001::1", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2002:808:808::1"])(
    "%s — глобальный",
    (ip) => {
      expect(isGlobalAddress(ip)).toBe(true);
    },
  );
});

describe("разрешение имени (РП40 п. 2, 4)", () => {
  const fixed =
    (a: readonly string[]): HostResolver =>
    async () =>
      a;

  it("все адреса глобальные — принимается", async () => {
    expect(await resolveGlobal(HOST, fixed(["8.8.8.8", "2a00:1450::1"]))).toEqual({
      ok: true,
      addresses: ["8.8.8.8", "2a00:1450::1"],
    });
  });

  it("хоть один не глобальный — отказ (подмена DNS частью ответа)", async () => {
    expect(await resolveGlobal(HOST, fixed(["8.8.8.8", "127.0.0.1"]))).toEqual({ ok: false, reason: "address_not_global" });
  });

  const failing =
    (code?: string): HostResolver =>
    async () => {
      throw Object.assign(new Error("dns"), code === undefined ? {} : { code });
    };

  it("имени или адресов нет — отказ адреса name_not_found (дополнение РП40 п. 3)", async () => {
    expect(await resolveGlobal(HOST, fixed([]))).toEqual({ ok: false, reason: "name_not_found" });
    expect(await resolveGlobal(HOST, failing("ENOTFOUND"))).toEqual({ ok: false, reason: "name_not_found" });
    expect(await resolveGlobal(HOST, failing("ENODATA"))).toEqual({ ok: false, reason: "name_not_found" });
  });

  it("иной сбой разрешения — временный resolve_failed", async () => {
    for (const code of ["EAI_AGAIN", "ETIMEOUT", "ESERVFAIL", undefined]) {
      expect(await resolveGlobal(HOST, failing(code)), String(code)).toEqual({ ok: false, reason: "resolve_failed" });
    }
  });
});

describe("тело PUT /pao/v1/subscription (РП40 п. 1)", () => {
  it("url и events — по схеме; пустой events допустим", () => {
    expect(subscriptionBody(JSON.stringify({ url: "u", events: ["mandate.signed"] }))).toEqual({
      url: "u",
      events: ["mandate.signed"],
    });
    expect(subscriptionBody(JSON.stringify({ url: "u", events: [] }))).toEqual({ url: "u", events: [] });
  });

  it.each([
    "",
    "[]",
    JSON.stringify({ events: [] }),
    JSON.stringify({ url: "u" }),
    JSON.stringify({ url: 1, events: [] }),
    JSON.stringify({ url: "u", events: "mandate.signed" }),
    JSON.stringify({ url: "u", events: ["mandate.unknown"] }),
    JSON.stringify({ url: "u", events: [1] }),
    JSON.stringify({ url: "u", events: ["mandate.signed", "mandate.signed"] }),
  ])("%s — не по схеме", (raw) => {
    expect(subscriptionBody(raw)).toBeUndefined();
  });
});

describe("PUT /pao/v1/subscription на стенде (РП40 п. 1–3, 6–8)", () => {
  const code = "nspk:agent:subscription:v1";
  let stand: Stand;
  let side: AgentSide;
  const url = `https://${STAND_AGENT_EMULATOR_HOST}/pao/events`;

  beforeAll(async () => {
    stand = createStand();
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
  });
  afterEach(() => stand.dns.reset());
  afterAll(async () => stand.close());

  const put = (body: unknown, key: string | null = randomUUID(), as = side, asCode = code) =>
    signedInject(stand.app, as, asCode, {
      method: "PUT",
      path: "/pao/v1/subscription",
      body: typeof body === "string" ? body : JSON.stringify(body),
      headers: { "idempotency-key": key },
    });

  it("адрес эмулятора — 200, подписка в записи агента; замена — целиком; повтор с тем же ключом — тот же ответ", async () => {
    const key = randomUUID();
    const first = await put({ url, events: ["mandate.signed", "mandate.revoked"] }, key);
    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ url, events: ["mandate.signed", "mandate.revoked"] });
    expect(await stand.registry.subscription(code)).toEqual({ url, events: ["mandate.signed", "mandate.revoked"] });
    expect((await put({ url, events: ["mandate.signed", "mandate.revoked"] }, key)).json()).toEqual(first.json());

    const off = await put({ url, events: [] });
    expect(off.statusCode).toBe(200);
    expect(await stand.registry.subscription(code)).toEqual({ url, events: [] });
  });

  it.each([
    ["http://", `http://${STAND_AGENT_EMULATOR_HOST}/pao/events`],
    ["IP-литерал", `https://${STAND_AGENT_EMULATOR_ADDRESS}/pao/events`],
    ["петлевой IP-литерал", "https://127.0.0.1/pao/events"],
    ["метаданные облака", "https://169.254.169.254/latest/meta-data"],
    ["хост не из списка", "https://agent.example/pao/events"],
    ["порт", `https://${STAND_AGENT_EMULATOR_HOST}:8443/pao/events`],
    ["userinfo", `https://u:p@${STAND_AGENT_EMULATOR_HOST}/pao/events`],
  ])("%s — 400 REQUEST_INVALID, подписка не меняется", async (_name, bad) => {
    const before = await stand.registry.subscription(code);
    const res = await put({ url: bad, events: ["mandate.signed"] });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ code: "REQUEST_INVALID" });
    expect(res.body).not.toMatch(/scheme|ip_literal|host_not_allowed|port|userinfo/);
    expect(await stand.registry.subscription(code)).toEqual(before);
  });

  it.each([
    ["петлевой", ["127.0.0.1"]],
    ["частная сеть", ["10.0.0.5"]],
    ["метаданные облака", ["169.254.169.254"]],
    ["IPv4-mapped", ["::ffff:127.0.0.1"]],
    ["глобальный и внутренний вместе", [STAND_AGENT_EMULATOR_ADDRESS, "192.168.0.10"]],
    ["имя не разрешается", []],
  ])("подмена DNS: %s — 400 REQUEST_INVALID", async (_name, addrs) => {
    stand.dns.set(STAND_AGENT_EMULATOR_HOST, addrs);
    const before = await stand.registry.subscription(code);
    const res = await put({ url, events: ["mandate.signed"] });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ code: "REQUEST_INVALID" });
    expect(await stand.registry.subscription(code)).toEqual(before);
  });

  it("тело не по схеме — 400 REQUEST_INVALID; без Idempotency-Key — 400 IDEMPOTENCY_REQUIRED", async () => {
    expect((await put({ url, events: ["mandate.unknown"] })).json()).toMatchObject({ code: "REQUEST_INVALID" });
    const nokey = await put({ url, events: [] }, null);
    expect(nokey.statusCode).toBe(400);
    expect(nokey.json()).toMatchObject({ code: "IDEMPOTENCY_REQUIRED" });
  });

  it.each(["SUSPENDED", "EXCLUDED"] as const)("%s — 403 AGENT_SUSPENDED, подписка не меняется (РП40 п. 6–7)", async (to) => {
    const c = `nspk:agent:subscription-${to.toLowerCase()}:v1`;
    const s = newAgentSide();
    expect((await stand.admit(buyerApplication(c, s), "op")).admitted).toBe(true);
    expect((await put({ url, events: ["mandate.signed"] }, randomUUID(), s, c)).statusCode).toBe(200);
    await stand.registry.changeStatus(c, { to, ground: "KEY_COMPROMISE" });
    const res = await put({ url, events: [] }, randomUUID(), s, c);
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
    expect(await stand.registry.subscription(c)).toEqual({ url, events: ["mandate.signed"] });
  });
});

describe("шлюз подписки: журнал процесса, таймаут DNS, стендовый порт (РП40 п. 2, 4, 8; инвариант 3)", () => {
  const code = "nspk:agent:subscription-log:v1";
  const url = `https://${STAND_AGENT_EMULATOR_HOST}/secret-path/pao?token=t0p`;

  /** Сервер шлюза со своими разрешением имени и журналом процесса; агент допущен. */
  async function gateway(resolveHost: HostResolver, opts: { stand?: boolean } = { stand: true }) {
    const params = loadParams();
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const side = newAgentSide();
    expect((await registry.admit(buyerApplication(code, side), { contour: "sandbox", operator: "op" })).admitted).toBe(true);
    const lines: Record<string, unknown>[] = [];
    const app = Fastify({ logger: { level: "info", stream: { write: (l: string) => void lines.push(JSON.parse(l)) } } });
    await app.register(async (scope) =>
      paoRoutes(scope, {
        verifier: new PaoRequestVerifier(
          { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
          { skewSec: params.signature_skew_sec },
        ),
        keys,
        idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }),
        params,
        consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
        subscriptions: { set: registry.subscribe.bind(registry) },
        resolveHost,
        ...opts,
      }),
    );
    await app.ready();
    const put = (u: string, key = randomUUID()) =>
      signedInject(app, side, code, {
        method: "PUT",
        path: "/pao/v1/subscription",
        body: JSON.stringify({ url: u, events: [] }),
        headers: { "idempotency-key": key },
      });
    return { app, lines, put, registry };
  }

  const refusals = (lines: Record<string, unknown>[]) => lines.filter((l) => String(l.msg).includes("адрес подписки не принят"));

  it("отказ — в журнал процесса причина и хост, без пути и запроса", async () => {
    const dns = createStandDns();
    dns.set(STAND_AGENT_EMULATOR_HOST, ["10.0.0.5"]);
    const g = await gateway(dns.resolve);
    expect((await g.put(url)).statusCode).toBe(400);
    expect((await g.put(url.replace(STAND_AGENT_EMULATOR_HOST, "other.example"))).statusCode).toBe(400);
    const r = refusals(g.lines);
    expect(r.map((l) => [l.reason, l.host])).toEqual([
      ["address_not_global", STAND_AGENT_EMULATOR_HOST],
      ["host_not_allowed", "other.example"],
    ]);
    expect(JSON.stringify(g.lines)).not.toMatch(/secret-path|t0p/);
    await g.app.close();
  });

  it("разрешение имени зависло — 503 STATE_UNAVAILABLE не позже предела шлюза, не под ключом: повтор тем же ключом — 200 (инвариант 3, дополнение РП40 п. 3)", async () => {
    let hang = true;
    const g = await gateway(async () => (hang ? new Promise<readonly string[]>(() => undefined) : [STAND_AGENT_EMULATOR_ADDRESS]));
    const key = randomUUID();
    const t0 = performance.now();
    const res = await g.put(url, key);
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ code: "STATE_UNAVAILABLE", retry: "same_key" });
    expect(res.headers["retry-after"]).toBeDefined();
    expect(performance.now() - t0).toBeLessThan(PAO_DB_TIMEOUT_MS + 1000);
    expect(refusals(g.lines)).toEqual([]);
    expect(g.lines.filter((l) => String(l.msg).includes("сбой разрешения имени")).map((l) => l.host)).toEqual([STAND_AGENT_EMULATOR_HOST]);
    expect(JSON.stringify(g.lines)).not.toMatch(/secret-path|t0p/);
    expect(await g.registry.subscription(code)).toBeUndefined();
    hang = false;
    const again = await g.put(url, key);
    expect(again.statusCode).toBe(200);
    expect(await g.registry.subscription(code)).toMatchObject({ events: [] });
    await g.app.close();
  });

  it("временный сбой DNS (EAI_AGAIN) — 503 STATE_UNAVAILABLE; имени нет (ENOTFOUND) — 400 REQUEST_INVALID", async () => {
    let code: string = "EAI_AGAIN";
    const g = await gateway(async () => {
      throw Object.assign(new Error("dns"), { code });
    });
    expect((await g.put(url)).json()).toMatchObject({ code: "STATE_UNAVAILABLE" });
    code = "ENOTFOUND";
    const res = await g.put(url);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ code: "REQUEST_INVALID" });
    expect(refusals(g.lines).map((l) => l.reason)).toEqual(["name_not_found"]);
    await g.app.close();
  });

  it("стендовое разрешение имени без stand: true — отказ запуска (РП40 п. 8)", async () => {
    await expect(gateway(createStandDns().resolve, {})).rejects.toThrow(/стендовое разрешение имени в рабочем сервере/);
  });
});
