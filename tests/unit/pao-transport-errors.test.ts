// РП62 п. 1–5: ответы транспорта в области /pao — тело ПАО §6 (до 1.5.0 — REQUEST_INVALID при HTTP Fastify), вне /pao —
// {code}; каждый отказ — запись «отказ транспорта» без пути, строки запроса и err.message. Стенд собирается целиком,
// журнал — в массив (как server-request-log).
import { randomUUID } from "node:crypto";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { signRequest } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { paoIdempotency } from "../../src/pao/idempotency.js";
import { PAO_BODY_LIMIT_BYTES } from "../../src/pao/transport.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer, type ServerOptions } from "../../src/server.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { memoryConsent } from "../support/consent.js";
import { coarseLimit } from "../support/rate-limit.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const sink = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock("../../src/server.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/server.js")>();
  return {
    ...actual,
    buildServer: (opts: ServerOptions) =>
      actual.buildServer({ ...opts, logger: { level: "info", stream: { write: (l: string) => void sink.lines.push(l) } } }),
  };
});

type Entry = Record<string, unknown>;
const entries = (): Entry[] => sink.lines.map((l) => JSON.parse(l) as Entry);
const rejects = (): Entry[] => entries().filter((e) => e.msg === "отказ транспорта");

const A = "nspk:agent:buyref-01:v3";
const mark = `mark${randomUUID().replaceAll("-", "")}`;
/** Тело §6 строго по схеме Error: только code, message, retry (norm у этих отказов нет). */
const PAO_REQUEST_INVALID = { code: "REQUEST_INVALID", message: expect.any(String), retry: "after_fix" };

describe("ответы транспорта по ПАО §6 и запись отказа (РП62)", () => {
  let s: Stand;
  let a: AgentSide;

  beforeEach(async () => {
    sink.lines.length = 0;
    s = stand();
    a = newAgentSide();
    expect((await s.admit(buyerApplication(A, a), "op")).admitted).toBe(true);
    await s.app.ready();
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await s.app.close();
  });

  it("в /pao: 404, 414, 400 bad url, 413 — тело §6 с REQUEST_INVALID при HTTP Fastify, без пути", async () => {
    const calls = [
      { status: 404, reject: "NOT_FOUND", req: { url: `/pao/v1/${mark}?q=${mark}` } },
      { status: 414, reject: "FST_ERR_MAX_PARAM_LENGTH", req: { method: "POST" as const, url: `/pao/v1/agent/keys/${mark}${"x".repeat(300)}/revoke?q=${mark}` } },
      { status: 400, reject: "FST_ERR_BAD_URL", req: { url: `/pao/v1/mandates/%zz${mark}?q=${mark}` } },
      {
        status: 413,
        reject: "FST_ERR_CTP_BODY_TOO_LARGE",
        req: {
          method: "POST" as const,
          url: `/pao/v1/mandates?q=${mark}`,
          // Агент допущен: предпроверка до тела пройдена, отвечает разбор тела (РП63 п. 10).
          headers: { "content-type": "application/json", "x-agent-code": A },
          payload: `{"x":"${mark}${"y".repeat(PAO_BODY_LIMIT_BYTES)}"}`,
        },
      },
    ];
    for (const c of calls) {
      const res = await s.app.inject(c.req);
      expect(res.statusCode).toBe(c.status);
      expect(res.json()).toStrictEqual(PAO_REQUEST_INVALID);
      expect(res.body).not.toContain(mark);
    }
    const got = rejects();
    expect(got.map((e) => [e.reject, e.status, e.pao_code, e.area])).toEqual(
      calls.map((c) => [c.reject, c.status, "REQUEST_INVALID", "pao"]),
    );
    for (const [i, c] of calls.entries()) {
      expect(got[i]?.url_length).toBe(Buffer.byteLength(c.req.url));
      expect(got[i]?.level).toBe(40);
      expect(got[i]).not.toHaveProperty("err");
      // Адрес — через сериализатор и у запроса без контекста маршрута (frameworkErrors).
      expect(got[i]?.req).toMatchObject({ method: c.req.method ?? "GET", remoteAddress: "127.0.0.1" });
    }
    expect(got[3]?.content_length).toBeGreaterThan(PAO_BODY_LIMIT_BYTES);
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
  });

  it("4xx разбора (Content-Length не по телу, испорченный Content-Type) — 400 REQUEST_INVALID по §6, запись с кодом Fastify", async () => {
    // Агент допущен: предпроверка до тела пройдена, отвечает разбор тела (РП63 п. 10).
    for (const headers of [
      { "content-type": "application/json", "content-length": "999", "x-agent-code": A },
      { "content-type": `\u0000${mark}`, "x-agent-code": A },
    ]) {
      const res = await s.app.inject({ method: "POST", url: `/pao/v1/mandates?q=${mark}`, headers, payload: "{}" });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toStrictEqual(PAO_REQUEST_INVALID);
    }
    const got = rejects();
    expect(got.map((e) => [e.status, e.pao_code, e.area])).toEqual([
      [400, "REQUEST_INVALID", "pao"],
      [400, "REQUEST_INVALID", "pao"],
    ]);
    for (const e of got) expect(String(e.reject)).toMatch(/^FST_ERR_CTP_/);
    expect(got[0]?.content_length).toBe(999);
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
  });

  it("предпроверка до тела (РП63 п. 9–10): неизвестный агент или без x-agent-code с телом больше 64 КиБ — 401 AGENT_UNKNOWN, тело не читается", async () => {
    for (const headers of [{ "content-type": "application/json", "x-agent-code": "nspk:agent:nobody:v1" }, { "content-type": "application/json" }]) {
      const res = await s.app.inject({
        method: "POST",
        url: "/pao/v1/mandates",
        headers,
        payload: `{"x":"${"y".repeat(PAO_BODY_LIMIT_BYTES + 10)}"}`,
      });
      expect([res.statusCode, res.json().code]).toEqual([401, "AGENT_UNKNOWN"]);
    }
    // Ответ — до разбора: записи «отказ транспорта» 413 нет.
    expect(rejects()).toEqual([]);
  });

  // Повтор заголовка через inject не воспроизводится (РП62 доп. 8) — тест повтора через node:http ниже.
  it("предпроверка до тела: неизвестный агент с телом у GET — AGENT_UNKNOWN, порядок прежний (агент → тело)", async () => {
    const unknownWithBody = await s.app.inject({
      method: "GET",
      url: "/pao/v1/agent",
      headers: { "x-agent-code": "nspk:agent:nobody:v1", "content-length": "5" },
      payload: "abcde",
    });
    expect([unknownWithBody.statusCode, unknownWithBody.json().code]).toEqual([401, "AGENT_UNKNOWN"]);
  });

  it("тело на пределе 64 КиБ доходит до проверки обращения (401 по §6, не 413)", async () => {
    const res = await s.app.inject({
      method: "POST",
      url: "/pao/v1/mandates",
      headers: { "content-type": "application/json" },
      payload: "x".repeat(PAO_BODY_LIMIT_BYTES),
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ code: "AGENT_UNKNOWN" });
  });

  it("исключение обработчика — 503 UPSTREAM_UNAVAILABLE с Retry-After, в записи err — только name, code, кадры стека", async () => {
    vi.spyOn(s.keys, "list").mockImplementation(() => {
      // Как у ошибок PostgreSQL: message, detail и where со значениями запроса и путём в запись не идут (КТ1 № 8).
      throw Object.assign(new Error(`сбой ключей /pao/v1/agent/${mark}\nзначение ${mark}`), { code: "XX000", detail: mark, where: mark });
    });
    const res = await signedInject(s.app, a, A, { query: `q=${mark}` });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toStrictEqual({ code: "UPSTREAM_UNAVAILABLE", message: expect.any(String), retry: "same_key" });
    expect(res.headers["retry-after"]).toBe(String(s.params.unavailable_retry_after_sec));
    const [e] = rejects();
    expect(e).toMatchObject({ reject: "UNHANDLED", status: 503, pao_code: "UPSTREAM_UNAVAILABLE", area: "pao" });
    expect(Object.keys(e?.err as object).sort()).toEqual(["code", "name", "stack"]);
    expect(e?.err).toMatchObject({ name: "Error", code: "XX000" });
    const stack = String((e?.err as { stack?: unknown }).stack);
    expect(stack).toMatch(/^\s+at /);
    for (const line of stack.split("\n")) expect(line).toMatch(/^\s+at /);
    for (const x of entries()) expect(JSON.stringify(x)).not.toContain(mark);
  });

  it("/pao и /pao?x, метод без маршрута на существующем пути, POST с телом на несуществующий путь — 404 по §6 с записью", async () => {
    const calls = [
      { url: "/pao" },
      { url: `/pao?q=${mark}` },
      { method: "DELETE" as const, url: `/pao/v1/agent?q=${mark}` },
      { method: "POST" as const, url: `/pao/v1/${mark}`, headers: { "content-type": "application/json" }, payload: `{"x":"${mark}"}` },
    ];
    for (const c of calls) {
      const res = await s.app.inject(c);
      expect(res.statusCode).toBe(404);
      expect(res.json()).toStrictEqual(PAO_REQUEST_INVALID);
    }
    expect(rejects().map((e) => [e.reject, e.status, e.area])).toEqual(calls.map(() => ["NOT_FOUND", 404, "pao"]));
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
  });

  /** Подписанные заголовки, как у signedInject, — чтобы затем повторить или добавить заголовок в обход подписи. */
  function signedHeaders(method: string, path: string, body = "", extra: Record<string, string> = {}): Record<string, string> {
    const headers: Record<string, string> = {
      "x-agent-code": A,
      "x-timestamp": new Date().toISOString().slice(0, 19) + "Z",
      "x-nonce": randomUUID(),
      ...(body !== "" ? { "content-type": "application/json" } : {}),
      ...extra,
    };
    return signRequest({ method, path, query: "", headers, body }, a.signer).headers;
  }

  it("повтор подписываемого заголовка — 401 SIGNATURE_INVALID, даже когда склейка Node совпала бы с подписанным (РП62 п. 6)", async () => {
    // Подписано x-nonce «p, q»; пришло два заголовка «p» и «q» — Node склеил бы их ровно в подписанное значение, и без
    // проверки повтора подпись сошлась бы. Прокси за шлюзом мог бы взять из них только первое.
    // По настоящему HTTP: у inject массив заголовка остаётся массивом, склеивает его только сервер Node.
    const nonce = `${randomUUID()}, ${randomUUID()}`;
    const h = signedHeaders("GET", "/pao/v1/agent", "", { "x-nonce": nonce });
    await s.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = s.app.server.address() as AddressInfo;
    const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const r = request({ host: "127.0.0.1", port, path: "/pao/v1/agent", headers: { ...h, "x-nonce": nonce.split(", ") } }, (m) => {
        let body = "";
        m.on("data", (c: Buffer) => (body += c.toString()));
        m.on("end", () => resolve({ status: m.statusCode ?? 0, body }));
      });
      r.on("error", reject);
      r.end();
    });
    expect([res.status, (JSON.parse(res.body) as { code: string }).code]).toEqual([401, "SIGNATURE_INVALID"]);
    // Тот же подписанный «p, q» одним заголовком — принят: значение с запятой само по себе не отказ.
    const one = await s.app.inject({ url: "/pao/v1/agent", headers: signedHeaders("GET", "/pao/v1/agent", "", { "x-nonce": nonce }) });
    expect(one.statusCode).toBe(200);
  });

  it("два Idempotency-Key — 400 REQUEST_INVALID, ключ «a, b» не занят (РП62 п. 6)", async () => {
    const body = "{}";
    const h = signedHeaders("POST", "/pao/v1/mandates", body);
    const res = await s.app.inject({ method: "POST", url: "/pao/v1/mandates", headers: { ...h, "idempotency-key": ["a", "b"] }, payload: body });
    expect([res.statusCode, res.json().code]).toEqual([400, "REQUEST_INVALID"]);
    // Ключ «a, b» не занят: с ним одним — обычный путь метода (тело {} не по схеме — тот же REQUEST_INVALID, но не конфликт).
    const one = await s.app.inject({
      method: "POST",
      url: "/pao/v1/mandates",
      headers: signedHeaders("POST", "/pao/v1/mandates", body, { "idempotency-key": "a, b" }),
      payload: body,
    });
    expect([one.statusCode, one.json().code]).toEqual([400, "REQUEST_INVALID"]);
  });

  it("тело у GET (Content-Length или Transfer-Encoding) — 401 SIGNATURE_INVALID (РП62 п. 7)", async () => {
    for (const extra of [{ "content-length": "2" }, { "transfer-encoding": "chunked" }]) {
      const res = await s.app.inject({ url: "/pao/v1/agent", headers: { ...signedHeaders("GET", "/pao/v1/agent"), ...extra } });
      expect([res.statusCode, res.json().code]).toEqual([401, "SIGNATURE_INVALID"]);
    }
  });

  it("% в сыром пути существующего маршрута — 400 REQUEST_INVALID, подпись над сырым путём не спасает (РП62 п. 8)", async () => {
    const path = `/pao/v1/mandates/%6D${mark}`;
    const res = await s.app.inject({ url: path, headers: signedHeaders("GET", path) });
    expect([res.statusCode, res.json().code]).toEqual([400, "REQUEST_INVALID"]);
  });

  it("HEAD на существующий путь — 404 с записью отказа транспорта (РП62 п. 8)", async () => {
    const res = await s.app.inject({ method: "HEAD", url: `/pao/v1/agent?q=${mark}` });
    expect(res.statusCode).toBe(404);
    expect(rejects().map((e) => [e.reject, e.status, e.area])).toEqual([["NOT_FOUND", 404, "pao"]]);
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
  });

  it("сбой источника при проверке обращения — 503, в записи err только name, code и кадры стека", async () => {
    vi.spyOn(s.registry, "get").mockImplementation(async () => {
      throw Object.assign(new Error(`сбой реестра ${mark}`), { code: "XX000", detail: mark, where: mark });
    });
    const res = await signedInject(s.app, a, A);
    expect(res.statusCode).toBe(503);
    const e = entries().find((x) => typeof x.msg === "string" && x.msg.startsWith("ПАО: сбой источника"));
    expect(Object.keys(e?.err as object).sort()).toEqual(["code", "name", "stack"]);
    for (const x of entries()) expect(JSON.stringify(x)).not.toContain(mark);
  });

  it("вне /pao: 414 и 400 bad url — тем же HTTP, тело {code: REQUEST_INVALID}, без пути; запись area other", async () => {
    const r414 = await s.app.inject({ url: `/merchants/v1/agents/${mark}${"x".repeat(300)}?q=${mark}` });
    const r400 = await s.app.inject({ url: `/participants/v1/mandates/%zz${mark}/sign?q=${mark}`, method: "POST" });
    expect([r414.statusCode, r400.statusCode]).toEqual([414, 400]);
    for (const r of [r414, r400]) expect(r.json()).toStrictEqual({ code: "REQUEST_INVALID" });
    expect(rejects().map((e) => [e.reject, e.status, e.area, e.pao_code])).toEqual([
      ["FST_ERR_MAX_PARAM_LENGTH", 414, "other", undefined],
      ["FST_ERR_BAD_URL", 400, "other", undefined],
    ]);
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
  });
});

describe("404 в /pao — под грубым лимитом по адресу (РП62 п. 1; аудит К4.3 № 6)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  /** Собранный сервер с шлюзом ПАО при пределе 2 — как в рабочей сборке, регистрация 404 с префиксом /pao (server.ts). */
  function server(): FastifyInstance {
    const params = coarseLimit(2);
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const verifier = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    return buildServer({
      env: "dev",
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    });
  }
  const nope = async (i: number) => (await app!.inject({ url: `/pao/v1/nope${i}` })).statusCode;
  const gate = async () => (await app!.inject({ url: "/pao/v1/agent" })).statusCode;

  it("предел 2: третий несуществующий путь — 429 RATE_LIMITED по §6, а не 404", async () => {
    app = server();
    expect([await nope(0), await nope(1), await nope(2)]).toEqual([404, 404, 429]);
    const last = await app.inject({ url: "/pao/v1/nope" });
    expect(last.json()).toStrictEqual({ code: "RATE_LIMITED", message: expect.any(String), retry: "same_key" });
  });

  it("POST с испорченным Content-Type на несуществующий путь — 404 до разбора тела, под лимитом (КТ1 № 1): третий — 429", async () => {
    app = server();
    const post = async () =>
      (await app!.inject({ method: "POST", url: "/pao/v1/nope", headers: { "content-type": "\u0000bad" }, payload: "{" })).statusCode;
    expect([await post(), await post(), await post()]).toEqual([404, 404, 429]);
  });

  it("тело несуществующего пути не читается: больше серверного предела 1 МиБ — всё равно 404 по §6, не 413", async () => {
    app = server();
    const res = await app.inject({
      method: "POST",
      url: "/pao/v1/nope",
      headers: { "content-type": "application/json" },
      payload: "x".repeat(1_100_000),
    });
    expect([res.statusCode, res.json().code]).toEqual([404, "REQUEST_INVALID"]);
  });

  it("счётчики 404 и шлюза раздельны в собранном сервере: исчерпание одного не даёт 429 другому", async () => {
    app = server();
    expect([await nope(0), await nope(1), await nope(2)]).toEqual([404, 404, 429]);
    expect([await gate(), await gate(), await gate()]).toEqual([401, 401, 429]);
    expect(await nope(3)).toBe(429);
  });
});
