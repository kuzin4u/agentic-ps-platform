// РП61: журнал запросов без значений параметров пути и строки запроса — на всех маршрутах сервера (блокер развёртывания,
// РП60 доп. 4). Стенд собирается целиком (ПАО, обнаружение, ПИ-8, API продавцов, ADP); buildServer подменяется обёрткой,
// которая пишет журнал в массив, собирает маршруты и добавляет маршрут-сбой для записи 5xx.
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ServerOptions } from "../../src/server.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { stand, type Stand } from "../support/stand.js";

const sink = vi.hoisted(() => ({ lines: [] as string[], routes: [] as { method: string; url: string }[] }));

vi.mock("../../src/server.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/server.js")>();
  return {
    ...actual,
    buildServer: (opts: ServerOptions) => {
      const app = actual.buildServer({ ...opts, logger: { level: "info", stream: { write: (l: string) => void sink.lines.push(l) } } });
      // Маршруты контекстов регистрируются при ready(): хук видит каждый.
      app.addHook("onRoute", (r) => {
        for (const method of [r.method].flat()) sink.routes.push({ method, url: r.url });
      });
      // Корневой контекст без своего обработчика ошибок — запись Fastify defaultErrorLog при 5xx.
      app.get("/test/boom/:secret", async () => {
        throw new Error("сбой обработчика");
      });
      return app;
    },
  };
});

type Entry = Record<string, unknown> & { req?: Record<string, unknown> };
const entries = (): Entry[] => sink.lines.map((l) => JSON.parse(l) as Entry);
/** Стандартные записи Fastify о запросе: с req или res, «маршрут не найден». */
const standard = (): Entry[] => entries().filter((e) => "req" in e || "res" in e || e.msg === "маршрут не найден");

const A = "nspk:agent:buyref-01:v3";
const B = "nspk:agent:other-01:v1";

describe("журнал запросов без значений параметров пути (РП61)", () => {
  let s: Stand;
  const mark = `mark${randomUUID().replaceAll("-", "")}`;

  beforeEach(async () => {
    sink.lines.length = 0;
    sink.routes.length = 0;
    s = stand();
    await s.app.ready();
  });
  afterEach(async () => {
    await s.app.close();
  });

  it("каждый маршрут с параметрами пути и строкой запроса: значений нет ни в одной записи о запросе, у найденного — шаблон", async () => {
    const withParams = sink.routes.filter((r) => /[:*]/.test(r.url));
    // Все контексты стенда: ПАО, ПИ-8, API продавцов, ADP и маршрут-сбой.
    for (const prefix of ["/pao/", "/participants/", "/merchants/", "/test/boom/"]) {
      expect(withParams.some((r) => r.url.startsWith(prefix))).toBe(true);
    }
    let i = 0;
    const found: { method: string; url: string }[] = [];
    for (const r of sink.routes) {
      const n = i++;
      const path = r.url.replace(/:[A-Za-z0-9_]+(\([^)]*\))?/g, `${mark}p${n}`).replace("*", `${mark}w${n}`);
      const res = await s.app.inject({ method: r.method as "GET", url: `${path}?q=${mark}q${n}&after=${mark}a${n}` });
      if (res.statusCode !== 404) found.push(r);
    }
    expect(found.length).toBeGreaterThan(withParams.length / 2);
    // Обращения без подписи — собственных записей с kid нет (РП60 доп. 3): проверяется весь журнал, не только записи Fastify.
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
    const lines = standard();
    expect(lines.length).toBeGreaterThan(0);
    const incoming = lines.filter((e) => e.msg === "incoming request").map((e) => `${String(e.req?.method)} ${String(e.req?.route)}`);
    for (const r of found) expect(incoming).toContain(`${r.method} ${r.url}`);
    for (const e of lines.filter((x) => "req" in x)) expect(e.req).not.toHaveProperty("url");
    // 5xx необработанного исключения — запись defaultErrorLog с req: шаблон есть, значения нет.
    const boom = lines.find((e) => e.msg === "сбой обработчика");
    expect(boom?.req).toMatchObject({ method: "GET", route: "/test/boom/:secret" });
  });

  it("404, 414 и 400 bad url: значений пути и строки запроса нет; у 404 — запись без шаблона", async () => {
    const r404 = await s.app.inject({ url: `/pao/v1/${mark}n?q=${mark}` });
    expect(r404.statusCode).toBe(404);
    const r414 = await s.app.inject({ method: "POST", url: `/pao/v1/agent/keys/${mark}${"x".repeat(300)}/revoke?q=${mark}` });
    expect(r414.statusCode).toBe(414);
    const r400 = await s.app.inject({ url: `/pao/v1/mandates/%zz${mark}?q=${mark}` });
    expect(r400.statusCode).toBe(400);
    for (const e of entries()) expect(JSON.stringify(e)).not.toContain(mark);
    const notFound = entries().filter((e) => e.msg === "маршрут не найден");
    expect(notFound).toHaveLength(1);
    expect(notFound[0]?.req).toEqual({ method: "GET", host: "localhost:80", remoteAddress: "127.0.0.1" });
  });
});

describe("отзыв ключа: kid в собственной записи — только FOREIGN и UNKNOWN (РП60 доп. 3), в записях Fastify — нет", () => {
  let s: Stand;
  let a: AgentSide;
  let b: AgentSide;

  beforeEach(() => {
    sink.lines.length = 0;
    s = stand();
    a = newAgentSide();
    b = newAgentSide();
    expect(s.admit(buyerApplication(A, a), "op").admitted).toBe(true);
    expect(s.admit(buyerApplication(B, b), "op").admitted).toBe(true);
  });
  afterEach(async () => {
    await s.app.close();
  });

  it("чужой → FOREIGN и kid, неизвестный → UNKNOWN и kid, не по форме → MALFORMED и длина; стандартные записи — без всех трёх", async () => {
    const unknown = newAgentSide().kid;
    const malformed = `секрет-${randomUUID()}`;
    for (const kid of [b.kid, unknown, malformed]) {
      const res = await signedInject(s.app, a, A, {
        method: "POST",
        path: `/pao/v1/agent/keys/${encodeURIComponent(kid)}/revoke`,
        headers: { "idempotency-key": randomUUID() },
      });
      expect(res.statusCode).toBe(422);
    }
    const own = entries().filter((e) => e.msg === "ПАО: отзыв — у агента нет такого ключа (РП60 п. 2)");
    expect(own.map(({ reason, kid, kid_length }) => ({ reason, kid, kid_length }))).toEqual([
      { reason: "FOREIGN", kid: b.kid, kid_length: undefined },
      { reason: "UNKNOWN", kid: unknown, kid_length: undefined },
      { reason: "MALFORMED", kid: undefined, kid_length: malformed.length },
    ]);
    const all = sink.lines.join("\n");
    expect(all).not.toContain(malformed);
    expect(all).not.toContain(encodeURIComponent(malformed));
    const lines = standard();
    const revoke = lines.filter((e) => e.msg === "incoming request" && e.req?.route === "/pao/v1/agent/keys/:kid/revoke");
    expect(revoke.map((e) => e.req?.method)).toEqual(["POST", "POST", "POST"]);
    for (const e of lines) {
      const text = JSON.stringify(e);
      for (const kid of [b.kid, unknown]) expect(text).not.toContain(kid);
    }
  });
});
