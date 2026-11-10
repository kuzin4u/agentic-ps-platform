// Экран мандатов: обновление главной без F5 (РП36 «Нюанс UI-К2 — З9» п. 2; дополнение к #115, Р-1361, Р-1443).
// `<meta http-equiv="refresh">` — только на главной `/` при 200 и только когда задан `refresh_sec` (2…60); на страницах
// решения, в формах и в ответе 401 его нет; скриптов нет, CSP прежняя; новый запрос подтверждения виден следующим
// обращением той же сессии без входа заново. Стенд — 5 с.
import { afterEach, describe, expect, it } from "vitest";
import { createMandatesScreen, type MandatesScreenDeps } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort, ScreenConfirmation, ScreenMandate } from "../../src/ui/mandates/port.js";
import { UI_CSP } from "../../src/ui/shared/index.js";
import { createStand } from "../../src/stand/index.js";

const T0 = Date.parse("2026-11-10T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_refresh";
const MID = "mnd_00000001-0000-4000-8000-000000000000";
const CID = "cnf_00000001-0000-4000-8000-000000000000";
const META = /<meta http-equiv="refresh" content="(\d+)">/;

const mandate: ScreenMandate = {
  id: MID,
  agent_code: "nspk:agent:screen:v1",
  type: "INTENT",
  parent_id: null,
  status: "ACTIVE",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-11-17T10:00:00.000Z",
  merchant_scope: ["MER-1042"],
  subject: "продукты",
  cart: null,
  hash: "ab".repeat(32),
};

const request: ScreenConfirmation = {
  id: CID,
  agent_code: "nspk:agent:screen:v1",
  mandate_id: MID,
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref: "ORD-1",
  status: "PENDING",
  expires_at: "2026-11-10T10:15:00.000Z",
  totals_hash: "ab".repeat(32),
};

const closers: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function open(over: Partial<MandatesScreenDeps> = {}) {
  const waiting: ScreenConfirmation[] = [];
  let t = T0;
  const port: MandatesScreenPort = {
    mandates: async () => [mandate],
    mandate: async (_p, id) => (id === MID ? mandate : undefined),
    decide: async () => ({ kind: "NOT_FOUND" }),
    revoke: async () => ({ kind: "NOT_FOUND" }),
    revokeAll: async () => ({ revoked: 0 }),
    confirmations: async () => waiting,
    confirmation: async (_p, id) => waiting.find((c) => c.id === id),
    confirm: async () => ({ kind: "NOT_FOUND" }),
    agent: async () => undefined,
    history: async () => [],
    notifications: async () => [],
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(t), ...over });
  closers.push(() => screen.app.close());
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = String([login.headers["set-cookie"]].flat()[0]).split(";")[0]!;
  const get = (url: string, withCookie = true) => screen.app.inject({ method: "GET", url, headers: withCookie ? { cookie } : {} });
  return { get, waiting, tick: (sec: number) => (t += sec * 1000) };
}

describe("обновление главной без F5 (З9 п. 2)", () => {
  it("refresh_sec задан — мета-тег только на главной при 200; CSP прежняя, скриптов нет", async () => {
    const s = await open({ refresh_sec: 5 });
    s.waiting.push(request);
    const home = await s.get("/?lang=en");
    expect(home.statusCode).toBe(200);
    expect(META.exec(home.body)?.[1]).toBe("5");
    expect(home.headers["content-security-policy"]).toBe(UI_CSP);
    expect(home.body).not.toContain("<script");
    for (const url of [`/c/${CID}`, `/m/${MID}`, `/m/${MID}/history`, `/m/${MID}/revoke`, "/revoke-all", "/agents", "/notifications"]) {
      const r = await s.get(url);
      expect(r.statusCode, url).toBe(200);
      expect(r.body, url).not.toMatch(META);
    }
  });

  it("без сессии и после её срока — 401 без мета-тега: обновление останавливается", async () => {
    const s = await open({ refresh_sec: 5 });
    const anon = await s.get("/", false);
    expect(anon.statusCode).toBe(401);
    expect(anon.body).not.toMatch(META);
    s.tick(TTL.session_ttl_sec);
    const late = await s.get("/");
    expect(late.statusCode).toBe(401);
    expect(late.body).not.toMatch(META);
  });

  it("refresh_sec не задан — мета-тега нет (модуль банка по умолчанию)", async () => {
    const s = await open();
    const home = await s.get("/");
    expect(home.statusCode).toBe(200);
    expect(home.body).not.toMatch(META);
  });

  it("новый запрос подтверждения виден следующим обращением той же сессии", async () => {
    const s = await open({ refresh_sec: 5 });
    expect((await s.get("/")).body).not.toContain(`data-confirmation="${CID}"`);
    s.waiting.push(request);
    s.tick(5);
    expect((await s.get("/")).body).toContain(`data-confirmation="${CID}"`);
  });

  it("refresh_sec не целое 2…60 — отказ запуска", () => {
    for (const refresh_sec of [0, 1, 61, 2.5, Number.NaN]) {
      expect(() =>
        createMandatesScreen({ port: {} as MandatesScreenPort, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0), refresh_sec }),
      ).toThrow(/refresh_sec/);
    }
  });

  it("стенд: главная экрана банка обновляется каждые 5 с", async () => {
    const stand = createStand();
    closers.push(() => stand.close());
    const login = await stand.bankApp.app.inject({ method: "GET", url: stand.bankApp.session(P) });
    const cookie = String([login.headers["set-cookie"]].flat()[0]).split(";")[0]!;
    const home = await stand.bankApp.app.inject({ method: "GET", url: "/", headers: { cookie } });
    expect(home.statusCode).toBe(200);
    expect(META.exec(home.body)?.[1]).toBe("5");
    expect(home.headers["content-security-policy"]).toBe(UI_CSP);
  });
});
