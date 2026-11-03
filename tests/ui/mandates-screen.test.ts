// Экран мандатов — эталонный модуль банка (UI-К2 ч. 1, К1.1; решение владельца 02.11; правило совместимости 3):
// язык и бренд с проверкой при создании, заголовки безопасности, вход по одноразовой ссылке с коротким сроком, сессия в
// cookie `__Host-` (HttpOnly, Secure, SameSite=Strict), CSRF у формы; токен ссылки, cookie и CSRF не попадают в журнал
// процесса; подключение к стенду (`stand.bankApp`).
import { afterAll, describe, expect, it } from "vitest";
import { createMandatesScreen, type MandatesScreenDeps } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort } from "../../src/ui/mandates/port.js";
import { SESSION_COOKIE } from "../../src/ui/mandates/session.js";
import { UI_CSP, type UiSettings } from "../../src/ui/shared/index.js";
import { createStand } from "../../src/stand/index.js";

const T0 = Date.parse("2026-11-02T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const PRINCIPAL = "cl_screen_k11";

const EMPTY_PORT: MandatesScreenPort = {
  mandates: async () => [],
  mandate: async () => undefined,
  decide: async () => ({ kind: "NOT_FOUND" }),
  revoke: async () => ({ kind: "NOT_FOUND" }),
  revokeAll: async () => ({ revoked: 0 }),
  confirmations: async () => [],
  confirmation: async () => undefined,
  confirm: async () => ({ kind: "NOT_FOUND" }),
};

function setup(over: Partial<MandatesScreenDeps> = {}) {
  let t = T0;
  const screen = createMandatesScreen({ port: EMPTY_PORT, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(t), ...over });
  return { screen, app: screen.app, tick: (sec: number) => (t += sec * 1000) };
}

const cookieOf = (setCookie: unknown): string => {
  const v = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return String(v).split(";")[0]!;
};

async function login(app: ReturnType<typeof setup>["app"], path: string) {
  const res = await app.inject({ method: "GET", url: path });
  expect(res.statusCode).toBe(303);
  return cookieOf(res.headers["set-cookie"]);
}

const csrfOf = (html: string): string => /name="csrf" value="([^"]+)"/.exec(html)![1]!;

describe("экран мандатов: язык и бренд (правило совместимости 3)", () => {
  it("по умолчанию — ru и бренд банка стенда; ?lang=en — английский; переключатель — на другой язык", async () => {
    const { app } = setup();
    const ru = await app.inject({ method: "GET", url: "/" });
    expect(ru.body).toContain('<html lang="ru">');
    expect(ru.body).toContain("Войдите через приложение банка");
    expect(ru.body).toContain('href="?lang=en" data-lang-switch');
    const en = await app.inject({ method: "GET", url: "/?lang=en" });
    expect(en.body).toContain('<html lang="en">');
    expect(en.body).toContain("Please sign in through your banking app");
    expect(en.body).toContain('href="?lang=ru" data-lang-switch');
    const odd = await app.inject({ method: "GET", url: "/?lang=de" });
    expect(odd.body).toContain('<html lang="ru">');
  });

  it("бренд из настройки — название, цвет, логотип; язык по умолчанию — en", async () => {
    const settings: UiSettings = { lang: "en", brand: { name: "Test <Bank>", color: "#123abc", logo_url: "https://bank.example/logo.svg" } };
    const { app } = setup({ settings });
    const res = await app.inject({ method: "GET", url: "/" });
    expect(res.body).toContain('<html lang="en">');
    expect(res.body).toContain("<strong data-brand>Test &lt;Bank&gt;</strong>");
    expect(res.body).toContain("background:#123abc");
    expect(res.body).toContain('<img src="https://bank.example/logo.svg"');
  });

  it("неверная настройка — отказ запуска экрана", () => {
    const base = { lang: "ru", brand: { name: "Б", color: "#000000" } } as const;
    expect(() => setup({ settings: { ...base, lang: "de" as never } })).toThrow(/язык/);
    expect(() => setup({ settings: { ...base, brand: { name: "", color: "#000000" } } })).toThrow(/название/);
    expect(() => setup({ settings: { ...base, brand: { name: "Б", color: "red" } } })).toThrow(/цвет/);
    expect(() => setup({ settings: { ...base, brand: { name: "Б", color: "#000000", logo_url: "http://x/l.png" } } })).toThrow(/логотип/);
  });

  it("неверные сроки входа — отказ запуска", () => {
    expect(() => setup({ ttl: { login_ttl_sec: 0, session_ttl_sec: 900 } })).toThrow(/ссылки/);
    expect(() => setup({ ttl: { login_ttl_sec: 601, session_ttl_sec: 900 } })).toThrow(/ссылки/);
    expect(() => setup({ ttl: { login_ttl_sec: 120, session_ttl_sec: 3601 } })).toThrow(/сессии/);
  });
});

describe("экран мандатов: заголовки безопасности", () => {
  it("CSP без скриптов и фреймов, DENY, no-store, nosniff, no-referrer", async () => {
    const { app } = setup();
    const res = await app.inject({ method: "GET", url: "/" });
    expect(res.headers["content-security-policy"]).toBe(UI_CSP);
    expect(UI_CSP).toContain("frame-ancestors 'none'");
    expect(UI_CSP).toContain("form-action 'self'");
    expect(UI_CSP).not.toContain("script-src");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
  });
});

describe("экран мандатов: вход по одноразовой ссылке и сессия", () => {
  it("без сессии — 401; ссылка → 303, cookie __Host- HttpOnly Secure SameSite=Strict; с cookie — 200", async () => {
    const { app, screen } = setup();
    expect((await app.inject({ method: "GET", url: "/" })).statusCode).toBe(401);
    const res = await app.inject({ method: "GET", url: `${screen.loginPath(PRINCIPAL)}?lang=en` });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe("/?lang=en");
    expect(res.headers["cache-control"]).toBe("no-store");
    const sc = String(res.headers["set-cookie"]);
    expect(sc.startsWith(`${SESSION_COOKIE}=`)).toBe(true);
    expect(SESSION_COOKIE.startsWith("__Host-")).toBe(true);
    for (const flag of ["Path=/", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=900"]) expect(sc).toContain(flag);
    expect(sc).not.toContain("Domain");
    const home = await app.inject({ method: "GET", url: "/?lang=en", headers: { cookie: cookieOf(res.headers["set-cookie"]) } });
    expect(home.statusCode).toBe(200);
    expect(home.body).toContain("data-logout");
  });

  it("ссылка одноразовая: второй переход — 401, сессия первого остаётся", async () => {
    const { app, screen } = setup();
    const path = screen.loginPath(PRINCIPAL);
    const cookie = await login(app, path);
    const again = await app.inject({ method: "GET", url: path });
    expect(again.statusCode).toBe(401);
    expect(again.headers["set-cookie"]).toBeUndefined();
    expect(again.body).toContain("Ссылка недействительна");
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie } })).statusCode).toBe(200);
  });

  it("ссылка действует строго меньше login_ttl_sec; истёкшая гасится", async () => {
    const a = setup();
    const p1 = a.screen.loginPath(PRINCIPAL);
    a.tick(119);
    expect((await a.app.inject({ method: "GET", url: p1 })).statusCode).toBe(303);
    const b = setup();
    const p2 = b.screen.loginPath(PRINCIPAL);
    b.tick(120);
    expect((await b.app.inject({ method: "GET", url: p2 })).statusCode).toBe(401);
    b.tick(-120);
    expect((await b.app.inject({ method: "GET", url: p2 })).statusCode).toBe(401);
  });

  it("неизвестный и не по форме токен — тот же 401", async () => {
    const { app } = setup();
    for (const t of ["A".repeat(43), "short", "%2e%2e", "A".repeat(44)]) {
      const res = await app.inject({ method: "GET", url: `/login/${t}` });
      expect(res.statusCode).toBe(401);
    }
  });

  it("сессия истекает через session_ttl_sec; чужое или битое cookie — 401", async () => {
    const { app, screen, tick } = setup();
    const cookie = await login(app, screen.loginPath(PRINCIPAL));
    tick(899);
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie } })).statusCode).toBe(200);
    tick(1);
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie } })).statusCode).toBe(401);
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie: `${SESSION_COOKIE}=${"B".repeat(43)}` } })).statusCode).toBe(401);
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie: `${SESSION_COOKIE}=x; other=1` } })).statusCode).toBe(401);
  });
});

describe("экран мандатов: CSRF у формы", () => {
  it("выход без CSRF и с чужим — 403, сессия жива; с верным — 200, cookie сброшено, дальше 401", async () => {
    const { app, screen } = setup();
    const cookie = await login(app, screen.loginPath(PRINCIPAL));
    const home = await app.inject({ method: "GET", url: "/", headers: { cookie } });
    const csrf = csrfOf(home.body);
    const form = (body: string) =>
      app.inject({ method: "POST", url: "/logout", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, payload: body });
    expect((await form("lang=ru")).statusCode).toBe(403);
    expect((await form(`lang=ru&csrf=${"C".repeat(43)}`)).statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie } })).statusCode).toBe(200);
    // Другая сессия того же клиента — свой CSRF: токен первой сессии во второй не действует.
    const cookie2 = await login(app, screen.loginPath(PRINCIPAL));
    const cross = await app.inject({
      method: "POST",
      url: "/logout",
      headers: { cookie: cookie2, "content-type": "application/x-www-form-urlencoded" },
      payload: `csrf=${encodeURIComponent(csrf)}`,
    });
    expect(cross.statusCode).toBe(403);
    const out = await form(`lang=en&csrf=${encodeURIComponent(csrf)}`);
    expect(out.statusCode).toBe(200);
    expect(out.body).toContain("You have signed out.");
    expect(String(out.headers["set-cookie"])).toContain("Max-Age=0");
    expect((await app.inject({ method: "GET", url: "/", headers: { cookie } })).statusCode).toBe(401);
    expect((await form(`csrf=${encodeURIComponent(csrf)}`)).statusCode).toBe(401);
  });
});

describe("экран мандатов: токен ссылки, cookie и CSRF — не в журнале процесса", () => {
  it("журнал не пуст (положительный контроль), шаблон маршрута есть, значений нет", async () => {
    const lines: string[] = [];
    const { app, screen } = setup({ logger: { level: "info", stream: { write: (l: string) => void lines.push(l) } } });
    const path = screen.loginPath(PRINCIPAL);
    const token = path.slice("/login/".length);
    const res = await app.inject({ method: "GET", url: path });
    const sc = String(res.headers["set-cookie"]);
    const sid = sc.slice(SESSION_COOKIE.length + 1).split(";")[0]!;
    const cookie = `${SESSION_COOKIE}=${sid}`;
    const home = await app.inject({ method: "GET", url: "/", headers: { cookie } });
    const csrf = csrfOf(home.body);
    await app.inject({ method: "GET", url: path });
    await app.inject({
      method: "POST",
      url: "/logout",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `csrf=${encodeURIComponent(csrf)}`,
    });
    expect(lines.length).toBeGreaterThan(0);
    const all = lines.join("\n");
    for (const secret of [token, sid, csrf, PRINCIPAL]) expect(all).not.toContain(secret);
    expect(all).not.toContain(SESSION_COOKIE);
    expect(all).toContain("/login/:token");
  });
});

describe("экран мандатов на стенде (stand.bankApp)", () => {
  const stand = createStand({ bankApp: { lang: "en", brand: { name: "Stand Bank", color: "#654321" } } });
  afterAll(() => stand.close());

  it("ссылка от стенда открывает сессию; язык и бренд — из StandOptions", async () => {
    const res = await stand.bankApp.app.inject({ method: "GET", url: stand.bankApp.session(PRINCIPAL) });
    expect(res.statusCode).toBe(303);
    const home = await stand.bankApp.app.inject({ method: "GET", url: "/", headers: { cookie: cookieOf(res.headers["set-cookie"]) } });
    expect(home.statusCode).toBe(200);
    expect(home.body).toContain('<html lang="en">');
    expect(home.body).toContain("<strong data-brand>Stand Bank</strong>");
  });
});
