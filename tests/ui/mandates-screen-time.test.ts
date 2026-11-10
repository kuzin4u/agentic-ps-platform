// Экран мандатов: время для человека (РП36 «Нюанс UI-К2 — З9» п. 1; дополнение к #115, Р-1361, Р-1443). Метки времени —
// «действует до» мандата, «решить до» запроса, история, уведомления — по языку страницы (ru «ДД.ММ.ГГГГ, ЧЧ:ММ», en
// «DD/MM/YYYY, HH:MM») в поясе экрана `time_zone`; машинное значение — в `<time datetime>`; строки UTC с «…Z» на странице
// нет; неразборчивая строка — как есть, экранированной; неверный пояс — отказ запуска; без пояса — пояс процесса.
import { afterEach, describe, expect, it } from "vitest";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort, ScreenConfirmation, ScreenMandate } from "../../src/ui/mandates/port.js";
import type { UiSettings } from "../../src/ui/shared/index.js";

const T0 = Date.parse("2026-11-09T09:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_time";
const MID = "mnd_00000001-0000-4000-8000-000000000000";
const CID = "cnf_00000001-0000-4000-8000-000000000000";
const BRAND = { name: "Банк стенда", color: "#2e7d32" };

const mandate = (valid_to: string): ScreenMandate => ({
  id: MID,
  agent_code: "nspk:agent:screen:v1",
  type: "INTENT",
  parent_id: null,
  status: "ACTIVE",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to,
  merchant_scope: ["MER-1042"],
  subject: "продукты",
  cart: null,
  hash: "ab".repeat(32),
});

const request = (expires_at: string): ScreenConfirmation => ({
  id: CID,
  agent_code: "nspk:agent:screen:v1",
  mandate_id: MID,
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref: "ORD-1",
  status: "PENDING",
  expires_at,
  totals_hash: "ab".repeat(32),
});

const closers: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

/** Одна метка времени во всех четырёх местах экрана. */
async function open(at: string, time_zone?: string) {
  const port: MandatesScreenPort = {
    mandates: async () => [mandate(at)],
    mandate: async (_p, id) => (id === MID ? mandate(at) : undefined),
    decide: async () => ({ kind: "NOT_FOUND" }),
    revoke: async () => ({ kind: "NOT_FOUND" }),
    revokeAll: async () => ({ revoked: 0 }),
    confirmations: async () => [request(at)],
    confirmation: async (_p, id) => (id === CID ? request(at) : undefined),
    confirm: async () => ({ kind: "NOT_FOUND" }),
    agent: async () => undefined,
    history: async () => [{ at, kind: "MANDATE_SIGNED", mandate_id: MID }],
    notifications: async () => [{ at, type: "client.revoked_all" }],
  };
  const settings: UiSettings = { lang: "ru", brand: BRAND, ...(time_zone === undefined ? {} : { time_zone }) };
  const screen = createMandatesScreen({ port, settings, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  closers.push(() => screen.app.close());
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = String([login.headers["set-cookie"]].flat()[0]).split(";")[0]!;
  /** Метки времени четырёх страниц экрана — содержимое `<time …>…</time>` целиком. */
  const times = async (lang: "ru" | "en") => {
    const out: string[] = [];
    for (const url of [`/m/${MID}`, `/c/${CID}`, `/m/${MID}/history`, "/notifications"]) {
      const r = await screen.app.inject({ method: "GET", url: `${url}?lang=${lang}`, headers: { cookie } });
      expect(r.statusCode, url).toBe(200);
      expect(r.body, url).not.toMatch(/>\s*\d{4}-\d{2}-\d{2}T/);
      out.push(...[...r.body.matchAll(/<time[^>]*>[^<]*<\/time>/g)].map((m) => m[0]));
    }
    return out;
  };
  return { times };
}

describe("время для человека на экране мандатов (З9 п. 1)", () => {
  const AT = "2026-11-10T10:54:30.123Z";

  it("ru и en в поясе экрана: «10.11.2026, 13:54» / «10/11/2026, 13:54», машинное значение — в datetime", async () => {
    const s = await open(AT, "Europe/Moscow");
    expect(await s.times("ru")).toEqual(Array(4).fill(`<time datetime="${AT}">10.11.2026, 13:54</time>`));
    expect(await s.times("en")).toEqual(Array(4).fill(`<time datetime="${AT}">10/11/2026, 13:54</time>`));
  });

  it("пояс меняет и дату: 20:30 UTC — в Москве 09.11, 23:30, во Владивостоке 10.11, 06:30", async () => {
    const at = "2026-11-09T20:30:00.000Z";
    expect(await (await open(at, "Europe/Moscow")).times("ru")).toEqual(Array(4).fill(`<time datetime="${at}">09.11.2026, 23:30</time>`));
    expect(await (await open(at, "Asia/Vladivostok")).times("ru")).toEqual(Array(4).fill(`<time datetime="${at}">10.11.2026, 06:30</time>`));
  });

  it("пояс не задан — пояс процесса", async () => {
    const own = new Intl.DateTimeFormat("ru-RU", {
      timeZone: new Intl.DateTimeFormat().resolvedOptions().timeZone,
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    }).format(Date.parse(AT));
    expect(await (await open(AT)).times("ru")).toEqual(Array(4).fill(`<time datetime="${AT}">${own}</time>`));
  });

  it("неразборчивая строка — как есть, экранированной, без datetime", async () => {
    const s = await open('вчера <b>"</b>', "Europe/Moscow");
    expect(await s.times("ru")).toEqual(Array(4).fill("<time>вчера &lt;b&gt;&quot;&lt;/b&gt;</time>"));
  });

  it("неверный пояс — отказ запуска", () => {
    for (const time_zone of ["Mars/Base", "", "x".repeat(65)]) {
      expect(() =>
        createMandatesScreen({
          port: {} as MandatesScreenPort,
          settings: { lang: "ru", brand: BRAND, time_zone },
          ttl: TTL,
          rate_limit_per_30s: 600,
          now: () => new Date(T0),
        }),
      ).toThrow(/пояс времени/);
    }
  });
});
