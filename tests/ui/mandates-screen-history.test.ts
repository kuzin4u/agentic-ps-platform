// Экран мандатов: история мандата, уведомления клиента и место для споров (UI-К2 ч. 3, К3.2; РП36 «Нюанс UI-К2 ч. 3»;
// РП46 (б), A3 п. 5.3; инварианты 1, 3, 5, 6). Модуль — с подставным портом: записи журнала и уведомления — кодами из
// словаря, неизвестный код — как есть; чужой мандат и id не по форме — 404 (второе — без обращения к порту); сбой — 503;
// споров — только надпись, без действий. Адаптер стенда: нарушенная цепочка журнала — сбой, не история. Стенд — сквозной
// путь: подпись и отзыв на экране → история REQUESTED → SIGNED → REVOKED; revoke-all → client.revoked_all только у своего
// клиента (лента ПИ-8 банка, отбор по principal_ref).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { issuerScreenPort, type IssuerScreenDeps } from "../../src/env/issuer/screen.js";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort, ScreenHistoryEntry, ScreenMandate, ScreenNotification } from "../../src/ui/mandates/port.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = Date.parse("2026-11-03T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_history";
const ID = (n: number) => `mnd_0000000${n}-0000-4000-8000-000000000000`;
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const REF = /name="ref" value="(rva_[a-z]{24})"/;

const cookieOf = (setCookie: unknown): string => String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0]!;
const csrfOf = (html: string): string => /name="csrf" value="([^"]+)"/.exec(html)![1]!;
const entriesOf = (html: string) => [...html.matchAll(/data-entry="([A-Z_]+)"/g)].map((m) => m[1]);
const noticesOf = (html: string) => [...html.matchAll(/data-notification="([a-z_.]+)"/g)].map((m) => m[1]);

const mandate = (n: number): ScreenMandate => ({
  id: ID(n),
  agent_code: "nspk:agent:screen:v1",
  type: "INTENT",
  parent_id: null,
  status: "ACTIVE",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-11-09T10:00:00.000Z",
  merchant_scope: ["MER-1042"],
  subject: "продукты",
  cart: null,
  hash: "ab".repeat(32),
});

async function open(history: Record<string, ScreenHistoryEntry[] | "fail">, notices: ScreenNotification[] | "fail" = []) {
  const calls: string[] = [];
  const list = [mandate(1)];
  const port: MandatesScreenPort = {
    mandates: async () => list,
    mandate: async (_p, id) => list.find((m) => m.id === id),
    decide: async () => ({ kind: "NOT_FOUND" }),
    revoke: async () => ({ kind: "NOT_FOUND" }),
    revokeAll: async () => ({ revoked: 0 }),
    confirmations: async () => [],
    confirmation: async () => undefined,
    confirm: async () => ({ kind: "NOT_FOUND" }),
    agent: async () => undefined,
    async history(principal, id) {
      calls.push(`history:${principal}:${id}`);
      const h = history[id];
      if (h === "fail") throw new Error("журнал недоступен");
      return h;
    },
    async notifications(principal) {
      calls.push(`notifications:${principal}`);
      if (notices === "fail") throw new Error("ПИ-8 недоступна");
      return notices;
    },
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = cookieOf(login.headers["set-cookie"]);
  const get = (url: string, withCookie = true) => screen.app.inject({ method: "GET", url, headers: withCookie ? { cookie } : {} });
  return { get, calls, close: () => screen.app.close() };
}

describe("История мандата на экране (модуль)", () => {
  const H: ScreenHistoryEntry[] = [
    { at: "2026-11-03T09:00:00.000Z", kind: "MANDATE_REQUESTED", mandate_id: ID(1), amount_limit: 50_000, currency: "RUB" },
    { at: "2026-11-03T09:01:00.000Z", kind: "MANDATE_SIGNED", mandate_id: ID(1) },
    { at: "2026-11-03T09:02:00.000Z", kind: "MANDATE_НОВЫЙ", mandate_id: ID(1) },
    { at: "2026-11-03T09:03:00.000Z", kind: "MANDATE_REVOKED", mandate_id: ID(2) },
  ];

  it("записи по порядку, тексты из словаря, неизвестная — кодом; предел — парой с валютой; запись родителя помечена", async () => {
    const s = await open({ [ID(1)]: H });
    const r = await s.get(`/m/${ID(1)}/history`);
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain("<ol data-history>");
    expect(r.body).toContain("Агент запросил мандат");
    expect(r.body).toContain("Мандат подписан");
    expect(r.body).toContain("MANDATE_НОВЫЙ");
    expect(r.body).toMatch(/500,00\s₽/);
    expect(r.body).toContain(`по мандату ${ID(2)}`);
    expect(r.body.indexOf("Агент запросил мандат")).toBeLessThan(r.body.indexOf("Мандат подписан"));
    const en = await s.get(`/m/${ID(1)}/history?lang=en`);
    expect(en.body).toContain("Mandate signed");
    expect(s.calls).toEqual([`history:${P}:${ID(1)}`, `history:${P}:${ID(1)}`]);
    await s.close();
  });

  it("чужой или неизвестный — 404; id не по форме — 404 без обращения к порту; сбой — 503; без сессии — 401", async () => {
    const s = await open({ [ID(2)]: "fail" });
    expect((await s.get(`/m/${ID(1)}/history`)).statusCode).toBe(404);
    expect((await s.get("/m/not-a-mandate/history")).statusCode).toBe(404);
    const down = await s.get(`/m/${ID(2)}/history`);
    expect(down.statusCode).toBe(503);
    expect(down.body).not.toContain("data-history");
    expect((await s.get(`/m/${ID(1)}/history`, false)).statusCode).toBe(401);
    expect(s.calls).toEqual([`history:${P}:${ID(1)}`, `history:${P}:${ID(2)}`]);
    await s.close();
  });

  it("страница мандата: ссылка на историю и место для споров — только надпись, без формы и без обращений к порту", async () => {
    const s = await open({});
    const r = await s.get(`/m/${ID(1)}`);
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain(`href="/m/${ID(1)}/history?lang=ru" data-history-link`);
    const disputes = /<section data-disputes>([\s\S]*?)<\/section>/.exec(r.body)?.[1] ?? "";
    expect(disputes).toContain("Споры");
    expect(disputes).not.toMatch(/<form|<button|<a /);
    expect(s.calls).toEqual([]);
    await s.close();
  });
});

describe("Уведомления клиента на экране (модуль)", () => {
  it("тип и причина — из словаря, неизвестный — кодом; ссылка на мандат; пусто — «нет»; сбой — 503", async () => {
    const s = await open({}, [
      { at: "2026-11-03T09:00:00.000Z", type: "client.mandate_first_use", mandate_id: ID(1), agent_code: "nspk:agent:screen:v1" },
      { at: "2026-11-03T09:05:00.000Z", type: "client.limit_declined", mandate_id: ID(1), reason: "CLIENT" },
      { at: "2026-11-03T09:06:00.000Z", type: "client.new_kind" },
    ]);
    const r = await s.get("/notifications");
    expect(r.statusCode).toBe(200);
    expect(noticesOf(r.body)).toEqual(["client.mandate_first_use", "client.limit_declined", "client.new_kind"]);
    expect(r.body).toContain("Первая покупка по мандату");
    expect(r.body).toContain("Покупка отклонена: превышен предел (ваш лимит)");
    expect(r.body).toContain(`href="/m/${ID(1)}?lang=ru"`);
    expect((await s.get("/")).body).toContain('href="/notifications?lang=ru" data-notifications-link');
    await s.close();
    const empty = await open({}, []);
    expect((await empty.get("/notifications")).body).toContain("Уведомлений нет");
    await empty.close();
    const down = await open({}, "fail");
    expect((await down.get("/notifications")).statusCode).toBe(503);
    expect((await down.get("/notifications", false)).statusCode).toBe(401);
    await down.close();
  });
});

describe("Адаптер стенда: журнал и лента", () => {
  const view = { principal_ref: P, agent_code: "nspk:agent:screen:v1" } as Awaited<ReturnType<IssuerScreenDeps["signingView"]>>;
  const deps = (over: Partial<IssuerScreenDeps>): IssuerScreenDeps => ({
    now: () => new Date(T0),
    mandateIds: () => [],
    signingView: async (id) => (id === ID(1) ? view : undefined),
    sign: async () => ({ statusCode: 500, body: {} }),
    revoke: async () => ({ statusCode: 500, body: {} }),
    revokeAll: async () => ({ statusCode: 500, body: {} }),
    confirmationIds: () => [],
    confirmationRecord: async () => undefined,
    confirm: async () => ({ statusCode: 500, body: {} }),
    agent: async () => undefined,
    journal: async () => undefined,
    notificationsPage: async () => ({ statusCode: 200, body: { notifications: [] } }),
    ...over,
  });

  it("нарушенная цепочка журнала — сбой (503 на экране), не история; чужой — undefined без чтения журнала", async () => {
    const read: string[] = [];
    const p = issuerScreenPort(
      deps({ journal: async (id) => (read.push(id), { integrity: "BROKEN", records: [] }) }),
    );
    await expect(p.history(P, ID(1))).rejects.toThrow();
    expect(await p.history("cl_other", ID(1))).toBeUndefined();
    expect(read).toEqual([ID(1)]);
  });

  it("лента по страницам до пустой; только записи клиента; ответ не 200 — сбой", async () => {
    const n = (i: number, principal_ref: string) => ({ notification_id: `ntf_${i}`, type: "client.revoked_all", at: `2026-11-03T09:0${i}:00.000Z`, data: { principal_ref } });
    const pages: Record<string, unknown[]> = { "": [n(1, P), n(2, "cl_other")], ntf_2: [n(3, P)], ntf_3: [] };
    const asked: (string | undefined)[] = [];
    const p = issuerScreenPort(deps({ notificationsPage: async (after) => (asked.push(after), { statusCode: 200, body: { notifications: pages[after ?? ""] } }) }));
    expect((await p.notifications(P)).map((x) => x.at)).toEqual(["2026-11-03T09:01:00.000Z", "2026-11-03T09:03:00.000Z"]);
    expect(asked).toEqual([undefined, "ntf_2", "ntf_3"]);
    const bad = issuerScreenPort(deps({ notificationsPage: async () => ({ statusCode: 401, body: { code: "SIGNATURE_INVALID" } }) }));
    await expect(bad.notifications(P)).rejects.toThrow();
  });
});

describe("История и уведомления через экран банка на стенде (РП36, РП46 (б); инварианты 5, 6)", () => {
  const code = "nspk:agent:screen-history:v1";
  const OTHER = "cl_screen_history_other";
  let stand: Stand;
  let side: AgentSide;
  const valid_to = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const intent = (over: Partial<MandateRequest> = {}): MandateRequest => ({
    type: "INTENT",
    subject: "продукты на неделю",
    amount_limit: 50_000,
    currency: "RUB",
    valid_to,
    merchant_scope: ["MER-1042"],
    principal_ref: P,
    mode: "IMMEDIATE",
    ...over,
  });

  beforeAll(async () => {
    stand = createStand();
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const create = async (req: MandateRequest): Promise<string> => {
    const res = await signedInject(stand.app, side, code, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(req),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(res.statusCode).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const enter = async (principal: string) => {
    const app = stand.bankApp.app;
    const login = await app.inject({ method: "GET", url: stand.bankApp.session(principal) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    const get = (url: string) => app.inject({ method: "GET", url, headers: { cookie } });
    const post = (url: string, body: string) => app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
    const csrf = encodeURIComponent(csrfOf((await get("/")).body));
    return { get, post, csrf };
  };

  it("подпись и отзыв на экране → история REQUESTED → SIGNED → REVOKED с пределом; чужой клиент — 404", async () => {
    const id = await create(intent());
    const me = await enter(P);
    expect(entriesOf((await me.get(`/m/${id}/history`)).body)).toEqual(["MANDATE_REQUESTED"]);
    expect((await me.post(`/m/${id}/decision`, `decision=SIGN&csrf=${me.csrf}`)).statusCode).toBe(200);
    expect((await me.post(`/m/${id}/revoke`, `confirm=yes&csrf=${me.csrf}`)).statusCode).toBe(200);
    const h = await me.get(`/m/${id}/history`);
    expect(h.statusCode).toBe(200);
    expect(entriesOf(h.body)).toEqual(["MANDATE_REQUESTED", "MANDATE_SIGNED", "MANDATE_REVOKED"]);
    expect(h.body).toMatch(/500,00\s₽/);
    const other = await enter(OTHER);
    expect((await other.get(`/m/${id}/history`)).statusCode).toBe(404);
  });

  it("revoke-all: client.revoked_all — в уведомлениях своего клиента, у другого клиента — только его", async () => {
    const mine = await create(intent({ subject: "моё" }));
    const theirs = await create(intent({ principal_ref: OTHER, subject: "чужое" }));
    expect((await stand.issuer.sign(mine)).statusCode).toBe(200);
    expect((await stand.issuer.sign(theirs)).statusCode).toBe(200);
    const me = await enter(P);
    const ref = REF.exec((await me.get("/revoke-all")).body)![1]!;
    expect((await me.post("/revoke-all", `confirm=yes&ref=${ref}&csrf=${me.csrf}`)).statusCode).toBe(200);
    const mineNotices = await me.get("/notifications");
    expect(mineNotices.statusCode).toBe(200);
    expect(noticesOf(mineNotices.body)).toEqual(["client.revoked_all"]);
    expect(mineNotices.body).toContain("Все полномочия агентов отозваны");
    const other = await enter(OTHER);
    expect(noticesOf((await other.get("/notifications")).body)).toEqual([]);
    expect((await stand.issuer.revokeAll(OTHER, "rva_otherotherotherotherothe")).statusCode).toBe(200);
    expect(noticesOf((await other.get("/notifications")).body)).toEqual(["client.revoked_all"]);
    expect(noticesOf((await me.get("/notifications")).body)).toEqual(["client.revoked_all"]);
  });
});
