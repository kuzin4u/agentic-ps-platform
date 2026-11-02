// Экран мандатов: список, экран мандата, подпись и отказ (UI-К2 ч. 1, К1.2; ФП3 → ПС03 через экран банка; A7 п. 3.1–3.2,
// п. 9.2; инварианты 1, 3, 5, 6, 7). Модуль — с подставным портом (порядок проверок, fail-closed, тексты); стенд — сквозной
// путь: агент запрашивает мандат по ПАО → клиент входит по ссылке банка → видит свои мандаты → подписывает → ПИ-8 →
// ACTIVE и mandate.signed у агента; чужой мандат — 404 как неизвестный; выше порога — QUALIFIED_SIGNATURE_REQUIRED.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { DecideResult, MandatesScreenPort, ScreenMandate } from "../../src/ui/mandates/port.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = Date.parse("2026-11-02T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_owner";
const HASH = "ab".repeat(32);
const ID = (n: number) => `mnd_0000000${n}-0000-4000-8000-000000000000`;
const FORM = { "content-type": "application/x-www-form-urlencoded" };
/** Номер карты — 13–19 цифр подряд (инвариант 1); контрольная сумма из букв и цифр в проверку не входит. */
const PAN = /\d{13,19}/;

const mandate = (n: number, over: Partial<ScreenMandate> = {}): ScreenMandate => ({
  id: ID(n),
  agent_code: "nspk:agent:screen:v1",
  type: "INTENT",
  parent_id: null,
  status: "ACTIVE",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-11-09T10:00:00.000Z",
  merchant_scope: ["MER-1042"],
  subject: "молоко <2 л>",
  cart: null,
  hash: HASH,
  ...over,
});

const cookieOf = (setCookie: unknown): string => String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0]!;
const csrfOf = (html: string): string => /name="csrf" value="([^"]+)"/.exec(html)![1]!;

function fake(list: ScreenMandate[], opts: { fail?: boolean; decide?: DecideResult } = {}) {
  const calls: { op: string; principal: string; id?: string; decision?: string }[] = [];
  const port: MandatesScreenPort = {
    async mandates(principal) {
      calls.push({ op: "mandates", principal });
      if (opts.fail) throw new Error("порт недоступен");
      return list;
    },
    async mandate(principal, id) {
      calls.push({ op: "mandate", principal, id });
      if (opts.fail) throw new Error("порт недоступен");
      return list.find((m) => m.id === id);
    },
    async decide(principal, id, decision) {
      calls.push({ op: "decide", principal, id, decision });
      if (opts.fail) throw new Error("порт недоступен");
      return opts.decide ?? { kind: "DONE", status: decision === "SIGN" ? "ACTIVE" : "REJECTED" };
    },
    async revoke(principal, id) {
      calls.push({ op: "revoke", principal, id });
      if (opts.fail) throw new Error("порт недоступен");
      return { kind: "DONE", status: "REVOKED" };
    },
    async revokeAll(principal, ref) {
      calls.push({ op: "revokeAll", principal, id: ref });
      if (opts.fail) throw new Error("порт недоступен");
      return { revoked: 0 };
    },
  };
  return { port, calls };
}

async function open(list: ScreenMandate[], opts: Parameters<typeof fake>[1] = {}) {
  const { port, calls } = fake(list, opts);
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  const res = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = cookieOf(res.headers["set-cookie"]);
  const get = (url: string) => screen.app.inject({ method: "GET", url, headers: { cookie } });
  const post = (url: string, body: string) => screen.app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
  return { app: screen.app, calls, get, post };
}

describe("экран мандатов: список и экран мандата (модуль)", () => {
  it("список — мандаты клиента из порта по principal_ref сессии, ждущие подписи первыми; статусы — словарём ru / en", async () => {
    const s = await open([mandate(1), mandate(2, { status: "PENDING_SIGNATURE" }), mandate(3, { status: "REVOKED", type: "CART" })]);
    const ru = await s.get("/");
    expect(ru.statusCode).toBe(200);
    expect(s.calls[0]).toEqual({ op: "mandates", principal: P });
    const order = [...ru.body.matchAll(/data-mandate="([^"]+)"/g)].map((m) => m[1]);
    expect(order).toEqual([ID(2), ID(1), ID(3)]);
    expect(ru.body).toContain("Ждёт подписи");
    expect(ru.body).toContain("Действует");
    expect(ru.body).toContain("Корзина · nspk:agent:screen:v1");
    expect(ru.body).toContain("data-logout");
    const en = await s.get("/?lang=en");
    expect(en.body).toContain("Awaiting signature");
    expect(en.body).toContain("Revoked");
    expect(en.body).not.toMatch(PAN);
  });

  it("пустой список — «Мандатов нет»; сбой порта — 503 без списка", async () => {
    expect((await (await open([])).get("/")).body).toContain("data-empty");
    const failed = await (await open([mandate(1)], { fail: true })).get("/");
    expect(failed.statusCode).toBe(503);
    expect(failed.body).not.toContain("data-mandate");
  });

  it("экран мандата: значения записи, предмет экранирован, корзина и итог, контрольная сумма; кнопки — только у ждущего подписи", async () => {
    const cart = mandate(4, {
      type: "CART",
      parent_id: ID(1),
      status: "PENDING_SIGNATURE",
      amount_limit: 12_900,
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }, { sku: "bread" }], total: 12_900 },
    });
    const s = await open([mandate(1), cart]);
    const res = await s.get(`/m/${ID(4)}`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("<dd data-subject>молоко &lt;2 л&gt;</dd>");
    expect(res.body).toContain(`<dd data-parent>${ID(1)}</dd>`);
    expect(res.body).toContain("<dd data-merchants>MER-1042</dd>");
    expect(res.body).toMatch(/<dd data-limit>129,00\s₽<\/dd>/);
    expect(res.body).toContain("milk-2l × 1");
    expect(res.body).toContain("bread × — — —");
    expect(res.body).toContain(`<code data-hash>${HASH}</code>`);
    expect(res.body).toContain("data-sign");
    expect(res.body).toContain("data-reject");
    expect(res.body).toContain(`action="/m/${ID(4)}/decision"`);
    expect(res.body.replace(HASH, "")).not.toMatch(PAN);
    const active = await s.get(`/m/${ID(1)}`);
    expect(active.statusCode).toBe(200);
    expect(active.body).not.toContain("data-sign");
  });

  it("неизвестный статус — показан как есть, без кнопок; истёкший по часам экрана — без кнопок (fail-closed)", async () => {
    const s = await open([
      mandate(1, { status: "SOMETHING_NEW" }),
      mandate(2, { status: "PENDING_SIGNATURE", valid_to: new Date(T0).toISOString() }),
    ]);
    const odd = await s.get(`/m/${ID(1)}`);
    expect(odd.body).toContain("<dd data-status>SOMETHING_NEW</dd>");
    expect(odd.body).not.toContain("data-sign");
    expect((await s.get(`/m/${ID(2)}`)).body).not.toContain("data-sign");
  });

  it("неизвестный и чужой мандат — 404 одинаково; id не по форме — 404 без обращения к порту; сбой порта — 503 без кнопок", async () => {
    const s = await open([mandate(1)]);
    expect((await s.get(`/m/${ID(9)}`)).statusCode).toBe(404);
    const before = s.calls.length;
    expect((await s.get("/m/not-a-mandate")).statusCode).toBe(404);
    expect(s.calls.length).toBe(before);
    const failed = await (await open([mandate(1, { status: "PENDING_SIGNATURE" })], { fail: true })).get(`/m/${ID(1)}`);
    expect(failed.statusCode).toBe(503);
    expect(failed.body).not.toContain("data-sign");
  });

  it("неизвестная валюта — 503, а не страница с суммой", async () => {
    const s = await open([mandate(1, { currency: "XYZ1" })]);
    expect((await s.get(`/m/${ID(1)}`)).statusCode).toBe(503);
    expect((await s.get("/")).statusCode).toBe(503);
  });

  it("без сессии — 401 на списке, мандате и решении; порт не вызывается", async () => {
    const { port, calls } = fake([mandate(1, { status: "PENDING_SIGNATURE" })]);
    const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
    expect((await screen.app.inject({ method: "GET", url: "/" })).statusCode).toBe(401);
    expect((await screen.app.inject({ method: "GET", url: `/m/${ID(1)}` })).statusCode).toBe(401);
    expect((await screen.app.inject({ method: "POST", url: `/m/${ID(1)}/decision`, headers: FORM, payload: "decision=SIGN" })).statusCode).toBe(401);
    expect(calls).toEqual([]);
  });
});

describe("экран мандатов: решение клиента (модуль)", () => {
  const pendingList = () => [mandate(1, { status: "PENDING_SIGNATURE" })];

  it("без CSRF и с чужим — 403, решение не уходит в порт; неверное решение — 400", async () => {
    const s = await open(pendingList());
    const csrf = csrfOf((await s.get(`/m/${ID(1)}`)).body);
    expect((await s.post(`/m/${ID(1)}/decision`, "decision=SIGN")).statusCode).toBe(403);
    expect((await s.post(`/m/${ID(1)}/decision`, `decision=SIGN&csrf=${"C".repeat(43)}`)).statusCode).toBe(403);
    expect((await s.post(`/m/${ID(1)}/decision`, `decision=APPROVE&csrf=${encodeURIComponent(csrf)}`)).statusCode).toBe(400);
    expect((await s.post("/m/bad/decision", `decision=SIGN&csrf=${encodeURIComponent(csrf)}`)).statusCode).toBe(404);
    expect(s.calls.filter((c) => c.op === "decide")).toEqual([]);
  });

  it("подпись и отказ — в порт с principal_ref сессии; ответ — словарём", async () => {
    const s = await open(pendingList());
    const csrf = encodeURIComponent(csrfOf((await s.get(`/m/${ID(1)}`)).body));
    const signed = await s.post(`/m/${ID(1)}/decision`, `decision=SIGN&csrf=${csrf}`);
    expect(signed.statusCode).toBe(200);
    expect(signed.body).toContain("Мандат подписан");
    expect(signed.body).toContain("<span data-status>Действует</span>");
    const rejected = await s.post(`/m/${ID(1)}/decision`, `decision=REJECT&lang=en&csrf=${csrf}`);
    expect(rejected.body).toContain("Mandate declined.");
    expect(s.calls.filter((c) => c.op === "decide")).toEqual([
      { op: "decide", principal: P, id: ID(1), decision: "SIGN" },
      { op: "decide", principal: P, id: ID(1), decision: "REJECT" },
    ]);
  });

  it("выше порога — 422 «нужна усиленная подпись»; уже не ждёт — 409 со статусом; неизвестный — 404; сбой — 503", async () => {
    const cases: [DecideResult, number, string][] = [
      [{ kind: "QUALIFIED_SIGNATURE_REQUIRED" }, 422, "нужна усиленная подпись"],
      [{ kind: "NOT_PENDING", status: "REVOKED" }, 409, "Отозван"],
      [{ kind: "NOT_FOUND" }, 404, "Мандат не найден"],
    ];
    for (const [decide, code, text] of cases) {
      const s = await open(pendingList(), { decide });
      const csrf = encodeURIComponent(csrfOf((await s.get(`/m/${ID(1)}`)).body));
      const res = await s.post(`/m/${ID(1)}/decision`, `decision=SIGN&csrf=${csrf}`);
      expect(res.statusCode).toBe(code);
      expect(res.body).toContain(text);
    }
    // Сбой порта при решении (ПИ-8 недоступна, ответ банку неожиданный) — 503, а не «подписан».
    const { port } = fake(pendingList());
    const screen = createMandatesScreen({
      port: { ...port, decide: async () => Promise.reject(new Error("ПИ-8 недоступна")) },
      ttl: TTL, rate_limit_per_30s: 600,
      now: () => new Date(T0),
    });
    const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    const csrf = encodeURIComponent(csrfOf((await screen.app.inject({ method: "GET", url: `/m/${ID(1)}`, headers: { cookie } })).body));
    const res = await screen.app.inject({ method: "POST", url: `/m/${ID(1)}/decision`, headers: { cookie, ...FORM }, payload: `decision=SIGN&csrf=${csrf}` });
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain("Мандат подписан");
  });
});

describe("ПС03 через экран банка на стенде (ФП3; A7 п. 3.1–3.2)", () => {
  const code = "nspk:agent:screen-ps03:v1";
  const OTHER = "cl_screen_other";
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
  const status = async (id: string) =>
    ((await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${id}` })).json() as { status: string }).status;
  const enter = async (principal: string) => {
    const app = stand.bankApp.app;
    const login = await app.inject({ method: "GET", url: stand.bankApp.session(principal) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    const get = (url: string) => app.inject({ method: "GET", url, headers: { cookie } });
    const decide = async (id: string, decision: string) => {
      const csrf = encodeURIComponent(csrfOf((await get("/")).body));
      return app.inject({ method: "POST", url: `/m/${id}/decision`, headers: { cookie, ...FORM }, payload: `decision=${decision}&csrf=${csrf}` });
    };
    return { get, decide };
  };

  it("клиент видит только свои мандаты; подпись на экране → ПИ-8 → ACTIVE и mandate.signed у агента", async () => {
    const mine = await create(intent());
    const theirs = await create(intent({ principal_ref: OTHER, subject: "чужое поручение" }));
    const me = await enter(P);
    const list = await me.get("/");
    expect(list.body).toContain(`data-mandate="${mine}"`);
    expect(list.body).not.toContain(theirs);
    const page = await me.get(`/m/${mine}`);
    expect(page.body).toContain("<dd data-subject>продукты на неделю</dd>");
    expect(page.body).toContain("data-sign");
    expect(page.body.replace(/<code data-hash>[0-9a-f]+<\/code>/, "")).not.toMatch(PAN);
    const res = await me.decide(mine, "SIGN");
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Мандат подписан");
    expect(await status(mine)).toBe("ACTIVE");
    const events = (await signedInject(stand.app, side, code, { method: "GET", path: "/pao/v1/events" })).json() as { type: string; data: unknown }[];
    expect(events.map((e) => [e.type, e.data])).toContainEqual(["mandate.signed", { mandate_id: mine }]);
    // Уже подписан: кнопок нет; другое решение — 409 со статусом, второй записи нет.
    expect((await me.get(`/m/${mine}`)).body).not.toContain("data-sign");
    const again = await me.decide(mine, "REJECT");
    expect(again.statusCode).toBe(409);
    expect(again.body).toContain("Действует");
    expect(await status(mine)).toBe("ACTIVE");
  });

  it("чужой мандат — 404 на экране и на решении, статус не меняется", async () => {
    const theirs = await create(intent({ principal_ref: OTHER }));
    const me = await enter(P);
    expect((await me.get(`/m/${theirs}`)).statusCode).toBe(404);
    expect((await me.decide(theirs, "SIGN")).statusCode).toBe(404);
    expect(await status(theirs)).toBe("PENDING_SIGNATURE");
  });

  it("отказ на экране → REJECTED", async () => {
    const id = await create(intent());
    const me = await enter(P);
    const res = await me.decide(id, "REJECT");
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Мандат отклонён");
    expect(await status(id)).toBe("REJECTED");
  });

  it("выше порога простой подписи (A7 п. 3.2) — 422 на экране, мандат ждёт подписи", async () => {
    const id = await create(intent({ amount_limit: stand.params.qualified_signature_above_kop + 1 }));
    const me = await enter(P);
    const res = await me.decide(id, "SIGN");
    expect(res.statusCode).toBe(422);
    expect(res.body).toContain("нужна усиленная подпись");
    expect(await status(id)).toBe("PENDING_SIGNATURE");
  });
});
