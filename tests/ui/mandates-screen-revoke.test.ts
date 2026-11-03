// Экран мандатов: отзыв мандата и отзыв всех полномочий клиента с шагом подтверждения (UI-К2 ч. 1, К1.3; ФП9 → ПС16
// через экран банка; РП38, РП45 п. 4, РП46 (а); инварианты 7, 8). Модуль — с подставным портом (шаг подтверждения,
// CSRF, confirm=yes, revocation_ref и повтор тем же после сбоя); стенд — сквозной путь: подпись → отзыв на экране → ПИ-8 →
// REVOKED и mandate.revoked у агента; revoke-all → все ACTIVE клиента отозваны, чужие не тронуты. Правка по /audit К1.2:
// отказ на экране уходит в ПИ-8 с token_consent: false, подпись — с true (РП12).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { issuerScreenPort } from "../../src/env/issuer/screen.js";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort, RevokeResult, ScreenMandate } from "../../src/ui/mandates/port.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = Date.parse("2026-11-02T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_revoker";
const ID = (n: number) => `mnd_0000000${n}-0000-4000-8000-000000000000`;
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const REF = /name="ref" value="(rva_[a-z]{24})"/;

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
  subject: "продукты",
  cart: null,
  hash: "ab".repeat(32),
  ...over,
});

const cookieOf = (setCookie: unknown): string => String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0]!;
const csrfOf = (html: string): string => /name="csrf" value="([^"]+)"/.exec(html)![1]!;

interface FakeOpts {
  readonly revoke?: RevokeResult | "fail";
  /** Ответы revokeAll по очереди: число — успех, "fail" — сбой. */
  readonly revokeAll?: (number | "fail")[];
}

async function open(list: ScreenMandate[], opts: FakeOpts = {}) {
  const writes: { op: string; principal: string; arg: string }[] = [];
  const answers = [...(opts.revokeAll ?? [1])];
  const port: MandatesScreenPort = {
    mandates: async () => list,
    mandate: async (_p, id) => list.find((m) => m.id === id),
    decide: async () => ({ kind: "NOT_FOUND" }),
    async revoke(principal, id) {
      writes.push({ op: "revoke", principal, arg: id });
      if (opts.revoke === "fail") throw new Error("ПИ-8 недоступна");
      return opts.revoke ?? { kind: "DONE", status: "REVOKED" };
    },
    async revokeAll(principal, ref) {
      writes.push({ op: "revokeAll", principal, arg: ref });
      const a = answers.shift() ?? 0;
      if (a === "fail") throw new Error("ПИ-8: сбой посередине");
      return { revoked: a };
    },
    confirmations: async () => [],
    confirmation: async () => undefined,
    confirm: async () => ({ kind: "NOT_FOUND" }),
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = cookieOf(login.headers["set-cookie"]);
  const get = (url: string) => screen.app.inject({ method: "GET", url, headers: { cookie } });
  const post = (url: string, body: string) => screen.app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
  const csrf = encodeURIComponent(csrfOf((await get("/")).body));
  return { writes, get, post, csrf };
}

describe("экран мандатов: отзыв мандата с шагом подтверждения (модуль)", () => {
  it("ссылка «Отозвать» — только у действующего; «Отозвать все» — только когда есть действующий", async () => {
    const s = await open([mandate(1), mandate(2, { status: "PENDING_SIGNATURE" }), mandate(3, { status: "REVOKED" })]);
    expect((await s.get(`/m/${ID(1)}`)).body).toContain(`href="/m/${ID(1)}/revoke?lang=ru" data-revoke`);
    expect((await s.get(`/m/${ID(2)}`)).body).not.toContain("data-revoke");
    expect((await s.get(`/m/${ID(3)}`)).body).not.toContain("data-revoke");
    expect((await s.get("/")).body).toContain("data-revoke-all");
    const none = await open([mandate(2, { status: "PENDING_SIGNATURE" }), mandate(3, { status: "EXPIRED" })]);
    expect((await none.get("/")).body).not.toContain("data-revoke-all");
  });

  it("шаг 1 — страница подтверждения без записи; не действующий — 409 со статусом; чужой и не по форме — 404", async () => {
    const s = await open([mandate(1), mandate(2, { status: "EXPIRED" })]);
    const ask = await s.get(`/m/${ID(1)}/revoke?lang=en`);
    expect(ask.statusCode).toBe(200);
    expect(ask.body).toContain("Purchases already approved before revocation will be completed.");
    expect(ask.body).toContain('name="confirm" value="yes"');
    expect(ask.body).toContain(`action="/m/${ID(1)}/revoke"`);
    expect(ask.body).toContain(`href="/m/${ID(1)}?lang=en" data-cancel`);
    const expired = await s.get(`/m/${ID(2)}/revoke`);
    expect(expired.statusCode).toBe(409);
    expect(expired.body).toContain("<span data-status>Истёк</span>");
    expect((await s.get(`/m/${ID(9)}/revoke`)).statusCode).toBe(404);
    expect((await s.get("/m/bad/revoke")).statusCode).toBe(404);
    expect(s.writes).toEqual([]);
  });

  it("шаг 2 — без CSRF 403, без confirm=yes 400, id не по форме 404: в порт не уходит", async () => {
    const s = await open([mandate(1)]);
    expect((await s.post(`/m/${ID(1)}/revoke`, "confirm=yes")).statusCode).toBe(403);
    expect((await s.post(`/m/${ID(1)}/revoke`, `csrf=${s.csrf}`)).statusCode).toBe(400);
    expect((await s.post(`/m/${ID(1)}/revoke`, `confirm=no&csrf=${s.csrf}`)).statusCode).toBe(400);
    expect((await s.post("/m/bad/revoke", `confirm=yes&csrf=${s.csrf}`)).statusCode).toBe(404);
    expect(s.writes).toEqual([]);
  });

  it("шаг 2 — отозван: 200; полномочий уже не было: 409 «уже не действует» со статусом; неизвестный — 404; сбой — 503", async () => {
    const ok = await open([mandate(1)]);
    const done = await ok.post(`/m/${ID(1)}/revoke`, `confirm=yes&csrf=${ok.csrf}`);
    expect(done.statusCode).toBe(200);
    expect(done.body).toContain("Мандат отозван.");
    expect(ok.writes).toEqual([{ op: "revoke", principal: P, arg: ID(1) }]);
    const late = await open([mandate(1)], { revoke: { kind: "DONE", status: "EXPIRED" } });
    const r = await late.post(`/m/${ID(1)}/revoke`, `confirm=yes&csrf=${late.csrf}`);
    expect(r.statusCode).toBe(409);
    expect(r.body).toContain("Мандат уже не действует.");
    expect(r.body).toContain("<span data-status>Истёк</span>");
    const gone = await open([mandate(1)], { revoke: { kind: "NOT_FOUND" } });
    expect((await gone.post(`/m/${ID(1)}/revoke`, `confirm=yes&csrf=${gone.csrf}`)).statusCode).toBe(404);
    const failed = await open([mandate(1)], { revoke: "fail" });
    const f = await failed.post(`/m/${ID(1)}/revoke`, `confirm=yes&csrf=${failed.csrf}`);
    expect(f.statusCode).toBe(503);
    expect(f.body).not.toContain("Мандат отозван");
  });
});

describe("экран мандатов: отзыв всех полномочий (модуль)", () => {
  it("шаг 1 — подтверждение с revocation_ref rva_ + 24 буквы, новый на каждую страницу; без записи", async () => {
    const s = await open([mandate(1)]);
    const a = await s.get("/revoke-all");
    const b = await s.get("/revoke-all");
    expect(a.statusCode).toBe(200);
    expect(a.body).toContain("Отозвать все действующие мандаты всех агентов?");
    const ra = REF.exec(a.body)![1]!;
    const rb = REF.exec(b.body)![1]!;
    expect(ra).not.toBe(rb);
    expect(ra).not.toMatch(/\d/);
    expect(s.writes).toEqual([]);
  });

  it("шаг 2 — без CSRF 403, без confirm 400, ref не по форме 400: в порт не уходит", async () => {
    const s = await open([mandate(1)]);
    const ref = REF.exec((await s.get("/revoke-all")).body)![1]!;
    expect((await s.post("/revoke-all", `confirm=yes&ref=${ref}`)).statusCode).toBe(403);
    expect((await s.post("/revoke-all", `ref=${ref}&csrf=${s.csrf}`)).statusCode).toBe(400);
    for (const bad of ["", "rva_short", "rva_1234567890123456789012345", `${ref}x`, "abc_abcdefghijklmnopqrstuvwx"]) {
      expect((await s.post("/revoke-all", `confirm=yes&ref=${bad}&csrf=${s.csrf}`)).statusCode).toBe(400);
    }
    expect(s.writes).toEqual([]);
  });

  it("шаг 2 — успех: число отозванных; сбой — 503 и форма с тем же ref, повтор тем же ref — 200", async () => {
    const s = await open([mandate(1)], { revokeAll: ["fail", 2] });
    const ref = REF.exec((await s.get("/revoke-all")).body)![1]!;
    const failed = await s.post("/revoke-all", `confirm=yes&ref=${ref}&csrf=${s.csrf}`);
    expect(failed.statusCode).toBe(503);
    expect(failed.body).toContain("повтор безопасен");
    expect(REF.exec(failed.body)![1]).toBe(ref);
    const again = await s.post("/revoke-all", `confirm=yes&ref=${ref}&csrf=${s.csrf}`);
    expect(again.statusCode).toBe(200);
    expect(again.body).toContain("Все полномочия отозваны. Отозвано мандатов: 2");
    expect(s.writes).toEqual([
      { op: "revokeAll", principal: P, arg: ref },
      { op: "revokeAll", principal: P, arg: ref },
    ]);
  });
});

describe("адаптер стенда: согласие на токен — только с подписью (правка по /audit К1.2; РП12)", () => {
  it("SIGN — token_consent: true, REJECT — token_consent: false", async () => {
    const sent: { id: string; decision: string; token_consent: boolean }[] = [];
    const port = issuerScreenPort({
      now: () => new Date(T0),
      mandateIds: () => [ID(1)],
      signingView: async (id) => ({
        id,
        hash: "ab".repeat(32),
        status: "PENDING_SIGNATURE",
        agent_code: "a",
        type: "INTENT",
        parent_id: null,
        merchant_scope: [],
        principal_ref: P,
        amount_limit: 1,
        currency: "RUB",
        valid_to: "2026-11-09T10:00:00.000Z",
        subject: "s",
        cart: null,
      }),
      sign: async (id, o) => {
        sent.push({ id, ...o });
        return { statusCode: 200, body: { status: o.decision === "SIGN" ? "ACTIVE" : "REJECTED" } };
      },
      revoke: async () => ({ statusCode: 500, body: {} }),
      revokeAll: async () => ({ statusCode: 500, body: {} }),
      confirmationIds: () => [],
      confirmationRecord: async () => undefined,
      confirm: async () => ({ statusCode: 500, body: {} }),
    });
    await port.decide(P, ID(1), "SIGN");
    await port.decide(P, ID(1), "REJECT");
    expect(sent).toEqual([
      { id: ID(1), decision: "SIGN", token_consent: true },
      { id: ID(1), decision: "REJECT", token_consent: false },
    ]);
  });
});

describe("ПС16 и revoke-all через экран банка на стенде (ФП9; РП38, РП45 п. 4; инвариант 8)", () => {
  const code = "nspk:agent:screen-ps16:v1";
  const OTHER = "cl_screen_bystander";
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
  const events = async () =>
    ((await signedInject(stand.app, side, code, { method: "GET", path: "/pao/v1/events" })).json() as { type: string; data: unknown }[]).map((e) => [
      e.type,
      e.data,
    ]);
  const enter = async (principal: string) => {
    const app = stand.bankApp.app;
    const login = await app.inject({ method: "GET", url: stand.bankApp.session(principal) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    const get = (url: string) => app.inject({ method: "GET", url, headers: { cookie } });
    const post = (url: string, body: string) => app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
    const csrf = encodeURIComponent(csrfOf((await get("/")).body));
    return { get, post, csrf };
  };

  it("ПС16: подпись на экране → отзыв на экране с подтверждением → REVOKED и mandate.revoked у агента", async () => {
    const id = await create(intent());
    const me = await enter(P);
    expect((await me.post(`/m/${id}/decision`, `decision=SIGN&csrf=${me.csrf}`)).statusCode).toBe(200);
    expect(await status(id)).toBe("ACTIVE");
    const ask = await me.get(`/m/${id}/revoke`);
    expect(ask.statusCode).toBe(200);
    expect(await status(id)).toBe("ACTIVE");
    const res = await me.post(`/m/${id}/revoke`, `confirm=yes&csrf=${me.csrf}`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Мандат отозван.");
    expect(await status(id)).toBe("REVOKED");
    expect(await events()).toContainEqual(["mandate.revoked", { mandate_id: id }]);
    // Повтор (двойное нажатие): ПИ-8 — 200 с текущим REVOKED без записи (РП38); экран — «отозван», второго события нет.
    const again = await me.post(`/m/${id}/revoke`, `confirm=yes&csrf=${me.csrf}`);
    expect(again.statusCode).toBe(200);
    expect(again.body).toContain("<span data-status>Отозван</span>");
    expect((await events()).filter(([t, d]) => t === "mandate.revoked" && (d as { mandate_id: string }).mandate_id === id)).toHaveLength(1);
  });

  it("чужой действующий мандат: страница отзыва и запись — 404, мандат остаётся ACTIVE", async () => {
    const theirs = await create(intent({ principal_ref: OTHER, subject: "чужое поручение" }));
    expect((await stand.issuer.sign(theirs)).statusCode).toBe(200);
    const me = await enter(P);
    expect((await me.get(`/m/${theirs}/revoke`)).statusCode).toBe(404);
    expect((await me.post(`/m/${theirs}/revoke`, `confirm=yes&csrf=${me.csrf}`)).statusCode).toBe(404);
    expect(await status(theirs)).toBe("ACTIVE");
  });

  it("отказ на экране уходит в ПИ-8 с token_consent: false (выписка агента — запись банка)", async () => {
    const id = await create(intent());
    const me = await enter(P);
    expect((await me.post(`/m/${id}/decision`, `decision=REJECT&csrf=${me.csrf}`)).statusCode).toBe(200);
    const ev = await signedInject(stand.app, side, code, { method: "GET", path: `/pao/v1/mandates/${id}/evidence` });
    expect(ev.statusCode).toBe(200);
    expect(ev.body).toContain('"decision":"REJECT"');
    expect(ev.body).toContain('"token_consent":false');
    expect(ev.body).not.toContain('"token_consent":true');
  });

  it("revoke-all на экране: все ACTIVE клиента отозваны, ждущий подписи и чужие не тронуты; ответ — число", async () => {
    const a = await create(intent());
    const b = await create(intent({ subject: "бытовая химия" }));
    const pendingOne = await create(intent({ subject: "ещё не подписан" }));
    const theirs = await create(intent({ principal_ref: OTHER, subject: "чужое" }));
    const me = await enter(P);
    for (const id of [a, b]) expect((await me.post(`/m/${id}/decision`, `decision=SIGN&csrf=${me.csrf}`)).statusCode).toBe(200);
    expect((await stand.issuer.sign(theirs)).statusCode).toBe(200);
    const ask = await me.get("/revoke-all");
    const ref = REF.exec(ask.body)![1]!;
    const res = await me.post("/revoke-all", `confirm=yes&ref=${ref}&csrf=${me.csrf}`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toMatch(/Отозвано мандатов: \d+/);
    expect(await status(a)).toBe("REVOKED");
    expect(await status(b)).toBe("REVOKED");
    expect(await status(pendingOne)).toBe("PENDING_SIGNATURE");
    expect(await status(theirs)).toBe("ACTIVE");
    const evs = await events();
    for (const id of [a, b]) expect(evs).toContainEqual(["mandate.revoked", { mandate_id: id }]);
    // Повтор тем же ref — 200 без новых отзывов (ПИ-8 идемпотентна по revocation_ref).
    expect((await me.post("/revoke-all", `confirm=yes&ref=${ref}&csrf=${me.csrf}`)).statusCode).toBe(200);
    expect(await status(theirs)).toBe("ACTIVE");
  });
});
