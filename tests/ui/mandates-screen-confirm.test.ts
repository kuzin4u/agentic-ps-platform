// Экран мандатов: подтверждение покупки в приложении банка (UI-К2 ч. 2, К2.1; ПС11 через экран банка; РП50 п. 4–5,
// РП51 п. 13; инварианты 1, 3, 5, 7). Модуль — с подставным портом: кнопки только у ждущего решения в сроке, CSRF, форма,
// в порт уходит totals_hash из формы (итог, который видел человек), сбой порта — 503 без кнопок. Стенд — сквозной путь:
// CONFIRMATION_REQUIRED → запрос на экране банка → «Подтвердить» → ПИ-8 от банка → confirmation.approved у агента →
// GET со ссылкой → повтор новой операцией → APPROVE; чужой клиент, изменившийся итог, отказ, истечение, двойное нажатие.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { totalsHash } from "../../src/confirm/model.js";
import { issuerScreenPort, type IssuerScreenDeps } from "../../src/env/issuer/screen.js";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { ConfirmResult, MandatesScreenPort, ScreenConfirmation } from "../../src/ui/mandates/port.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = Date.parse("2026-11-03T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_confirm";
const CID = (n: number) => `cnf_0000000${n}-0000-4000-8000-000000000000`;
const HASH = "ab".repeat(32);
const FORM = { "content-type": "application/x-www-form-urlencoded" };

const cookieOf = (setCookie: unknown): string => String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0]!;
const csrfOf = (html: string): string => /name="csrf" value="([^"]+)"/.exec(html)![1]!;
const hashOf = (html: string): string => /name="totals_hash" value="([0-9a-f]{64})"/.exec(html)![1]!;

const request = (n: number, over: Partial<ScreenConfirmation> = {}): ScreenConfirmation => ({
  id: CID(n),
  agent_code: "nspk:agent:screen:v1",
  mandate_id: "mnd_00000001-0000-4000-8000-000000000000",
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref: `ORD-${n}`,
  status: "PENDING",
  expires_at: "2026-11-03T10:15:00.000Z",
  totals_hash: HASH,
  ...over,
});

async function open(list: ScreenConfirmation[], opts: { fail?: boolean; confirm?: ConfirmResult } = {}) {
  const calls: { op: string; principal: string; id?: string; decision?: string; hash?: string }[] = [];
  const port: MandatesScreenPort = {
    mandates: async () => [],
    mandate: async () => undefined,
    decide: async () => ({ kind: "NOT_FOUND" }),
    revoke: async () => ({ kind: "NOT_FOUND" }),
    revokeAll: async () => ({ revoked: 0 }),
    async confirmations(principal) {
      calls.push({ op: "confirmations", principal });
      if (opts.fail) throw new Error("порт недоступен");
      return list;
    },
    async confirmation(principal, id) {
      calls.push({ op: "confirmation", principal, id });
      if (opts.fail) throw new Error("порт недоступен");
      return list.find((c) => c.id === id);
    },
    async confirm(principal, id, decision, hash) {
      calls.push({ op: "confirm", principal, id, decision, hash });
      if (opts.fail) throw new Error("порт недоступен");
      return opts.confirm ?? { kind: "DONE", status: decision === "APPROVE" ? "APPROVED" : "REJECTED" };
    },
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = cookieOf(login.headers["set-cookie"]);
  const get = (url: string) => screen.app.inject({ method: "GET", url, headers: { cookie } });
  const post = (url: string, body: string) => screen.app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
  const csrf = opts.fail ? "" : encodeURIComponent(csrfOf((await get("/")).body));
  return { calls, get, post, csrf };
}

describe("экран мандатов: подтверждение покупки (модуль)", () => {
  it("на главной — только ждущие решения в сроке, первыми; страница запроса — итог и кнопки с totals_hash", async () => {
    const s = await open([
      request(1),
      request(2, { status: "APPROVED" }),
      request(3, { expires_at: "2026-11-03T10:00:00.000Z" }),
      request(4, { status: "НЕИЗВЕСТНЫЙ" }),
    ]);
    const home = (await s.get("/")).body;
    expect(home).toContain(`data-confirmation="${CID(1)}"`);
    for (const n of [2, 3, 4]) expect(home).not.toContain(`data-confirmation="${CID(n)}"`);
    expect(home.indexOf("data-confirmations")).toBeLessThan(home.indexOf("data-empty"));
    expect(s.calls[0]).toEqual({ op: "confirmations", principal: P });

    const page = (await s.get(`/c/${CID(1)}`)).body;
    expect(page).toMatch(/data-amount>3\s?400,00\s?₽</);
    expect(page).toContain("data-order>ORD-1<");
    expect(page).toContain("data-merchant>MER-1042<");
    expect(page).toContain("data-approve");
    expect(page).toContain("data-decline");
    expect(hashOf(page)).toBe(HASH);
  });

  it("без кнопок: решённый, истёкший по часам экрана (статус — «срок истёк»), неизвестный статус", async () => {
    const s = await open([request(2, { status: "APPROVED" }), request(3, { expires_at: "2026-11-03T10:00:00.000Z" }), request(4, { status: "НЕИЗВЕСТНЫЙ" })]);
    for (const n of [2, 3, 4]) {
      const body = (await s.get(`/c/${CID(n)}`)).body;
      expect(body, `запрос ${n}`).not.toContain("data-approve");
      expect(body, `запрос ${n}`).not.toContain('name="totals_hash"');
    }
    expect((await s.get(`/c/${CID(3)}`)).body).toContain("data-status>Срок истёк<");
    expect((await s.get(`/c/${CID(4)}`)).body).toContain("data-status>НЕИЗВЕСТНЫЙ<");
  });

  it("неизвестный и не по форме id — 404 (не по форме — без обращения к порту)", async () => {
    const s = await open([request(1)]);
    expect((await s.get(`/c/${CID(9)}`)).statusCode).toBe(404);
    const before = s.calls.length;
    expect((await s.get("/c/not-an-id")).statusCode).toBe(404);
    expect(s.calls.length).toBe(before);
  });

  it("решение: в порт — totals_hash из формы, как есть; ответы порта — текст человеку", async () => {
    const s = await open([request(1)]);
    const other = "cd".repeat(32);
    const res = await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=APPROVE&totals_hash=${other}`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Покупка подтверждена");
    expect(s.calls.at(-1)).toEqual({ op: "confirm", principal: P, id: CID(1), decision: "APPROVE", hash: other });
    const rej = await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=REJECT&totals_hash=${HASH}`);
    expect(rej.body).toContain("Покупка отклонена");
  });

  it.each([
    [{ kind: "TOTALS_CHANGED" } as ConfirmResult, 409, "Данные покупки изменились"],
    [{ kind: "NOT_PENDING", status: "APPROVED" } as ConfirmResult, 409, "data-status>Подтверждена<"],
    [{ kind: "NOT_PENDING", status: "EXPIRED" } as ConfirmResult, 409, "data-status>Срок истёк<"],
    [{ kind: "NOT_FOUND" } as ConfirmResult, 404, "Запрос не найден"],
  ])("ответ порта %j — %i", async (confirm, code, text) => {
    const s = await open([request(1)], { confirm });
    const res = await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=APPROVE&totals_hash=${HASH}`);
    expect([res.statusCode, res.body.includes(text)]).toEqual([code, true]);
  });

  it("форма: без CSRF — 403, без решения или хэша, хэш не по форме — 400, id не по форме — 404; порт не вызывается", async () => {
    const s = await open([request(1)]);
    const before = s.calls.filter((c) => c.op === "confirm").length;
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&decision=APPROVE&totals_hash=${HASH}`)).statusCode).toBe(403);
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=wrong&decision=APPROVE&totals_hash=${HASH}`)).statusCode).toBe(403);
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&totals_hash=${HASH}`)).statusCode).toBe(400);
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=SIGN&totals_hash=${HASH}`)).statusCode).toBe(400);
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=APPROVE`)).statusCode).toBe(400);
    expect((await s.post(`/c/${CID(1)}/decision`, `lang=ru&csrf=${s.csrf}&decision=APPROVE&totals_hash=${HASH.toUpperCase()}`)).statusCode).toBe(400);
    expect((await s.post(`/c/bad/decision`, `lang=ru&csrf=${s.csrf}&decision=APPROVE&totals_hash=${HASH}`)).statusCode).toBe(404);
    expect(s.calls.filter((c) => c.op === "confirm").length).toBe(before);
  });

  it("сбой порта — 503 без кнопок (fail-closed)", async () => {
    const s = await open([request(1)], { fail: true });
    const home = await s.get("/");
    expect(home.statusCode).toBe(503);
    const page = await s.get(`/c/${CID(1)}`);
    expect(page.statusCode).toBe(503);
    expect(page.body).not.toContain("data-approve");
  });

  it("en: тексты и сумма на английском", async () => {
    const s = await open([request(1)]);
    const page = (await s.get(`/c/${CID(1)}?lang=en`)).body;
    expect(page).toContain("Confirm purchase");
    expect(page).toContain("data-status>Awaiting decision<");
    const res = await s.post(`/c/${CID(1)}/decision`, `lang=en&csrf=${s.csrf}&decision=APPROVE&totals_hash=${HASH}`);
    expect(res.body).toContain("Purchase confirmed");
  });
});

describe("адаптер стенда: «свой» запрос — по principal_ref мандата запроса (решение владельца 03.11)", () => {
  const rec = (mandate_id: string) => ({
    confirmation_id: CID(1),
    agent_code: "a",
    mandate_id,
    merchant_id: "MER-1042",
    amount: 340_000,
    currency: "RUB",
    order_ref: "ORD-1",
    split_detected: false,
    status: "PENDING" as const,
    created_at: "2026-11-03T10:00:00.000Z",
    expires_at: "2026-11-03T10:15:00.000Z",
    confirmation_ref: null,
    decision: null,
    op_ref: null,
  });
  const MINE = "mnd_00000001-0000-4000-8000-000000000000";
  const LOST = "mnd_00000002-0000-4000-8000-000000000000";
  function port(mandate_id: string) {
    const sent: unknown[] = [];
    const p = issuerScreenPort({
      now: () => new Date(T0),
      mandateIds: () => [],
      // Мандат MINE — этого клиента; LOST — не найден.
      signingView: async (id) => (id === MINE ? ({ principal_ref: P } as Awaited<ReturnType<IssuerScreenDeps["signingView"]>>) : undefined),
      sign: async () => ({ statusCode: 500, body: {} }),
      revoke: async () => ({ statusCode: 500, body: {} }),
      revokeAll: async () => ({ statusCode: 500, body: {} }),
      confirmationIds: () => [CID(1)],
      confirmationRecord: async () => rec(mandate_id),
      confirm: async (id, o) => (sent.push({ id, ...o }), { statusCode: 200, body: { status: "APPROVED" } }),
    });
    return { p, sent };
  }

  it("свой: итог и totals_hash из записи; решение уходит с хэшем из формы", async () => {
    const { p, sent } = port(MINE);
    const c = await p.confirmation(P, CID(1));
    expect(c).toMatchObject({ id: CID(1), amount: 340_000, currency: "RUB", order_ref: "ORD-1", totals_hash: totalsHash(rec(MINE)) });
    expect(await p.confirm(P, CID(1), "APPROVE", HASH)).toEqual({ kind: "DONE", status: "APPROVED" });
    expect(sent).toEqual([{ id: CID(1), decision: "APPROVE", totals_hash: HASH }]);
  });

  it("мандат запроса не найден и чужой клиент — как неизвестный: нет в списке, 404, ПИ-8 не вызывается", async () => {
    for (const [mandate, principal] of [[LOST, P], [MINE, "cl_other"]] as const) {
      const { p, sent } = port(mandate);
      expect(await p.confirmations(principal)).toEqual([]);
      expect(await p.confirmation(principal, CID(1))).toBeUndefined();
      expect(await p.confirm(principal, CID(1), "APPROVE", HASH)).toEqual({ kind: "NOT_FOUND" });
      expect(sent).toEqual([]);
    }
  });
});

const CODE = "nspk:agent:screen-confirm:v1";
const PRINCIPAL = "prn_screen_confirm";
const AMOUNT = 340_000;

describe("ПС11 через экран банка на стенде: подтверждение покупки человеком → ссылка → повтор → APPROVE (РП50, РП51)", () => {
  let stand: Stand;
  let side: AgentSide;
  let cartId: string;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date(T0));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
    cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: 2_000_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: AMOUNT }], total: AMOUNT },
    });
  });
  afterAll(async () => stand.close());

  const call = (method: "GET" | "POST", path: string, body?: unknown) =>
    signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });

  async function mandate(over: Partial<MandateRequest>): Promise<string> {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-11-07T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await call("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  }

  /** Заказ выше порога: реквизит, авторизация → CONFIRMATION_REQUIRED; запрос П6 и сообщение для повтора. */
  async function overThreshold(order: string) {
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" })).json() as Credential;
    const msg = (op_ref: string, confirmation_ref?: string): CanonicalMessage => ({
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: AMOUNT,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      aoi: c.aoi,
      order_ref: order,
      ...(confirmation_ref ? { confirmation_ref } : {}),
    });
    expect(parseDecision(await decide(msg(`${order}-1`)), "adp").decision).toBe("CONFIRMATION_REQUIRED");
    const [req] = await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref: order, amount: AMOUNT, currency: "RUB" });
    return { id: req!.confirmation_id, expires_at: req!.expires_at, msg };
  }
  const decide = async (m: CanonicalMessage): Promise<Decision> => (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;

  /** Вход клиента на экран банка стенда по одноразовой ссылке. */
  async function bank(principal: string) {
    const login = await stand.bankApp.app.inject({ method: "GET", url: stand.bankApp.session(principal) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    const get = (url: string) => stand.bankApp.app.inject({ method: "GET", url, headers: { cookie } });
    const post = (url: string, body: string) => stand.bankApp.app.inject({ method: "POST", url, headers: { cookie, ...FORM }, payload: body });
    const csrf = encodeURIComponent(csrfOf((await get("/")).body));
    return { get, post, csrf };
  }

  type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];
  const feed = async (): Promise<Feed> => (await call("GET", "/pao/v1/events")).json() as Feed;

  it("доказательный: запрос на экране → «Подтвердить» → ПИ-8 от банка → confirmation.approved → ссылка → APPROVE; второй раз — нет", async () => {
    const { id, msg } = await overThreshold("ORD-scr-1");
    const b = await bank(PRINCIPAL);
    expect((await b.get("/")).body).toContain(`data-confirmation="${id}"`);
    const page = (await b.get(`/c/${id}`)).body;
    expect(page).toMatch(/data-amount>3\s?400,00\s?₽</);
    expect(page).toContain("data-order>ORD-scr-1<");
    expect(page).toContain(`data-agent>${CODE}<`);
    const hash = hashOf(page);

    const done = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=APPROVE&totals_hash=${hash}`);
    expect(done.statusCode).toBe(200);
    expect(done.body).toContain("data-status>Подтверждена<");
    expect(done.body, "confirmation_ref человеку не показывается (РП50 п. 7)").not.toContain("cr_");
    const rec = await stand.confirmations.get(id);
    expect(rec?.decision).toMatchObject({ participant_code: "stand:issuer-emulator", decision: "APPROVE", totals_hash: hash });
    expect(rec?.decision, "банк не передаёт instrument_chosen (РП51 п. 13)").not.toHaveProperty("instrument_chosen");

    // Агент: событие → GET со ссылкой → повтор через продавца новой операцией.
    expect((await feed()).filter((e) => e.type === "confirmation.approved" && e.data.confirmation_id === id)).toHaveLength(1);
    const view = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { status: string; confirmation_ref: string };
    expect(view.status).toBe("APPROVED");
    expect(parseDecision(await decide(msg("ORD-scr-1-2", view.confirmation_ref)), "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect((await stand.confirmations.get(id))?.status).toBe("USED");
    expect(parseDecision(await decide(msg("ORD-scr-1-3", view.confirmation_ref)), "adp").decision).not.toBe("APPROVE");

    // После решения: на главной запроса нет, страница — без кнопок.
    expect((await b.get("/")).body).not.toContain(`data-confirmation="${id}"`);
    expect((await b.get(`/c/${id}`)).body).not.toContain("data-approve");
    // Двойное нажатие в ту же секунду — та же запись банка (decided_at и подпись те же): ПИ-8 — 200 с текущим статусом
    // без записи; позже — другая запись: 409 «уже не ждёт». Второго события нет ни в одном случае.
    const same = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=APPROVE&totals_hash=${hash}`);
    expect([same.statusCode, same.body.includes("data-status>Подтверждена, оплата проведена<")]).toEqual([200, true]);
    stand.setClock(new Date(T0 + 1_000));
    try {
      const later = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=APPROVE&totals_hash=${hash}`);
      expect([later.statusCode, later.body.includes("Запрос уже не ждёт решения")]).toEqual([409, true]);
    } finally {
      stand.setClock(new Date(T0));
    }
    expect((await feed()).filter((e) => e.type === "confirmation.approved" && e.data.confirmation_id === id)).toHaveLength(1);
  });

  it("чужой клиент: запроса нет ни в списке, ни по id; решение — 404 без записи", async () => {
    const { id } = await overThreshold("ORD-scr-2");
    const other = await bank("prn_someone_else");
    expect((await other.get("/")).body).not.toContain(id);
    expect((await other.get(`/c/${id}`)).statusCode).toBe(404);
    const owner = await bank(PRINCIPAL);
    const hash = hashOf((await owner.get(`/c/${id}`)).body);
    expect((await other.post(`/c/${id}/decision`, `lang=ru&csrf=${other.csrf}&decision=APPROVE&totals_hash=${hash}`)).statusCode).toBe(404);
    expect((await stand.confirmations.get(id))?.status).toBe("PENDING");
  });

  it("итог не тот, что видел человек: ПИ-8 отказывает, экран — «изменились», запрос ждёт; отказ человека — REJECTED без ссылки", async () => {
    const { id } = await overThreshold("ORD-scr-3");
    const b = await bank(PRINCIPAL);
    const res = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=APPROVE&totals_hash=${"0".repeat(64)}`);
    expect(res.statusCode).toBe(409);
    expect(res.body).toContain("Данные покупки изменились");
    expect((await stand.confirmations.get(id))?.status).toBe("PENDING");

    const hash = hashOf((await b.get(`/c/${id}`)).body);
    const rej = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=REJECT&totals_hash=${hash}`);
    expect(rej.statusCode).toBe(200);
    expect(rej.body).toContain("Покупка отклонена");
    expect(await stand.confirmations.get(id)).toMatchObject({ status: "REJECTED", confirmation_ref: null });
  });

  it("после срока: страница без кнопок, «срок истёк»; решение из старой формы — 409 EXPIRED", async () => {
    const { id, expires_at } = await overThreshold("ORD-scr-4");
    const hash = hashOf((await (await bank(PRINCIPAL)).get(`/c/${id}`)).body);
    stand.setClock(new Date(Date.parse(expires_at)));
    try {
      // На стенде срок сессии экрана (900 с) равен order_hold_sec — вход заново, форма — с хэшем, виденным до срока.
      const b = await bank(PRINCIPAL);
      const page = (await b.get(`/c/${id}`)).body;
      expect(page).not.toContain("data-approve");
      expect(page).toContain("data-status>Срок истёк<");
      const res = await b.post(`/c/${id}/decision`, `lang=ru&csrf=${b.csrf}&decision=APPROVE&totals_hash=${hash}`);
      expect(res.statusCode).toBe(409);
      expect(res.body).toContain("data-status>Срок истёк<");
    } finally {
      stand.setClock(new Date(T0));
    }
  });
});
