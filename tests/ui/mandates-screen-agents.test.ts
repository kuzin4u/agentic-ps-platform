// Экран мандатов: список агентов клиента и подсказка о приостановленном агенте (UI-К2 ч. 2, К2.2; РП54; решение владельца
// 03.11; инварианты 3, 5). Модуль — с подставным портом: агенты по agent_code мандатов (без повторов, по порядку), класс
// и статус — из порта; статус не прочитан — пометка, страница работает; подсказка на странице запроса подтверждения —
// кнопки остаются. Стенд — сквозной путь: приостановление агента оператором → подсказка на экране банка, на странице УПК и
// в списке агентов; после снятия — подсказки нет.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMandatesScreen } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort, ScreenAgent, ScreenConfirmation, ScreenMandate } from "../../src/ui/mandates/port.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const T0 = Date.parse("2026-11-03T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };
const P = "cl_screen_agents";
const A1 = "nspk:agent:one:v1";
const A2 = "nspk:agent:two:v1";
const A3 = "nspk:agent:three:v1";
const CID = "cnf_00000001-0000-4000-8000-000000000000";

const cookieOf = (setCookie: unknown): string => String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0]!;
const hintOf = (html: string) => /data-agent-hint="([A-Z]+)"/.exec(html)?.[1];

const mandate = (n: number, agent_code: string): ScreenMandate => ({
  id: `mnd_0000000${n}-0000-4000-8000-000000000000`,
  agent_code,
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

const request = (agent_code: string): ScreenConfirmation => ({
  id: CID,
  agent_code,
  mandate_id: "mnd_00000001-0000-4000-8000-000000000000",
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref: "ORD-1",
  status: "PENDING",
  expires_at: "2026-11-03T10:15:00.000Z",
  totals_hash: "ab".repeat(32),
});

/** Агенты реестра подставного порта: значение — агент, "fail" — сбой чтения, нет ключа — нет в реестре. */
async function open(mandates: ScreenMandate[] | "fail", agents: Record<string, ScreenAgent | "fail">, confirmations: ScreenConfirmation[] = []) {
  const asked: string[] = [];
  const port: MandatesScreenPort = {
    mandates: async () => {
      if (mandates === "fail") throw new Error("порт недоступен");
      return mandates;
    },
    mandate: async () => undefined,
    decide: async () => ({ kind: "NOT_FOUND" }),
    revoke: async () => ({ kind: "NOT_FOUND" }),
    revokeAll: async () => ({ revoked: 0 }),
    confirmations: async () => confirmations,
    confirmation: async (_p, id) => confirmations.find((c) => c.id === id),
    confirm: async () => ({ kind: "NOT_FOUND" }),
    async agent(code) {
      asked.push(code);
      const a = agents[code];
      if (a === "fail") throw new Error("реестр недоступен");
      return a;
    },
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: 600, now: () => new Date(T0) });
  const login = await screen.app.inject({ method: "GET", url: screen.loginPath(P) });
  const cookie = cookieOf(login.headers["set-cookie"]);
  const get = (url: string) => screen.app.inject({ method: "GET", url, headers: { cookie } });
  return { get, asked };
}

const agent = (agent_code: string, status: string, cls = "BUYER"): ScreenAgent => ({ agent_code, class: cls, status });

describe("экран мандатов: список агентов (модуль)", () => {
  it("агенты — по agent_code мандатов, без повторов, по порядку; класс и статус — текстом; ссылка с главной", async () => {
    const s = await open([mandate(1, A1), mandate(2, A2), mandate(3, A1)], { [A1]: agent(A1, "ACTIVE"), [A2]: agent(A2, "SUSPENDED", "SERVICE") });
    expect((await s.get("/")).body).toContain('href="/agents?lang=ru" data-agents-link');
    const page = await s.get("/agents");
    expect(page.statusCode).toBe(200);
    const rows = [...page.body.matchAll(/data-agent="([^"]+)"/g)].map((m) => m[1]);
    expect(rows).toEqual([A1, A2]);
    expect(s.asked).toEqual([A1, A2]);
    expect(page.body).toContain("Агент покупателя — <span data-status>Действует</span>");
    expect(page.body).toContain("Сервисный агент — <span data-status>Приостановлен</span>");
    expect(page.body).toContain("Пока агент приостановлен, подтверждение не приведёт к оплате.");
  });

  it("статус не прочитан (сбой или нет в реестре) — пометка в строке, страница 200; неизвестные класс и статус — кодом", async () => {
    const s = await open([mandate(1, A1), mandate(2, A2), mandate(3, A3)], { [A1]: "fail", [A3]: agent(A3, "НОВЫЙ", "ДРУГОЙ") });
    const page = await s.get("/agents");
    expect(page.statusCode).toBe(200);
    expect(page.body.match(/data-agent-hint="UNKNOWN"/g)).toHaveLength(2);
    expect(page.body).toContain("ДРУГОЙ — <span data-status>НОВЫЙ</span>");
  });

  it("мандаты не прочитаны — 503; мандатов нет — «агентов нет»; en", async () => {
    expect((await (await open("fail", {})).get("/agents")).statusCode).toBe(503);
    expect((await (await open([], {})).get("/agents")).body).toContain("data-empty>Агентов нет<");
    const en = (await (await open([mandate(1, A1)], { [A1]: agent(A1, "EXCLUDED") })).get("/agents?lang=en")).body;
    expect(en).toContain("Buyer agent — <span data-status>Excluded</span>");
    expect(en).toContain("Confirming will not lead to payment.");
  });
});

describe("экран мандатов: подсказка о статусе агента на странице запроса подтверждения (модуль; РП54)", () => {
  it.each([
    ["ACTIVE", agent(A1, "ACTIVE"), undefined],
    ["SUSPENDED", agent(A1, "SUSPENDED"), "SUSPENDED"],
    ["EXCLUDED", agent(A1, "EXCLUDED"), "EXCLUDED"],
    ["нет в реестре", undefined, "UNKNOWN"],
    ["сбой чтения", "fail" as const, "UNKNOWN"],
  ])("%s — подсказка %s; кнопки остаются, страница 200", async (_name, a, hint) => {
    const s = await open([], a === undefined ? {} : { [A1]: a }, [request(A1)]);
    const page = await s.get(`/c/${CID}`);
    expect(page.statusCode).toBe(200);
    expect(hintOf(page.body)).toBe(hint);
    expect(page.body).toContain("data-approve");
  });

  it("текст подсказки — как решил владелец; статус не читается у запроса, который уже не ждёт решения", async () => {
    const s = await open([], { [A1]: agent(A1, "SUSPENDED") }, [request(A1)]);
    expect((await s.get(`/c/${CID}`)).body).toContain("Агент приостановлен оператором. Пока агент приостановлен, подтверждение не приведёт к оплате.");
    const done = await open([], { [A1]: agent(A1, "SUSPENDED") }, [{ ...request(A1), status: "APPROVED" }]);
    expect(hintOf((await done.get(`/c/${CID}`)).body)).toBeUndefined();
    expect(done.asked).toEqual([]);
  });
});

const CODE = "nspk:agent:screen-agents:v1";
const PRINCIPAL = "prn_screen_agents";
const AMOUNT = 340_000;

describe("стенд: приостановление агента — подсказка на экране банка, странице УПК и в списке агентов (РП54)", () => {
  let stand: Stand;
  let side: AgentSide;
  let confirmationId: string;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date(T0));
    side = newAgentSide();
    expect((await stand.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    const intentId = await signed({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
    const cartId = await signed({
      type: "CART",
      parent_id: intentId,
      amount_limit: 2_000_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: AMOUNT }], total: AMOUNT },
    });
    const order = "ORD-agents-1";
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" })).json() as Credential;
    const msg: CanonicalMessage = {
      op_ref: "OPKC-AGENTS-1",
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: AMOUNT,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      aoi: c.aoi,
      order_ref: order,
    };
    const d = (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
    expect(d.decision).toBe("CONFIRMATION_REQUIRED");
    const [req] = await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref: order, amount: AMOUNT, currency: "RUB" });
    confirmationId = req!.confirmation_id;
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

  async function signed(over: Partial<MandateRequest>): Promise<string> {
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

  async function bank() {
    const login = await stand.bankApp.app.inject({ method: "GET", url: stand.bankApp.session(PRINCIPAL) });
    const cookie = cookieOf(login.headers["set-cookie"]);
    return (url: string) => stand.bankApp.app.inject({ method: "GET", url, headers: { cookie } });
  }
  const upkPage = async () => (await stand.upk.app.inject({ method: "GET", url: `/c/${confirmationId}` })).body;

  it("действует — подсказки нет; приостановлен — подсказка везде, кнопки остаются; после снятия — подсказки нет", async () => {
    const get = await bank();
    expect(hintOf((await get(`/c/${confirmationId}`)).body)).toBeUndefined();
    expect(hintOf(await upkPage())).toBeUndefined();
    expect((await get("/agents")).body).toContain("Агент покупателя — <span data-status>Действует</span>");

    await stand.suspendAgent(CODE, "OUT_OF_MANDATE");
    const screen = (await get(`/c/${confirmationId}`)).body;
    expect(hintOf(screen)).toBe("SUSPENDED");
    expect(screen).toContain("data-approve");
    const upk = await upkPage();
    expect(hintOf(upk)).toBe("SUSPENDED");
    expect(upk).toContain('value="APPROVE"');
    const agents = (await get("/agents")).body;
    expect(agents).toContain(`data-agent="${CODE}"`);
    expect(agents).toContain("<span data-status>Приостановлен</span>");

    await stand.reinstateAgent(CODE);
    expect(hintOf((await get(`/c/${confirmationId}`)).body)).toBeUndefined();
    expect(hintOf(await upkPage())).toBeUndefined();
  });
});

describe("стенд: /agents — только агенты мандатов этого клиента (поломка по решению владельца 03.11)", () => {
  const C1 = { code: "nspk:agent:screen-agents-a:v1", principal: "prn_screen_agents_a" };
  const C2 = { code: "nspk:agent:screen-agents-b:v1", principal: "prn_screen_agents_b" };
  let stand: Stand;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date(T0));
    // Два агента, у каждого — мандат своего клиента.
    for (const c of [C1, C2]) {
      const side = newAgentSide();
      expect((await stand.admit(buyerApplication(c.code, side), "op")).admitted).toBe(true);
      const req: MandateRequest = {
        type: "INTENT",
        subject: "s",
        amount_limit: 100_000,
        currency: "RUB",
        valid_to: "2026-11-07T00:00:00Z",
        merchant_scope: ["MER-1042"],
        principal_ref: c.principal,
        mode: "IMMEDIATE",
      };
      const res = await signedInject(stand.app, side, c.code, {
        method: "POST",
        path: "/pao/v1/mandates",
        body: JSON.stringify(req),
        headers: { "idempotency-key": randomUUID() },
        now: stand.now(),
      });
      expect(res.statusCode).toBe(201);
    }
  });
  afterAll(async () => stand.close());

  const agentsOf = async (principal: string): Promise<string[]> => {
    const login = await stand.bankApp.app.inject({ method: "GET", url: stand.bankApp.session(principal) });
    const page = await stand.bankApp.app.inject({ method: "GET", url: "/agents", headers: { cookie: cookieOf(login.headers["set-cookie"]) } });
    expect(page.statusCode).toBe(200);
    return [...page.body.matchAll(/data-agent="([^"]+)"/g)].map((m) => m[1]!);
  };

  it("каждый клиент видит только своего агента; чужой агент на /agents не виден", async () => {
    expect(await agentsOf(C1.principal)).toEqual([C1.code]);
    expect(await agentsOf(C2.principal)).toEqual([C2.code]);
    expect(await agentsOf("prn_no_mandates")).toEqual([]);
  });
});
