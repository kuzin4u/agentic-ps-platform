// PS-12: эмулятор продавцов — тест на каждый тип витрины (К6 пула, A5), подпись агента по каталогу ключей (РП22).
import { afterEach, describe, expect, it } from "vitest";
import { SHOPS, SHOP_BEHAVIOURS, buildMerchantsServer, MerchantAgentVerifier } from "../../src/env/merchants/index.js";
import { Acquirer, OpkcStub } from "../../src/env/acquirer/index.js";
import { createMerchants, createStand, type MerchantsStand, type Stand } from "../../src/stand/index.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";

const LIMIT = loadParams().merchant_rate_limit_per_min;
const A = "nspk:agent:shop-a:v1";
const B = "nspk:agent:shop-b:v1";
const T0 = new Date("2026-10-13T10:00:00Z");

let m: MerchantsStand | undefined;
afterEach(async () => {
  await m?.close();
  m = undefined;
});

function setup(opts: Parameters<typeof createMerchants>[1] = {}) {
  const s = createStand();
  s.setClock(T0);
  const a = newAgentSide();
  const b = newAgentSide();
  expect(s.admit(buyerApplication(A, a), "op-a").admitted).toBe(true);
  expect(s.admit(buyerApplication(B, b), "op-b").admitted).toBe(true);
  m = createMerchants(s, opts);
  const as = (side: AgentSide, code: string) => ({ side, agentCode: code, now: s.now() });
  return { s, a, b, m, app: m.app, asA: () => as(a, A) };
}

const pkg = (order_ref: string, mandate = "MND-cart-1", agent = A) => ({
  credential_ref: "CRD-test-1",
  kind: "CARD",
  payload: { token_ref: "tok_ag_test", cryptogram: "Y3J5cHRvZ3JhbQ==", valid_to: "2026-10-13T10:15:00Z" },
  aoi: { indicator: true, agent_code: agent, mandate_id: mandate },
  cart_mandate_id: mandate,
  order_ref,
});

async function order(app: Stand["app"], who: object, shop: string, sku: string, qty = 1, extra: object = {}) {
  return merchantCall(app, { ...who, path: `/v1/shops/${shop}/orders`, body: { items: [{ sku, qty }], cart_mandate_id: "MND-cart-1", ...extra } });
}

describe("К6: список витрин и зоны", () => {
  it("каждое поведение представлено витриной; ID — по сценариям агента и SHOP-5501", async () => {
    expect(new Set(SHOPS.map((s) => s.behaviour))).toEqual(new Set(SHOP_BEHAVIOURS));
    const { app } = setup();
    const r = await merchantCall(app, { path: "/v1/shops" });
    expect(r.statusCode).toBe(200);
    const ids = r.json().shops.map((s: { id: string }) => s.id);
    expect(ids).toEqual(["MKT-77", "SHOP-1042", "SHOP-2210", "SHOP-3301", "SHOP-3302", "SHOP-3303", "SHOP-4401", "SHOP-5003", "SHOP-5501"]);
  });

  it("SHOP-1042 — в контуре со знаком готовности; MKT-77 — вне контура (A5 п. 5, П07)", async () => {
    const { app } = setup();
    const shops = (await merchantCall(app, { path: "/v1/shops" })).json().shops;
    expect(shops.find((s: { id: string }) => s.id === "SHOP-1042")).toMatchObject({ zone: "CONTOUR", readiness_mark: true });
    expect(shops.find((s: { id: string }) => s.id === "MKT-77")).toMatchObject({ zone: "OUTSIDE", readiness_mark: false });
  });

  it("знак готовности не меняет порядок выдачи (A5 п. 5.2, A6 п. 2.1)", async () => {
    const flipped = SHOPS.map((s) => ({ ...s, readiness_mark: !s.readiness_mark }));
    const opkc = new OpkcStub();
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: true, opkc });
    const verifier = new MerchantAgentVerifier(() => ({ keys: [] }), { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60 });
    const one = buildMerchantsServer({ verifier, acquirer, rateLimitPerMin: LIMIT });
    const two = buildMerchantsServer({ verifier, acquirer, shops: flipped, rateLimitPerMin: LIMIT });
    const list = async (app: typeof one) => (await merchantCall(app, { path: "/v1/shops" })).json().shops as { id: string; zone: string }[];
    const [a, b] = [await list(one), await list(two)];
    // Зоны действительно разные (у каждой витрины CONTOUR ↔ OUTSIDE), порядок — один.
    expect(a.every((s, i) => s.zone !== b[i]!.zone)).toBe(true);
    expect(b.map((s) => s.id)).toEqual(a.map((s) => s.id));
    // И каталог внутри витрины от знака не зависит.
    const items = async (app: typeof one) => (await merchantCall(app, { path: "/v1/shops/SHOP-1042/catalog" })).json().items;
    expect(await items(two)).toEqual(await items(one));
  });

  it("MKT-77 — только чтение: каталог отдаёт, заказ — ORDERS_NOT_ACCEPTED", async () => {
    const { app, asA } = setup();
    expect((await merchantCall(app, { path: "/v1/shops/MKT-77/catalog" })).statusCode).toBe(200);
    const r = await order(app, asA(), "MKT-77", "BRD-77-01");
    expect(r.statusCode).toBe(409);
    expect(r.json().code).toBe("ORDERS_NOT_ACCEPTED");
  });

  it("поиск по query и limit", async () => {
    const { app } = setup();
    const r = await merchantCall(app, { path: "/v1/shops/SHOP-1042/catalog", query: "query=%D0%BD%D0%B0%D0%B1%D0%BE%D1%80&limit=5" });
    expect(r.json().items.map((i: { sku: string }) => i.sku)).toEqual(["BRD-1042-02"]);
    const one = await merchantCall(app, { path: "/v1/shops/SHOP-1042/catalog", query: "limit=1" });
    expect(one.json().items).toHaveLength(1);
  });

  it("неизвестная витрина — 404", async () => {
    const { app } = setup();
    expect((await merchantCall(app, { path: "/v1/shops/SHOP-0000/catalog" })).statusCode).toBe(404);
  });
});

describe("SHOP-4401: отказ неопознанным, опознанный агент из реестра обслуживается (A5 п. 2.1–2.2, П08)", () => {
  const path = "/v1/shops/SHOP-4401/catalog";

  it("без подписи — 403 AGENT_UNIDENTIFIED", async () => {
    const { app } = setup();
    const r = await merchantCall(app, { path });
    expect(r.statusCode).toBe(403);
    expect(r.json().code).toBe("AGENT_UNIDENTIFIED");
  });

  it("подписанное обращение агента из реестра — 200", async () => {
    const { app, asA } = setup();
    expect((await merchantCall(app, { ...asA(), path })).statusCode).toBe(200);
  });

  it("агент не в реестре — KEY_UNKNOWN", async () => {
    const { app, s } = setup();
    const stranger = newAgentSide();
    const r = await merchantCall(app, { side: stranger, agentCode: "nspk:agent:stranger:v1", now: s.now(), path });
    expect(r.statusCode).toBe(401);
    expect(r.json().code).toBe("KEY_UNKNOWN");
  });

  it("ключ агента B, x-agent-code агента A — AGENT_MISMATCH (инвариант 5)", async () => {
    const { app, s, b } = setup();
    const r = await merchantCall(app, { side: b, agentCode: A, now: s.now(), path });
    expect(r.statusCode).toBe(401);
    expect(r.json().code).toBe("AGENT_MISMATCH");
  });

  it("отозванный ключ — из каталога удалён: KEY_UNKNOWN", async () => {
    const { app, s, a, asA } = setup();
    s.keys.revoke(A, a.kid);
    expect((await merchantCall(app, { ...asA(), path })).json().code).toBe("KEY_UNKNOWN");
  });

  it("приостановленный агент — KEY_UNKNOWN", async () => {
    const { app, s, asA } = setup();
    s.registry.changeStatus(A, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" });
    expect((await merchantCall(app, { ...asA(), path })).json().code).toBe("KEY_UNKNOWN");
  });

  it("истёкший exp в кэше каталога — KEY_EXPIRED", async () => {
    const { app, s, asA } = setup({ jwksMaxAgeMs: 400 * 86_400_000, jwksRefetchMinMs: 400 * 86_400_000 });
    expect((await merchantCall(app, { ...asA(), path })).statusCode).toBe(200);
    s.setClock(new Date(T0.getTime() + (s.params.key_ttl_days + 1) * 86_400_000));
    const r = await merchantCall(app, { ...asA(), path });
    expect(r.json().code).toBe("KEY_EXPIRED");
  });

  it("повтор nonce — SIGNATURE_INVALID", async () => {
    const { app, asA } = setup();
    const nonce = "nonce-fixed-1";
    expect((await merchantCall(app, { ...asA(), path, nonce })).statusCode).toBe(200);
    expect((await merchantCall(app, { ...asA(), path, nonce })).json().code).toBe("SIGNATURE_INVALID");
  });

  it("сбой каталога ключей — 503, не догадка (инвариант 3)", async () => {
    const opkc = new OpkcStub();
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: true, opkc });
    const verifier = new MerchantAgentVerifier(
      () => {
        throw new Error("каталог недоступен");
      },
      { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60 },
    );
    const app = buildMerchantsServer({ verifier, acquirer, rateLimitPerMin: LIMIT });
    const side = newAgentSide();
    const r = await merchantCall(app, { side, agentCode: A, path });
    expect(r.statusCode).toBe(503);
  });
});

describe("РП22 п. 3: перечитывание каталога по неизвестному kid — не чаще окна", () => {
  it("недоступный каталог не перечитывается на каждый запрос: окно — от попытки чтения", async () => {
    let now = T0;
    const verifier = new MerchantAgentVerifier(
      () => {
        throw new Error("каталог недоступен");
      },
      { maxAgeMs: 3_600_000, refetchMinMs: 60_000, skewSec: 60, now: () => now },
    );
    const side = newAgentSide();
    const app = buildMerchantsServer({ verifier, acquirer: new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: true, opkc: new OpkcStub() }), rateLimitPerMin: LIMIT });
    const path = "/v1/shops/SHOP-1042/catalog";
    expect((await merchantCall(app, { side, agentCode: A, now, path })).statusCode).toBe(503);
    for (let i = 0; i < 3; i++) expect((await merchantCall(app, { side, agentCode: A, now, path })).json().code).toBe("KEY_UNKNOWN");
    expect(verifier.fetches).toBe(1);
    now = new Date(T0.getTime() + 60_000);
    expect((await merchantCall(app, { side, agentCode: A, now, path })).statusCode).toBe(503);
    expect(verifier.fetches).toBe(2);
  });

  it("второй неизвестный kid в окне — отказ без перечитывания; новый ключ виден после окна", async () => {
    const minute = 60_000;
    const { app, s, m: ms } = setup({ jwksMaxAgeMs: 60 * minute, jwksRefetchMinMs: minute });
    const path = "/v1/shops/SHOP-1042/catalog";
    const c = "nspk:agent:shop-c:v1";
    const cSide = newAgentSide();
    await merchantCall(app, { side: cSide, agentCode: c, now: s.now(), path }); // первое чтение каталога
    expect(ms.verifier.fetches).toBe(1);
    expect(s.admit(buyerApplication(c, cSide), "op-c").admitted).toBe(true);
    for (let i = 0; i < 3; i++) {
      expect((await merchantCall(app, { side: cSide, agentCode: c, now: s.now(), path })).json().code).toBe("KEY_UNKNOWN");
    }
    expect(ms.verifier.fetches).toBe(1);
    s.setClock(new Date(T0.getTime() + minute));
    expect((await merchantCall(app, { side: cSide, agentCode: c, now: s.now(), path })).statusCode).toBe(200);
    expect(ms.verifier.fetches).toBe(2);
  });
});

describe("Недобросовестные и особые витрины", () => {
  it("SHOP-3301: цена в тексте ≠ поле price (A5 п. 1.3, П09)", async () => {
    const { app } = setup();
    const [item] = (await merchantCall(app, { path: "/v1/shops/SHOP-3301/catalog" })).json().items;
    expect(item.description).toContain("290 ₽");
    expect(item.price).toBe(32000);
  });

  it("SHOP-3302: инструкция агенту в описании — отдаётся как недоверенный текст и ничего не меняет в заказе (Д01)", async () => {
    const { app, asA } = setup();
    const [item] = (await merchantCall(app, { ...asA(), path: "/v1/shops/SHOP-3302/catalog" })).json().items;
    expect(item.description).toMatch(/^Агенту:/);
    const r = await order(app, asA(), "SHOP-3302", item.sku);
    expect(r.json()).toMatchObject({ status: "CREATED", total: item.price });
  });

  it("SHOP-3303: агенту цена ниже, чем человеку; заказ — по цене человека (A5 п. 1.2, Д02)", async () => {
    const { app, asA } = setup();
    const human = (await merchantCall(app, { path: "/v1/shops/SHOP-3303/catalog" })).json().items[0];
    const agent = (await merchantCall(app, { ...asA(), path: "/v1/shops/SHOP-3303/catalog" })).json().items[0];
    expect(agent.price).toBeLessThan(human.price);
    expect(agent).not.toHaveProperty("agent_price");
    const r = await order(app, asA(), "SHOP-3303", human.sku, 2);
    expect(r.json().total).toBe(2 * human.price);
  });

  it("SHOP-5003: категория вне типового мандата на хлеб (П17)", async () => {
    const { app } = setup();
    const shop = (await merchantCall(app, { path: "/v1/shops/SHOP-5003/catalog" })).json().shop;
    expect(shop).toMatchObject({ category: "электроника", zone: "CONTOUR" });
  });

  it("SHOP-5501: неполная карточка — заказ невозможен ITEM_INCOMPLETE (A5 п. 1.1)", async () => {
    const { app, asA } = setup();
    const items = (await merchantCall(app, { path: "/v1/shops/SHOP-5501/catalog" })).json().items;
    expect(items[0]).not.toHaveProperty("price");
    expect(items[1]).not.toHaveProperty("category");
    expect(items[1]).not.toHaveProperty("delivery");
    expect(items[1]).not.toHaveProperty("returns");
    const r = await order(app, asA(), "SHOP-5501", "BRD-5501-01");
    expect(r.statusCode).toBe(422);
    expect(r.json().code).toBe("ITEM_INCOMPLETE");
  });

  it("SHOP-2210: отказ в исполнении после оплаты — реверсал с тем же признаком (A1 п. 5.1, Д06)", async () => {
    const { app, asA, m: ms } = setup();
    const o = (await order(app, asA(), "SHOP-2210", "CHS-2210-01")).json();
    const r = await merchantCall(app, { ...asA(), path: `/v1/shops/SHOP-2210/orders/${o.id}/payment`, body: pkg(o.id) });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ status: "REJECTED", fulfilment_refused: true, payment: { approved: true } });
    const [auth, rev] = ms.opkc.messages;
    expect(rev).toMatchObject({ msg_type: "REVERSAL", op_ref: auth!.op_ref, amount: auth!.amount });
    expect(rev!.aoi).toEqual(auth!.aoi);
  });

  it("инвариант 5: сумма из тела заказа, тела /payment и пакета не читается — в авторизации сумма заказа продавца", async () => {
    const { app, asA, m: ms } = setup();
    const o = (await order(app, asA(), "SHOP-1042", "BRD-1042-02", 1, { total: 1 })).json();
    expect(o.total).toBe(189000);
    const r = await merchantCall(app, { ...asA(), path: `/v1/shops/SHOP-1042/orders/${o.id}/payment`, body: { ...pkg(o.id), amount: 1, amount_max: 1, payload: { ...pkg(o.id).payload, amount: 1 } } });
    expect(r.json()).toMatchObject({ status: "PAID", payment: { approved: true } });
    expect(ms.opkc.messages[0]).toMatchObject({ amount: 189000, order_ref: o.id, merchant: { id: "MER-1042", acquirer_id: "ACQ-01" } });
  });
});

describe("Лимит частоты витрин по адресу (CodeQL js/missing-rate-limiting)", () => {
  it("сверх лимита — 429 RATE_LIMITED с Retry-After; на все маршруты /v1, до опознания агента", async () => {
    const s = createStand();
    const m2 = createMerchants(s, { rateLimitPerMin: 3 });
    try {
      for (let i = 0; i < 3; i++) expect((await merchantCall(m2.app, { path: "/v1/shops" })).statusCode).toBe(200);
      for (const path of ["/v1/shops", "/v1/shops/SHOP-1042/catalog", "/v1/shops/SHOP-1042/orders"]) {
        const r = await merchantCall(m2.app, { path, ...(path.endsWith("orders") ? { body: {} } : {}) });
        expect(r.statusCode, path).toBe(429);
        expect(r.json()).toEqual({ code: "RATE_LIMITED" });
        expect(Number(r.headers["retry-after"])).toBeGreaterThan(0);
      }
    } finally {
      await m2.close();
    }
  });

  it("на стенде лимит щедрый — из params.stand.json", () => {
    expect(LIMIT).toBeGreaterThanOrEqual(1000);
  });

  it("лимит — целое ≥ 1", () => {
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: true, opkc: new OpkcStub() });
    const verifier = new MerchantAgentVerifier(() => ({ keys: [] }), { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60 });
    for (const v of [0, 1.5, Number.NaN]) expect(() => buildMerchantsServer({ verifier, acquirer, rateLimitPerMin: v })).toThrow();
  });
});

describe("Заказ и пакет: привязка к агенту", () => {
  it("в заказе — мандат корзины cart_mandate_id; без него (в том числе со старым mandate_id) — ITEM_INVALID", async () => {
    const { app, asA } = setup();
    const ok = await order(app, asA(), "SHOP-1042", "BRD-1042-01");
    expect(ok.json()).toMatchObject({ cart_mandate_id: "MND-cart-1" });
    expect(ok.json()).not.toHaveProperty("mandate_id");
    const r = await merchantCall(app, { ...asA(), path: "/v1/shops/SHOP-1042/orders", body: { items: [{ sku: "BRD-1042-01", qty: 1 }], mandate_id: "MND-cart-1" } });
    expect(r.statusCode).toBe(422);
    expect(r.json().code).toBe("ITEM_INVALID");
  });

  it("заказ без подписи — 403 AGENT_UNIDENTIFIED", async () => {
    const { app } = setup();
    const r = await order(app, {}, "SHOP-1042", "BRD-1042-01");
    expect(r.statusCode).toBe(403);
  });

  it("чужой заказ — ORDER_NOT_FOUND; пакет на другой заказ или другого агента — PACKAGE_MISMATCH; неполный — PACKAGE_INVALID", async () => {
    const { app, s, b, asA } = setup();
    const o = (await order(app, asA(), "SHOP-1042", "BRD-1042-01")).json();
    const path = `/v1/shops/SHOP-1042/orders/${o.id}/payment`;
    expect((await merchantCall(app, { side: b, agentCode: B, now: s.now(), path, body: pkg(o.id, "MND-cart-1", B) })).json().code).toBe("ORDER_NOT_FOUND");
    expect((await merchantCall(app, { ...asA(), path, body: pkg("ORD-other") })).json().code).toBe("PACKAGE_MISMATCH");
    expect((await merchantCall(app, { ...asA(), path, body: pkg(o.id, "MND-cart-1", B) })).json().code).toBe("PACKAGE_MISMATCH");
    expect((await merchantCall(app, { ...asA(), path, body: { ...pkg(o.id), cart_mandate_id: "MND-other" } })).json().code).toBe("PACKAGE_MISMATCH");
    expect((await merchantCall(app, { ...asA(), path, body: { ...pkg(o.id), kind: "CASH" } })).json().code).toBe("PACKAGE_INVALID");
  });

  it("повторная оплата заказа — ORDER_NOT_PAYABLE", async () => {
    const { app, asA } = setup();
    const o = (await order(app, asA(), "SHOP-1042", "BRD-1042-01")).json();
    const path = `/v1/shops/SHOP-1042/orders/${o.id}/payment`;
    expect((await merchantCall(app, { ...asA(), path, body: pkg(o.id) })).statusCode).toBe(200);
    expect((await merchantCall(app, { ...asA(), path, body: pkg(o.id) })).json().code).toBe("ORDER_NOT_PAYABLE");
  });

  it("отказ ОПКЦ — заказ DECLINED; op_ref и код решения продавец не раскрывает (РП22 п. 6, РП2)", async () => {
    const { app, asA } = setup({ decide: () => ({ approved: false, reason: "LIMIT_EXCEEDED" }) });
    const o = (await order(app, asA(), "SHOP-1042", "BRD-1042-01")).json();
    const r = await merchantCall(app, { ...asA(), path: `/v1/shops/SHOP-1042/orders/${o.id}/payment`, body: pkg(o.id) });
    expect(r.json()).toMatchObject({ status: "DECLINED", payment: { approved: false } });
    expect(r.json().payment).toEqual({ approved: false });
    expect(r.body).not.toMatch(/OPKC|LIMIT_EXCEEDED/);
  });

  it("две одновременные оплаты заказа — одна авторизация, вторая ORDER_NOT_PAYABLE", async () => {
    const { s, a } = setup();
    // ОПКЦ отвечает только по сигналу теста: первая оплата висит в авторизации, пока приходит вторая.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const sent: string[] = [];
    const opkc = {
      authorize: async (msg: { order_ref?: string }) => {
        sent.push(msg.order_ref as string);
        await gate;
        return { op_ref: `OPKC-T-${sent.length}`, approved: true, reason: null };
      },
      reverse: async () => {},
    };
    const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: true, opkc });
    const verifier = new MerchantAgentVerifier(() => s.keys.jwks("sandbox"), { maxAgeMs: 0, refetchMinMs: 0, skewSec: 60, now: s.now });
    const app = buildMerchantsServer({ verifier, acquirer, rateLimitPerMin: LIMIT });
    const who = { side: a, agentCode: A, now: s.now() };
    const o = (await order(app, who, "SHOP-1042", "BRD-1042-01")).json();
    const path = `/v1/shops/SHOP-1042/orders/${o.id}/payment`;
    const first = merchantCall(app, { ...who, path, body: pkg(o.id) });
    while (sent.length === 0) await new Promise((r) => setTimeout(r, 1));
    const second = await merchantCall(app, { ...who, path, body: pkg(o.id) });
    expect(second.statusCode).toBe(409);
    expect(second.json().code).toBe("ORDER_NOT_PAYABLE");
    release();
    expect((await first).json().status).toBe("PAID");
    expect(sent).toHaveLength(1);
  });

  it("сбой эквайрера — 503, заказ снова можно оплатить", async () => {
    let down = true;
    const { app, asA } = setup({
      decide: () => {
        if (down) throw new Error("ОПКЦ недоступен");
        return { approved: true, reason: null };
      },
    });
    const o = (await order(app, asA(), "SHOP-1042", "BRD-1042-01")).json();
    const path = `/v1/shops/SHOP-1042/orders/${o.id}/payment`;
    expect((await merchantCall(app, { ...asA(), path, body: pkg(o.id) })).statusCode).toBe(503);
    down = false;
    expect((await merchantCall(app, { ...asA(), path, body: pkg(o.id) })).json().status).toBe("PAID");
  });
});
