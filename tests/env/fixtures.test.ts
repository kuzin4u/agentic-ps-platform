// PS-12: фикстуры витрин и агентов (AG-04, AG-09) — из того же источника, что эмулятор; номеров карт и закрытых ключей нет.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AGENT_FIXTURES, MERCHANT_ERROR_CODES, MERCHANT_FIXTURES, agentApplication } from "../../src/fixtures/index.js";
import { SHOPS } from "../../src/env/merchants/index.js";
import { createMerchants, createStand } from "../../src/stand/index.js";
import { newAgentSide } from "../support/agent.js";
import { merchantCall } from "../support/merchant-call.js";

// Номер карты: 13–19 цифр подряд, в том числе через пробел или дефис (инвариант 1).
const PAN_LIKE = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/;
const PAN_KEYS = /^(pan|card_?number|card_?no|cvv2?|cvc2?|track[12]|pin|expiry)$/i;

/** Все строки и имена полей объекта — для сканера. */
function scan(node: unknown, out: { keys: string[]; values: string[] } = { keys: [], values: [] }) {
  if (typeof node === "string") out.values.push(node);
  else if (typeof node === "number") out.values.push(String(node));
  else if (Array.isArray(node)) node.forEach((v) => scan(v, out));
  else if (node && typeof node === "object")
    for (const [k, v] of Object.entries(node)) {
      out.keys.push(k);
      scan(v, out);
    }
  return out;
}

/**
 * Каталог без времени: `updated_at` фикстур — на момент загрузки модуля, у витрины — по часам ответа (РП58 п. 6). Время
 * сверяется отдельно: у ответа — `updated_at` = `responded_at` − возраст карточки; здесь — только наличие.
 */
function timeless(body: { items: readonly { updated_at?: string }[]; responded_at?: string }) {
  if (body.responded_at !== undefined) {
    for (const i of body.items) {
      if (i.updated_at !== undefined) expect(Date.parse(body.responded_at) - Date.parse(i.updated_at)).toBe(7_200_000);
    }
  }
  return body.items.map(({ updated_at, ...rest }) => ({ ...rest, has_updated_at: updated_at !== undefined }));
}

function expectNoCardData(node: unknown): void {
  const { keys, values } = scan(node);
  expect(keys.filter((k) => PAN_KEYS.test(k))).toEqual([]);
  expect(values.filter((v) => PAN_LIKE.test(v))).toEqual([]);
}

describe("Сканер номеров карт: сам сканер", () => {
  it("находит номер карты в значении и в имени поля", () => {
    expect(() => expectNoCardData({ x: "2200 1234 5678 9010" })).toThrow();
    expect(() => expectNoCardData({ card_number: "x" })).toThrow();
    expect(() => expectNoCardData({ x: 2200123456789010 })).toThrow();
  });
});

describe("Фикстуры витрин", () => {
  it("один источник: витрины фикстур = витрины эмулятора, каталог фикстур = ответы витрин человеку и агенту", async () => {
    expect(MERCHANT_FIXTURES.map((f) => f.id).sort()).toEqual(SHOPS.map((s) => s.id).sort());
    const s = createStand();
    const side = newAgentSide();
    const agent = AGENT_FIXTURES.find((a) => a.registered)!;
    expect((await s.admit(agentApplication(agent, { alg: "ed25519", public_key: side.publicKey }), agent.operator)).admitted).toBe(true);
    const m = createMerchants(s);
    try {
      const shops = (await merchantCall(m.app, { path: "/v1/shops" })).json().shops;
      expect(shops.map((x: { id: string }) => x.id)).toEqual(MERCHANT_FIXTURES.map((f) => f.id));
      for (const f of MERCHANT_FIXTURES) {
        const path = `/v1/shops/${f.id}/catalog`;
        const human = await merchantCall(m.app, { path });
        if (f.behaviour === "REJECTS_UNIDENTIFIED") expect(human.statusCode).toBe(403);
        else expect(timeless(human.json())).toEqual(timeless({ items: f.items }));
        const asAgent = await merchantCall(m.app, { path, side, agentCode: agent.agent_code });
        expect(timeless(asAgent.json())).toEqual(timeless({ items: f.agent_items }));
        const { inn, mcc, payment_methods, delivery_regions, returns } = f;
        expect(asAgent.json().shop).toEqual({
          id: f.id, merchant_id: f.merchant_id, name: f.name, category: f.category, zone: f.zone, readiness_mark: f.readiness_mark,
          inn, mcc, payment_methods, delivery_regions, ...(returns ? { returns } : {}),
        });
      }
    } finally {
      await m.close();
    }
  });

  it("номеров карт нет", () => {
    expectNoCardData(MERCHANT_FIXTURES);
    expectNoCardData(SHOPS);
  });
});

describe("Фикстуры агентов", () => {
  it("закрытых ключей нет; зарегистрированные допускаются в стенде с ключом потребителя", async () => {
    const text = JSON.stringify(AGENT_FIXTURES);
    expect(text).not.toMatch(/PRIVATE|public_key|"d"/);
    expectNoCardData(AGENT_FIXTURES);
    const s = createStand();
    for (const f of AGENT_FIXTURES.filter((a) => a.registered)) {
      const side = newAgentSide();
      expect((await s.admit(agentApplication(f, { alg: "ed25519", public_key: side.publicKey }), f.operator)).admitted).toBe(true);
    }
    expect(AGENT_FIXTURES.some((a) => !a.registered)).toBe(true);
  });
});

describe("Ответы эмуляторов и сообщения в ОПКЦ — без номеров карт", () => {
  it("полный проход по всем витринам: каталог, заказ, оплата", async () => {
    const s = createStand();
    const side = newAgentSide();
    const agent = AGENT_FIXTURES[0]!;
    await s.admit(agentApplication(agent, { alg: "ed25519", public_key: side.publicKey }), agent.operator);
    const m = createMerchants(s);
    const seen: unknown[] = [];
    const who = { side, agentCode: agent.agent_code };
    try {
      seen.push((await merchantCall(m.app, { path: "/v1/shops" })).json());
      for (const f of MERCHANT_FIXTURES) {
        seen.push((await merchantCall(m.app, { ...who, path: `/v1/shops/${f.id}/catalog` })).json());
        const sku = f.items.find((i) => typeof i.price === "number")?.sku ?? f.items[0]!.sku;
        const o = await merchantCall(m.app, { ...who, path: `/v1/shops/${f.id}/orders`, body: { items: [{ sku, qty: 1 }], cart_mandate_id: "MND-1" } });
        seen.push(o.json());
        if (o.statusCode !== 201) continue;
        const id = o.json().id;
        const pkg = {
          credential_ref: "CRD-1",
          kind: "CARD",
          payload: { token_ref: "tok_ag_1", cryptogram: "Y3J5cHRv" },
          aoi: { indicator: true, agent_code: agent.agent_code, mandate_id: "MND-1" },
          cart_mandate_id: "MND-1",
          order_ref: id,
        };
        seen.push((await merchantCall(m.app, { ...who, path: `/v1/shops/${f.id}/orders/${id}/payment`, body: pkg })).json());
      }
      expect(m.opkc.messages.length).toBeGreaterThan(0);
      expectNoCardData(seen);
      expectNoCardData(m.opkc.messages);
    } finally {
      await m.close();
    }
  });
});

// Р26 п. 5 агента (К3.3 PS-05): перечень кодов отказа витрин — из того же источника, что ответы эмулятора.
describe("Коды отказа витрин", () => {
  it("перечень закрыт и совпадает с кодами, которые отдаёт эмулятор", () => {
    const src = readFileSync("src/env/merchants/server.ts", "utf8") + readFileSync("src/env/merchants/verify.ts", "utf8");
    // Коды, которые эмулятор отдаёт: fail(reply, "…") и коды проверки подписи (MerchantAuthError).
    const emitted = new Set(
      [...src.matchAll(/fail\(reply, "([A-Z_]+)"\)|code: "([A-Z_]+)"/g)].map((m) => (m[1] ?? m[2]) as string),
    );
    const listed = MERCHANT_ERROR_CODES.map((e) => e.code);
    for (const c of emitted) expect(listed, c).toContain(c);
    expect(listed).toEqual([...listed].sort());
    expect(new Set(listed).size).toBe(listed.length);
    for (const { code, http } of MERCHANT_ERROR_CODES) expect([401, 403, 404, 409, 422, 429, 503], code).toContain(http);
  });

  it("ответ витрины несёт код из перечня с его HTTP-статусом: без подписи — 403 AGENT_UNIDENTIFIED", async () => {
    const stand = createStand();
    const m = createMerchants(stand);
    try {
      const res = await m.app.inject({ method: "POST", url: "/v1/shops/SHOP-1042/orders", payload: { items: [] } });
      const body = res.json() as { code: string };
      expect(MERCHANT_ERROR_CODES).toContainEqual({ code: body.code, http: res.statusCode });
      expect(body.code).toBe("AGENT_UNIDENTIFIED");
    } finally {
      await m.app.close();
      await stand.close();
    }
  });
});
